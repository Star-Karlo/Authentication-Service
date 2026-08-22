// Package services holds the authentication service's business rules.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/config"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/cache"
	"github.com/karlo/authentication-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// Errors the HTTP and gRPC layers translate into status codes.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountSuspended   = errors.New("account suspended")
	ErrAccountDeleted     = errors.New("account deleted")
	ErrRateLimited        = errors.New("too many attempts")
	ErrSessionRevoked     = errors.New("session revoked")
	ErrTokenInvalid       = errors.New("token invalid")
)

// singleDeviceRoles are the roles the legacy system bound to one device at a
// time via the tokenKapps field. Logging in on a second device evicts the first.
var singleDeviceRoles = map[string]bool{
	"shipper":     true,
	"transporter": true,
	"manager":     true,
}

// AuthService issues, verifies and revokes credentials.
type AuthService struct {
	users    *repository.UserRepository
	sessions *repository.SessionRepository
	apiKeys  *repository.APIKeyRepository
	devices  *repository.DeviceTokenRepository
	modules  *repository.ModuleRepository
	access   *repository.AccessRepository
	audit    *repository.AuditRepository
	signer   *authctx.Signer
	verifier *authctx.Verifier
	cache    cache.Cache
	cfg      *config.Config
}

func NewAuthService(
	users *repository.UserRepository,
	sessions *repository.SessionRepository,
	apiKeys *repository.APIKeyRepository,
	devices *repository.DeviceTokenRepository,
	modules *repository.ModuleRepository,
	access *repository.AccessRepository,
	audit *repository.AuditRepository,
	signer *authctx.Signer,
	c cache.Cache,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		users:    users,
		sessions: sessions,
		apiKeys:  apiKeys,
		devices:  devices,
		modules:  modules,
		access:   access,
		audit:    audit,
		signer:   signer,
		verifier: signer.Public(),
		cache:    c,
		cfg:      cfg,
	}
}

// LoginInput carries the credentials and the request metadata recorded with the
// resulting session.
type LoginInput struct {
	Identifier string
	Password   string
	DeviceID   string
	Platform   string
	UserAgent  string
	IPAddress  string
}

// TokenPair is what a successful authentication yields.
type TokenPair struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    time.Time `json:"expiresAt"`
	TokenType    string    `json:"tokenType"`
}

// LoginResult is the full outcome of a login.
type LoginResult struct {
	Tokens TokenPair    `json:"tokens"`
	User   *models.User `json:"user"`
}

// Login authenticates a set of credentials and opens a session.
//
// Two behaviours here differ deliberately from the legacy implementation.
// First, every failure returns the same error regardless of cause, so the
// endpoint cannot be used to enumerate which emails are registered. Second, a
// password comparison runs even when no user matched, so response timing does
// not reveal the answer either.
func (s *AuthService) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	identifier := strings.TrimSpace(in.Identifier)
	if identifier == "" || in.Password == "" {
		return nil, ErrInvalidCredentials
	}

	if limited, err := s.isRateLimited(ctx, identifier); err != nil {
		slog.Warn("rate limit check failed, allowing attempt", "error", err)
	} else if limited {
		return nil, ErrRateLimited
	}

	user, err := s.users.FindByIdentifier(ctx, identifier)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Spend roughly the same time as a real comparison would.
			bcryptDummy(in.Password)
			s.recordLoginFailure(ctx, nil, identifier, in, "user not found")
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("login: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(in.Password)); err != nil {
		s.recordLoginFailure(ctx, &user.ID, identifier, in, "bad password")
		return nil, ErrInvalidCredentials
	}

	if user.IsSuspended {
		s.recordLoginFailure(ctx, &user.ID, identifier, in, "suspended")
		return nil, ErrAccountSuspended
	}

	result, err := s.issueSession(ctx, user, in)
	if err != nil {
		return nil, err
	}

	s.clearRateLimit(ctx, identifier)

	if err := s.users.TouchLastLogin(ctx, user.ID); err != nil {
		slog.Warn("failed to record last login", "user_id", user.ID, "error", err)
	}
	s.writeAudit(ctx, &models.AuditEntry{
		UserID:    &user.ID,
		Event:     models.AuditLoginSuccess,
		Succeeded: true,
		IPAddress: nilIfEmpty(in.IPAddress),
		UserAgent: nilIfEmpty(in.UserAgent),
		Detail:    models.JSONMap{"identifier": identifier, "platform": in.Platform},
	})

	return result, nil
}

// issueSession mints a token pair and persists the session behind it.
func (s *AuthService) issueSession(ctx context.Context, user *models.User, in LoginInput) (*LoginResult, error) {
	tokenID := uuid.New()
	singleDevice := singleDeviceRoles[user.Role]

	refreshToken, refreshHash, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("login: generate refresh token: %w", err)
	}

	session := &models.Session{
		UserID:           user.ID,
		TokenID:          tokenID,
		RefreshTokenHash: &refreshHash,
		SingleDevice:     singleDevice,
		DeviceID:         nilIfEmpty(in.DeviceID),
		Platform:         nilIfEmpty(in.Platform),
		UserAgent:        nilIfEmpty(in.UserAgent),
		IPAddress:        nilIfEmpty(in.IPAddress),
		ExpiresAt:        time.Now().Add(s.cfg.RefreshTokenTTL),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	// Enforce the one-device rule after the new session exists, so a failure
	// here cannot leave the user with no working session at all.
	if singleDevice {
		if err := s.sessions.RevokeOtherSingleDeviceSessions(ctx, user.ID, tokenID); err != nil {
			slog.Warn("failed to evict previous single-device sessions", "user_id", user.ID, "error", err)
		}
	}

	access, expiresAt, err := s.mintAccessToken(ctx, user, tokenID, singleDevice)
	if err != nil {
		return nil, err
	}

	return &LoginResult{
		Tokens: TokenPair{
			AccessToken:  access,
			RefreshToken: refreshToken,
			ExpiresAt:    expiresAt,
			TokenType:    "Bearer",
		},
		User: user,
	}, nil
}

func (s *AuthService) mintAccessToken(ctx context.Context, user *models.User, tokenID uuid.UUID, singleDevice bool) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.cfg.AccessTokenTTL)

	principal := authctx.Principal{
		UserID:          user.ID.String(),
		IsPlatformStaff: user.IsPlatformStaff,
		SingleDevice:    singleDevice,
		TokenID:         tokenID.String(),
	}
	if user.CompanyID != nil {
		principal.CompanyID = user.CompanyID.String()
	}
	if user.ParentID != nil {
		principal.ParentID = user.ParentID.String()
	}

	// The per-product access map: which products this person may use, in what
	// role, with which permissions, and what their company is entitled to in
	// each. Embedded so no service has to ask again on the request path.
	//
	// A lookup failure mints a token with NO access rather than broad access.
	// That fails closed — the holder authenticates but reaches nothing, which a
	// refresh fixes. Failing open would hand out a token granting modules the
	// company never bought, valid until it expired.
	access, aerr := s.access.BuildAccess(ctx, user.ID, user.CompanyID)
	if aerr != nil {
		slog.Error("could not load product access; minting a token with none",
			"user_id", user.ID, "error", aerr)
	} else {
		principal.Access = access
	}

	// The company's FMS-facing alias, so FMS reads its bigint tenant id
	// straight from the token instead of translating the UUID per request.
	if user.Company != nil && user.Company.FMSTenantID != nil {
		principal.FMSTenantID = *user.Company.FMSTenantID
	}

	token, err := s.signer.Sign(principal, jwt.RegisteredClaims{
		Subject:   user.ID.String(),
		ID:        tokenID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint access token: %w", err)
	}
	return token, expiresAt, nil
}

// Refresh exchanges a refresh token for a new access token, rotating the
// refresh token in the process so a stolen one is usable at most once.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	hash := hashToken(refreshToken)

	session, err := s.sessions.FindByRefreshHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTokenInvalid
		}
		return nil, fmt.Errorf("refresh: %w", err)
	}
	if !session.IsActive() {
		return nil, ErrSessionRevoked
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, ErrTokenInvalid
	}
	if user.IsSuspended {
		return nil, ErrAccountSuspended
	}

	// Rotate: the old refresh token stops working the moment this succeeds.
	newRefresh, newHash, err := generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	newTokenID := uuid.New()

	if err := s.sessions.Revoke(ctx, session.TokenID); err != nil {
		return nil, fmt.Errorf("refresh: revoke old session: %w", err)
	}
	newSession := &models.Session{
		UserID:           user.ID,
		TokenID:          newTokenID,
		RefreshTokenHash: &newHash,
		SingleDevice:     session.SingleDevice,
		DeviceID:         session.DeviceID,
		Platform:         session.Platform,
		ExpiresAt:        time.Now().Add(s.cfg.RefreshTokenTTL),
	}
	if err := s.sessions.Create(ctx, newSession); err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}

	access, expiresAt, err := s.mintAccessToken(ctx, user, newTokenID, session.SingleDevice)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: newRefresh,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken resolves any credential this system accepts into a principal.
//
// It handles what other services cannot verify locally: API keys, and
// single-device sessions whose revocation must take effect immediately rather
// than at the next token expiry.
func (s *AuthService) ValidateToken(ctx context.Context, token string) (authctx.Principal, *models.User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}

	// An API key is presented as an opaque string; a JWT always has two dots.
	if strings.Count(token, ".") != 2 {
		return s.validateAPIKey(ctx, token)
	}

	principal, err := s.verifier.Verify(token)
	if err != nil {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}

	// A single-device session must be confirmed against the store, because that
	// is the only way an eviction takes effect before the access token expires.
	if principal.SingleDevice && principal.TokenID != "" {
		tokenID, perr := uuid.Parse(principal.TokenID)
		if perr != nil {
			return authctx.Principal{}, nil, ErrTokenInvalid
		}
		session, serr := s.sessions.FindByTokenID(ctx, tokenID)
		if serr != nil || !session.IsActive() {
			return authctx.Principal{}, nil, ErrSessionRevoked
		}
	}

	userID, err := uuid.Parse(principal.UserID)
	if err != nil {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		// The token is well-formed but the account is gone. The legacy message
		// is preserved for client compatibility.
		return authctx.Principal{}, nil, ErrAccountDeleted
	}
	if user.IsSuspended {
		return authctx.Principal{}, nil, ErrAccountSuspended
	}

	return principal, user, nil
}

func (s *AuthService) validateAPIKey(ctx context.Context, key string) (authctx.Principal, *models.User, error) {
	apiKey, err := s.apiKeys.FindByHash(ctx, hashToken(key))
	if err != nil {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}
	if !apiKey.IsUsable() {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}
	if apiKey.UserID == nil {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}

	user, err := s.users.FindByID(ctx, *apiKey.UserID)
	if err != nil {
		return authctx.Principal{}, nil, ErrTokenInvalid
	}
	if user.IsSuspended {
		return authctx.Principal{}, nil, ErrAccountSuspended
	}

	s.apiKeys.TouchLastUsed(ctx, apiKey.ID)

	principal := authctx.Principal{
		UserID:          user.ID.String(),
		IsPlatformStaff: user.IsPlatformStaff,
	}
	if user.CompanyID != nil {
		principal.CompanyID = user.CompanyID.String()
	}
	if user.ParentID != nil {
		principal.ParentID = user.ParentID.String()
	}

	// An API key is subject to exactly the same access as a login. Omitting
	// this would make a key a way around both the entitlement and the
	// per-product gate.
	access, aerr := s.access.BuildAccess(ctx, user.ID, user.CompanyID)
	if aerr != nil {
		return authctx.Principal{}, nil, fmt.Errorf("resolve product access: %w", aerr)
	}
	principal.Access = access

	return principal, user, nil
}

// Logout revokes the session behind a token.
func (s *AuthService) Logout(ctx context.Context, tokenID uuid.UUID, userID uuid.UUID, deviceID string) error {
	if err := s.sessions.Revoke(ctx, tokenID); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	if deviceID != "" {
		if err := s.devices.DeactivateForDevice(ctx, userID, deviceID); err != nil {
			slog.Warn("failed to deactivate device token on logout", "user_id", userID, "error", err)
		}
	}
	s.writeAudit(ctx, &models.AuditEntry{UserID: &userID, Event: models.AuditLogout, Succeeded: true})
	return nil
}

// LogoutAll revokes every session a user holds.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) (int64, error) {
	n, err := s.sessions.RevokeAllForUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("logout all: %w", err)
	}
	s.writeAudit(ctx, &models.AuditEntry{
		UserID: &userID, Event: models.AuditSessionRevoked, Succeeded: true,
		Detail: models.JSONMap{"revoked": n},
	})
	return n, nil
}

// ChangePassword updates a password after verifying the current one, then
// revokes every existing session: a password change that leaves old sessions
// alive does not actually lock anyone out.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		s.writeAudit(ctx, &models.AuditEntry{
			UserID: &userID, Event: models.AuditPasswordChanged, Succeeded: false,
		})
		return ErrInvalidCredentials
	}

	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	hash, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if err := s.users.UpdateFields(ctx, userID, map[string]interface{}{"password_hash": hash}); err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	if _, err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
		slog.Warn("password changed but sessions not revoked", "user_id", userID, "error", err)
	}

	s.writeAudit(ctx, &models.AuditEntry{UserID: &userID, Event: models.AuditPasswordChanged, Succeeded: true})
	return nil
}

// HashPassword applies bcrypt at the configured cost.
func (s *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// CreateAPIKey mints a new key, returning the plaintext exactly once.
func (s *AuthService) CreateAPIKey(ctx context.Context, name string, userID, companyID *uuid.UUID, scopes []string, expiresAt *time.Time) (string, *models.APIKey, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("create api key: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)

	key := &models.APIKey{
		Name:      name,
		KeyHash:   hashToken(plaintext),
		KeyPrefix: plaintext[:8],
		UserID:    userID,
		CompanyID: companyID,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}
	if err := s.apiKeys.Create(ctx, key); err != nil {
		return "", nil, err
	}

	s.writeAudit(ctx, &models.AuditEntry{
		UserID: userID, Event: models.AuditAPIKeyCreated, Succeeded: true,
		Detail: models.JSONMap{"name": name, "prefix": key.KeyPrefix},
	})
	return plaintext, key, nil
}

// isRateLimited reports whether an identifier has exhausted its login attempts.
//
// Redis first, the audit log second. The counter is a single INCR against a
// keyspace built for it; the fallback is a COUNT over a growing audit table
// with a JSONB predicate — a query that gets slower exactly as the table grows,
// which is to say under attack. The fallback runs only when Redis is absent or
// unreachable, so the limiter survives a cache outage.
func (s *AuthService) isRateLimited(ctx context.Context, identifier string) (bool, error) {
	key := cache.Key("auth", "login", "attempts", cache.Fingerprint(strings.ToLower(identifier)))

	count, err := s.cache.Increment(ctx, key, s.cfg.LoginRateWindow)
	if err == nil {
		return count > int64(s.cfg.LoginRateLimit), nil
	}
	if !errors.Is(err, cache.ErrNoCache) {
		slog.Warn("login rate limiting fell back to the audit log", "error", err)
	}

	since := time.Now().Add(-s.cfg.LoginRateWindow)
	dbCount, dbErr := s.audit.CountRecentFailures(ctx, identifier, since)
	if dbErr != nil {
		return false, dbErr
	}
	return dbCount >= int64(s.cfg.LoginRateLimit), nil
}

// clearRateLimit forgets an identifier's failed attempts after a success.
//
// Without it, someone who mistypes four times then gets it right stays one
// attempt from lockout for the rest of the window. The counter exists to slow
// guessing, not to punish typing.
func (s *AuthService) clearRateLimit(ctx context.Context, identifier string) {
	s.cache.Delete(ctx, cache.Key("auth", "login", "attempts",
		cache.Fingerprint(strings.ToLower(identifier))))
}

func (s *AuthService) recordLoginFailure(ctx context.Context, userID *uuid.UUID, identifier string, in LoginInput, reason string) {
	s.writeAudit(ctx, &models.AuditEntry{
		UserID:    userID,
		Event:     models.AuditLoginFailure,
		Succeeded: false,
		IPAddress: nilIfEmpty(in.IPAddress),
		UserAgent: nilIfEmpty(in.UserAgent),
		Detail:    models.JSONMap{"identifier": identifier, "reason": reason},
	})
}

// writeAudit never propagates its error: auditing is important, but failing a
// successful login because the audit insert failed is worse.
func (s *AuthService) writeAudit(ctx context.Context, e *models.AuditEntry) {
	if err := s.audit.Write(ctx, e); err != nil {
		slog.Error("audit write failed", "event", e.Event, "error", err)
	}
}

// ValidatePasswordStrength enforces the minimum the legacy system had none of.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(password) > 72 {
		// bcrypt silently truncates beyond 72 bytes, which would make the tail
		// of a long password meaningless. Reject rather than mislead.
		return errors.New("password must be at most 72 characters")
	}

	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		}
	}
	if !hasLetter || !hasDigit {
		return errors.New("password must contain at least one letter and one digit")
	}
	return nil
}

// generateRefreshToken returns the plaintext token and the hash to store.
func generateRefreshToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, hashToken(token), nil
}

// hashToken hashes a bearer secret for storage. SHA-256 is right here rather
// than bcrypt: these are already high-entropy random values, so the only
// property needed is preimage resistance, and lookups must be indexable.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SecureCompare is a constant-time comparison for secrets held in memory.
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// bcryptDummy burns roughly one bcrypt's worth of time so that a login attempt
// for an unknown identifier costs the same as one for a known identifier.
func bcryptDummy(password string) {
	// A precomputed hash of a value nothing can match. Cost 12 to match config.
	const dummy = "$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	_ = bcrypt.CompareHashAndPassword([]byte(dummy), []byte(password))
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
