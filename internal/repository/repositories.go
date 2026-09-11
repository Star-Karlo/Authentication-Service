package repository

import (
	"context"
	"fmt"
	"github.com/karlo/authentication-service/internal/platform/revocation"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/query"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Companies
// ---------------------------------------------------------------------------

type CompanyRepository struct{ db *gorm.DB }

func NewCompanyRepository(db *gorm.DB) *CompanyRepository { return &CompanyRepository{db: db} }

// WithTx returns a repository that writes through the given transaction.
func (r *CompanyRepository) WithTx(tx *gorm.DB) *CompanyRepository {
	if tx == nil {
		return r
	}
	return &CompanyRepository{db: tx}
}

var companyListFields = query.FieldSet{
	"name":        "name",
	"role":        "role",
	"npwp":        "npwp",
	"isVerified":  "is_verified",
	"isSuspended": "is_suspended",
	"createdAt":   "created_at",
}

func CompanyListFields() query.FieldSet { return companyListFields }

func (r *CompanyRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Company, error) {
	var c models.Company
	return one(&c, r.db.WithContext(ctx).First(&c, "id = ?", id).Error)
}

func (r *CompanyRepository) Create(ctx context.Context, c *models.Company) error {
	if err := r.db.WithContext(ctx).Create(c).Error; err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %v", ErrConflict, err)
		}
		return fmt.Errorf("repository: create company: %w", err)
	}
	return nil
}

func (r *CompanyRepository) UpdateFields(ctx context.Context, id uuid.UUID, fields map[string]interface{}) error {
	if len(fields) == 0 {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&models.Company{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("repository: update company: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *CompanyRepository) List(ctx context.Context, p query.Params) ([]models.Company, int64, error) {
	q := applyFilters(r.db.WithContext(ctx).Model(&models.Company{}), p)
	if p.Search != "" {
		like := "%" + p.Search + "%"
		q = q.Where("name ILIKE ? OR npwp ILIKE ?", like, like)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("repository: count companies: %w", err)
	}

	var out []models.Company
	err := applySorts(q, p, "created_at DESC").Offset(p.Offset()).Limit(p.PageSize).Find(&out).Error
	if err != nil {
		return nil, 0, fmt.Errorf("repository: list companies: %w", err)
	}
	return out, total, nil
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type SessionRepository struct {
	db        *gorm.DB
	announcer Announcer
}

func NewSessionRepository(db *gorm.DB) *SessionRepository { return &SessionRepository{db: db} }

func (r *SessionRepository) Create(ctx context.Context, s *models.Session) error {
	if err := r.db.WithContext(ctx).Create(s).Error; err != nil {
		return fmt.Errorf("repository: create session: %w", err)
	}
	return nil
}

// FindByTokenID resolves the session behind a JWT's jti claim.
func (r *SessionRepository) FindByTokenID(ctx context.Context, tokenID uuid.UUID) (*models.Session, error) {
	var s models.Session
	return one(&s, r.db.WithContext(ctx).First(&s, "token_id = ?", tokenID).Error)
}

// FindByRefreshHash resolves a session from the hash of its refresh token.
func (r *SessionRepository) FindByRefreshHash(ctx context.Context, hash string) (*models.Session, error) {
	var s models.Session
	return one(&s, r.db.WithContext(ctx).First(&s, "refresh_token_hash = ?", hash).Error)
}

// Revoke ends one session.
func (r *SessionRepository) Revoke(ctx context.Context, tokenID uuid.UUID) error {
	res := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("token_id = ? AND revoked_at IS NULL", tokenID).
		Update("revoked_at", time.Now())
	if res.Error != nil {
		return fmt.Errorf("repository: revoke session: %w", res.Error)
	}
	return nil
}

// RevokeAllForUser ends every live session a user has. Used on logout-all,
// password change and suspension: a changed password must invalidate sessions
// that were issued under the old one.
func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	res := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", time.Now())
	if res.Error != nil {
		return 0, fmt.Errorf("repository: revoke user sessions: %w", res.Error)
	}

	// Announced HERE rather than at each caller.
	//
	// Eight places revoke a user's sessions — suspension, password change, role
	// change, permission change, logout-all — and any one of them could be
	// added later without remembering to announce. Marking the database row
	// revoked and telling the other services are the same act, so they live in
	// the same place and cannot come apart.
	r.announce(ctx, revocation.Event{
		Kind: revocation.KindUser,
		ID:   userID.String(),
		At:   time.Now().UTC(),
	})

	return res.RowsAffected, nil
}

// RevokeOtherSingleDeviceSessions enforces the legacy one-device rule: a new
// login on a single-device role evicts the previous one.
func (r *SessionRepository) RevokeOtherSingleDeviceSessions(ctx context.Context, userID, keepTokenID uuid.UUID) error {
	// The evicted token ids are collected BEFORE the update, because
	// afterwards there is no way to tell which rows this call revoked from
	// rows revoked a minute ago.
	var evicted []uuid.UUID
	err := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND single_device AND token_id <> ? AND revoked_at IS NULL", userID, keepTokenID).
		Pluck("token_id", &evicted).Error
	if err != nil {
		return fmt.Errorf("repository: find sessions to evict: %w", err)
	}

	if err := r.db.WithContext(ctx).Model(&models.Session{}).
		Where("user_id = ? AND single_device AND token_id <> ? AND revoked_at IS NULL", userID, keepTokenID).
		Update("revoked_at", time.Now()).Error; err != nil {
		return fmt.Errorf("repository: evict sessions: %w", err)
	}

	// Announced per SESSION, not per user. A cutoff would refuse the login
	// that just happened — it was issued moments ago and would fall on the
	// wrong side of the line — so the new device would evict itself.
	for _, tokenID := range evicted {
		r.announce(ctx, revocation.Event{
			Kind: revocation.KindSession,
			ID:   tokenID.String(),
			At:   time.Now().UTC(),
		})
	}
	return nil
}

// SetAnnouncer gives the repository somewhere to publish revocations.
//
// Optional: with none set, revocation still works, it simply takes effect when
// the token expires rather than at once.
func (r *SessionRepository) SetAnnouncer(a Announcer) { r.announcer = a }

// Announcer publishes a revocation to the other services.
type Announcer interface {
	Publish(ctx context.Context, e revocation.Event) error
}

func (r *SessionRepository) announce(ctx context.Context, e revocation.Event) {
	if r.announcer == nil {
		return
	}
	if err := r.announcer.Publish(ctx, e); err != nil {
		// The database is already updated, so the revocation is real; only its
		// immediacy is lost. Failing the caller here would roll back a
		// suspension because a cache was unreachable, which is worse.
		slog.WarnContext(ctx, "session revoked but not announced; it takes "+
			"effect when the token expires rather than immediately",
			"kind", e.Kind, "error", err)
	}
}

// ListActiveForUser powers a "your devices" screen.
func (r *SessionRepository) ListActiveForUser(ctx context.Context, userID uuid.UUID) ([]models.Session, error) {
	var out []models.Session
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > NOW()", userID).
		Order("last_used_at DESC").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list sessions: %w", err)
	}
	return out, nil
}

// TouchLastUsed records session activity, for idle-session reporting.
func (r *SessionRepository) TouchLastUsed(ctx context.Context, tokenID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&models.Session{}).
		Where("token_id = ?", tokenID).
		Update("last_used_at", time.Now()).Error
}

// DeleteExpired prunes sessions that expired before cutoff. Run from a cron.
func (r *SessionRepository) DeleteExpired(ctx context.Context, cutoff time.Time) (int64, error) {
	res := r.db.WithContext(ctx).Where("expires_at < ?", cutoff).Delete(&models.Session{})
	if res.Error != nil {
		return 0, fmt.Errorf("repository: prune sessions: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

type APIKeyRepository struct{ db *gorm.DB }

func NewAPIKeyRepository(db *gorm.DB) *APIKeyRepository { return &APIKeyRepository{db: db} }

// FindByHash resolves a presented key. The plaintext is never stored, so the
// caller hashes first.
func (r *APIKeyRepository) FindByHash(ctx context.Context, hash string) (*models.APIKey, error) {
	var k models.APIKey
	return one(&k, r.db.WithContext(ctx).First(&k, "key_hash = ?", hash).Error)
}

func (r *APIKeyRepository) Create(ctx context.Context, k *models.APIKey) error {
	if err := r.db.WithContext(ctx).Create(k).Error; err != nil {
		return fmt.Errorf("repository: create api key: %w", err)
	}
	return nil
}

func (r *APIKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	res := r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Updates(map[string]interface{}{"revoked_at": time.Now(), "is_active": false})
	if res.Error != nil {
		return fmt.Errorf("repository: revoke api key: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed is fire-and-forget: failing to record usage must not fail the
// request that used the key.
func (r *APIKeyRepository) TouchLastUsed(ctx context.Context, id uuid.UUID) {
	_ = r.db.WithContext(ctx).Model(&models.APIKey{}).
		Where("id = ?", id).
		Update("last_used_at", time.Now()).Error
}

func (r *APIKeyRepository) List(ctx context.Context, companyID *uuid.UUID) ([]models.APIKey, error) {
	q := r.db.WithContext(ctx).Model(&models.APIKey{})
	if companyID != nil {
		q = q.Where("company_id = ?", *companyID)
	}
	var out []models.APIKey
	if err := q.Order("created_at DESC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("repository: list api keys: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Device tokens
// ---------------------------------------------------------------------------

type DeviceTokenRepository struct{ db *gorm.DB }

func NewDeviceTokenRepository(db *gorm.DB) *DeviceTokenRepository {
	return &DeviceTokenRepository{db: db}
}

// Upsert registers a device's push token, reactivating it if the same device
// re-registers after a failure.
func (r *DeviceTokenRepository) Upsert(ctx context.Context, t *models.DeviceToken) error {
	err := r.db.WithContext(ctx).Exec(`
		INSERT INTO device_tokens (user_id, push_token, platform, device_id, is_active)
		VALUES (?, ?, ?, ?, TRUE)
		ON CONFLICT (user_id, push_token)
		DO UPDATE SET is_active = TRUE, failed_at = NULL, platform = EXCLUDED.platform,
		              device_id = EXCLUDED.device_id, updated_at = NOW()
	`, t.UserID, t.PushToken, t.Platform, t.DeviceID).Error
	if err != nil {
		return fmt.Errorf("repository: upsert device token: %w", err)
	}
	return nil
}

// ActiveForUsers returns every live push token for a set of users. The
// notification service calls this through gRPC to fan a push out.
func (r *DeviceTokenRepository) ActiveForUsers(ctx context.Context, userIDs []uuid.UUID) ([]models.DeviceToken, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	var out []models.DeviceToken
	err := r.db.WithContext(ctx).
		Where("user_id IN ? AND is_active", userIDs).
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: active device tokens: %w", err)
	}
	return out, nil
}

// MarkFailed deactivates a token the push provider rejected, so it is not
// retried indefinitely.
func (r *DeviceTokenRepository) MarkFailed(ctx context.Context, pushToken string) error {
	return r.db.WithContext(ctx).Model(&models.DeviceToken{}).
		Where("push_token = ?", pushToken).
		Updates(map[string]interface{}{"is_active": false, "failed_at": time.Now()}).Error
}

// DeactivateForDevice clears a device's token on logout.
func (r *DeviceTokenRepository) DeactivateForDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	return r.db.WithContext(ctx).Model(&models.DeviceToken{}).
		Where("user_id = ? AND device_id = ?", userID, deviceID).
		Update("is_active", false).Error
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

type DocumentRepository struct{ db *gorm.DB }

func NewDocumentRepository(db *gorm.DB) *DocumentRepository { return &DocumentRepository{db: db} }

func (r *DocumentRepository) Create(ctx context.Context, d *models.UserDocument) error {
	if err := r.db.WithContext(ctx).Create(d).Error; err != nil {
		return fmt.Errorf("repository: create document: %w", err)
	}
	return nil
}

func (r *DocumentRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.UserDocument, error) {
	var d models.UserDocument
	return one(&d, r.db.WithContext(ctx).First(&d, "id = ?", id).Error)
}

func (r *DocumentRepository) ListForUser(ctx context.Context, userID uuid.UUID) ([]models.UserDocument, error) {
	var out []models.UserDocument
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list documents: %w", err)
	}
	return out, nil
}

func (r *DocumentRepository) ListForCompany(ctx context.Context, companyID uuid.UUID) ([]models.UserDocument, error) {
	var out []models.UserDocument
	err := r.db.WithContext(ctx).Where("company_id = ?", companyID).Order("created_at DESC").Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list documents: %w", err)
	}
	return out, nil
}

// SetStatus records a verification decision.
func (r *DocumentRepository) SetStatus(ctx context.Context, id uuid.UUID, status string, verifiedBy uuid.UUID, reason *string) error {
	fields := map[string]interface{}{
		"status":      status,
		"verified_by": verifiedBy,
		"verified_at": time.Now(),
	}
	if status == models.DocStatusRejected {
		fields["rejection_reason"] = reason
	}
	res := r.db.WithContext(ctx).Model(&models.UserDocument{}).Where("id = ?", id).Updates(fields)
	if res.Error != nil {
		return fmt.Errorf("repository: set document status: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Collaboration invites
// ---------------------------------------------------------------------------
// InviteRepository is gone with the collaboration_invites table it owned.
// Inviting somebody into a company is the claim flow now — hashed, single-use
// and expiring, where the old invite value was none of those.

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

type AuditRepository struct{ db *gorm.DB }

func NewAuditRepository(db *gorm.DB) *AuditRepository { return &AuditRepository{db: db} }

// Write records an event. Audit writes must never fail the operation being
// audited, so callers log the error and carry on.
func (r *AuditRepository) Write(ctx context.Context, e *models.AuditEntry) error {
	if err := r.db.WithContext(ctx).Create(e).Error; err != nil {
		return fmt.Errorf("repository: write audit entry: %w", err)
	}
	return nil
}

// CountRecentFailures supports login rate limiting: how many failed attempts
// this identifier has made since the window opened.
func (r *AuditRepository) CountRecentFailures(ctx context.Context, identifier string, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.AuditEntry{}).
		Where("event = ? AND created_at > ? AND detail->>'identifier' = ?",
			models.AuditLoginFailure, since, identifier).
		Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("repository: count login failures: %w", err)
	}
	return count, nil
}

func (r *AuditRepository) ListForUser(ctx context.Context, userID uuid.UUID, limit int) ([]models.AuditEntry, error) {
	var out []models.AuditEntry
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).
		Order("created_at DESC").Limit(limit).Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("repository: list audit: %w", err)
	}
	return out, nil
}

// CountActiveUsers reports how many accounts occupy a seat at a company.
//
// Soft-deleted accounts are excluded; suspended ones are not. See
// models.Company.MaxUsers for why the two are treated differently.
func (r *UserRepository) CountActiveUsers(ctx context.Context, companyID uuid.UUID) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&models.User{}).
		Where("company_id = ? AND deleted_at IS NULL", companyID).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("repository: count active users: %w", err)
	}
	return n, nil
}
