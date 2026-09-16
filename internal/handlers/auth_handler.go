// Package handlers exposes the authentication service over HTTP.
package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

type AuthHandler struct {
	auth  *services.AuthService
	users *services.UserService
}

func NewAuthHandler(auth *services.AuthService, users *services.UserService) *AuthHandler {
	return &AuthHandler{auth: auth, users: users}
}

type loginRequest struct {
	// The legacy clients send whichever of these they collected, so all three
	// are accepted and folded into one identifier.
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password" binding:"required"`
	DeviceID string `json:"deviceId"`
	Platform string `json:"platform"`

	// Product names the app the person is signing in FROM: "tms" or "fms".
	//
	// It is optional and it does NOT change the token. One identity serves both
	// products, and a token minted at the FMS door must be identical to one
	// minted at the TMS door — otherwise the same account behaves differently
	// depending on where it signed in, which is exactly the coupling a shared
	// IAM exists to remove.
	//
	// What it changes is the ERROR. Without it, someone with no FMS access who
	// signs in to FMS authenticates successfully and is then refused by every
	// screen, with nothing to explain why. With it, they are told at the door.
	Product string `json:"product"`
}

// Login authenticates and opens a session.
//
// @Summary  Login
// @Tags     Auth
// @Accept   json
// @Produce  json
// @Param    body body loginRequest true "Credentials"
// @Success  200 {object} services.LoginResult
// @Router   /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	result, err := h.auth.Login(c.Request.Context(), services.LoginInput{
		Identifier: firstNonEmpty(req.Email, req.Username, req.Phone),
		Password:   req.Password,
		DeviceID:   req.DeviceID,
		Platform:   req.Platform,
		UserAgent:  c.Request.UserAgent(),
		IPAddress:  c.ClientIP(),
	})
	if err != nil {
		writeAuthError(c, err)
		return
	}

	// If the caller said which app they came from, check they can actually use
	// it. The credentials were right, so this is not an authentication failure
	// and the session stands — it is a clearer message in place of a silent
	// wall of empty screens.
	principal := principalOf(result)
	if req.Product != "" {
		product := authctx.Product(req.Product)
		if !authctx.IsKnownProduct(product) {
			response.BadRequest(c, "Unknown product: "+req.Product)
			return
		}
		if !principal.HasProduct(product) {
			response.Forbidden(c, "This account does not have access to "+
				req.Product+". Ask your company administrator to grant it.")
			return
		}
	}

	// The same identity shape as /auth/me, so a client parses one thing rather
	// than reconciling two.
	response.OK(c, gin.H{
		"tokens": result.Tokens,
		// Kept as `token` too: the access token is what clients attach to
		// requests, and making them reach into a nested object for the common
		// case is friction for no benefit.
		"token": result.Tokens.AccessToken,
		"user":  buildIdentity(result.User, principal),
	})
}

// principalOf rebuilds the principal for a freshly minted token, so the login
// response can carry the same access detail /auth/me does without the client
// making a second call.
func principalOf(result *services.LoginResult) authctx.Principal {
	if result == nil || result.User == nil {
		return authctx.Principal{}
	}
	// The token was just minted from this user, so verifying it back is the
	// cheapest way to get exactly the access it carries — and guarantees the
	// response describes the token the client actually received.
	p, err := authctx.NewVerifierFromEnv()
	if err != nil {
		return authctx.Principal{}
	}
	principal, err := p.Verify(result.Tokens.AccessToken)
	if err != nil {
		return authctx.Principal{}
	}
	return principal
}

type registerRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Password    string `json:"password" binding:"required"`
	FullName    string `json:"fullName"`
	Role        string `json:"role" binding:"required"`
	CompanyName string `json:"companyName"`
	// CompanyAbbreviation goes into every agreement number this company is
	// party to (AGR-KP-MAS-000101), so it belongs on the company from the
	// moment it exists — not bolted on later by somebody who has to remember.
	CompanyAbbreviation string `json:"companyAbbreviation"`
}

// Register creates a new root account and its company.
//
// @Summary  Register
// @Tags     Auth
// @Accept   json
// @Produce  json
// @Param    body body registerRequest true "Registration"
// @Success  201 {object} models.User
// @Router   /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	user, err := h.users.Register(c.Request.Context(), services.RegisterInput{
		Username:            req.Username,
		Email:               req.Email,
		Phone:               req.Phone,
		Password:            req.Password,
		FullName:            req.FullName,
		Role:                req.Role,
		CompanyName:         req.CompanyName,
		CompanyAbbreviation: req.CompanyAbbreviation,
	})
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	response.Created(c, user)
}

// RegisterMember creates a sub-account under the caller's company.
//
// @Summary  Register a company member
// @Tags     Auth
// @Security BearerAuth
// @Accept   json
// @Produce  json
// @Success  201 {object} models.User
// @Router   /auth/register-member [post]
func (h *AuthHandler) RegisterMember(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	var req struct {
		registerRequest
		// Permission keys from this product's catalogue, e.g. "order.read".
		Permissions []string `json:"permissions"`

		// RoleID is the role the new colleague holds, and it is REQUIRED for a
		// member — the service refuses to guess, because guessing high grants
		// access nobody chose and guessing low creates an account that cannot
		// work and looks broken.
		//
		// It was accepted by the service and never read here, so every invite
		// failed with "a role is required" no matter what the caller sent.
		RoleID string `json:"roleId"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	parentID, err := uuid.Parse(principal.UserID)
	if err != nil {
		response.Unauthorized(c, "Invalid principal")
		return
	}

	input := services.RegisterInput{
		Username:    req.Username,
		Email:       req.Email,
		Phone:       req.Phone,
		Password:    req.Password,
		FullName:    req.FullName,
		Role:        req.Role,
		ParentID:    &parentID,
		Permissions: req.Permissions,
	}
	if req.RoleID != "" {
		roleID, rerr := uuid.Parse(req.RoleID)
		if rerr != nil {
			response.BadRequest(c, "Invalid roleId")
			return
		}
		input.RoleID = &roleID
	}
	// The member joins the caller's company — or, for Karlo staff acting
	// for a client, that client. Without the second case a staff member
	// "adding a user to MAST" would quietly add them to Karlo's own row.
	if principal.CompanyID != "" || strings.TrimSpace(c.GetHeader("X-Acting-For")) != "" {
		companyID, ok := scopeCompany(c)
		if !ok {
			return
		}
		input.CompanyID = &companyID
	}

	user, err := h.users.Register(c.Request.Context(), input)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	// Staff begets staff, and only inside Karlo's own company: a member a
	// platform-staff caller creates into their OWN company (Karlo Platform
	// — no X-Acting-For, or acting for it explicitly) is platform staff. A
	// member created into a customer's company never is.
	if principal.IsPlatformStaff && input.CompanyID != nil && principal.CompanyID == input.CompanyID.String() {
		if err := h.users.GrantPlatformStaff(c.Request.Context(), parentID, user.ID); err != nil {
			slog.ErrorContext(c.Request.Context(), "platform staff flag not set on new member",
				"userId", user.ID, "error", err)
		} else {
			user.IsPlatformStaff = true
		}
	}

	response.Created(c, user)
}

// Refresh exchanges a refresh token for a new token pair.
//
// @Summary  Refresh access token
// @Tags     Auth
// @Accept   json
// @Produce  json
// @Success  200 {object} services.TokenPair
// @Router   /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refreshToken" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	tokens, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		writeAuthError(c, err)
		return
	}

	response.OK(c, tokens)
}

// Logout revokes the current session.
//
// @Summary  Logout
// @Tags     Auth
// @Security BearerAuth
// @Success  200 {object} object
// @Router   /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	var req struct {
		DeviceID string `json:"deviceId"`
	}
	_ = c.ShouldBindJSON(&req)

	userID, err := uuid.Parse(principal.UserID)
	if err != nil {
		response.Unauthorized(c, "Invalid principal")
		return
	}

	// An API-key principal has no session to revoke.
	if principal.TokenID == "" {
		response.OKWithMessage(c, "Logged out", nil)
		return
	}
	tokenID, err := uuid.Parse(principal.TokenID)
	if err != nil {
		response.BadRequest(c, "Invalid session")
		return
	}

	if err := h.auth.Logout(c.Request.Context(), tokenID, userID, req.DeviceID); err != nil {
		response.InternalError(c, "Failed to log out")
		return
	}

	response.OKWithMessage(c, "Logged out", nil)
}

// LogoutAll revokes every session the caller holds.
//
// @Summary  Logout from all devices
// @Tags     Auth
// @Security BearerAuth
// @Success  200 {object} object
// @Router   /auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, ok := principalUserID(c)
	if !ok {
		return
	}

	n, err := h.auth.LogoutAll(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, "Failed to log out")
		return
	}

	response.OKWithMessage(c, "Logged out everywhere", gin.H{"revokedSessions": n})
}

// ChangePassword updates the caller's password.
//
// @Summary  Change password
// @Tags     Auth
// @Security BearerAuth
// @Accept   json
// @Success  200 {object} object
// @Router   /auth/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, ok := principalUserID(c)
	if !ok {
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.auth.ChangePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			response.Unauthorized(c, "Current password is incorrect")
			return
		}
		response.BadRequest(c, err.Error())
		return
	}

	response.OKWithMessage(c, "Password changed. Please sign in again.", nil)
}

// CheckAvailability reports whether an identifier is free.
//
// @Summary  Check identifier availability
// @Tags     Auth
// @Produce  json
// @Param    kind  path  string true "email|username|phone"
// @Param    value query string true "Value to check"
// @Success  200 {object} object
// @Router   /auth/check-available/{kind} [get]
func (h *AuthHandler) CheckAvailability(c *gin.Context) {
	kind := c.Param("kind")
	value := c.Query("value")

	available, err := h.users.IdentifierAvailable(c.Request.Context(), kind, value)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	response.OK(c, gin.H{"available": available})
}

// Me returns the caller's own account.
//
// @Summary  Current user
// @Tags     Auth
// @Security BearerAuth
// @Success  200 {object} models.User
// @Router   /auth/me [get]
func (h *AuthHandler) Me(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	userID, ok := principalUserID(c)
	if !ok {
		return
	}

	user, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.NotFound(c, "User not found")
		return
	}

	response.OK(c, buildIdentity(user, principal))
}

// identity is what a client needs to render itself: who the user is, and what
// they may see in each product.
//
// The user record alone is no longer sufficient. Role and permissions moved to
// user_product_access when identity became multi-product, so `role` is not a
// field on the user any more — a client reading user.role would get nothing and
// silently fall through to a default view.
type identity struct {
	ID              string `json:"id"`
	Email           string `json:"email,omitempty"`
	Username        string `json:"username,omitempty"`
	FullName        string `json:"fullName,omitempty"`
	Phone           string `json:"phone,omitempty"`
	CompanyID       string `json:"companyId,omitempty"`
	Language        string `json:"language"`
	IsPlatformStaff bool   `json:"isPlatformStaff"`

	// Role and Permissions are this service's product, flattened for
	// convenience so a client that only speaks TMS need not walk the map.
	//
	// Role is the company's own NAME for the role — "Administrator", "Sales",
	// whatever they called it. It is display text, not an identifier: a company
	// may rename it at any time, so nothing may branch on its value.
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`

	// CompanyRole is which side of the market the company trades on: shipper
	// or transporter. Unlike Role it is a fixed vocabulary the platform owns,
	// which makes it the right thing for a client to switch on when deciding
	// WHICH CONSOLE to show. Empty for an account with no company.
	//
	// It was missing, and the omission broke the app: the frontend keyed its
	// navigation off Role, which used to be a fixed code and became a
	// company-chosen name when roles went dynamic. Every new account then
	// resolved to no navigation at all.
	CompanyRole string `json:"companyRole,omitempty"`
	CompanyName string `json:"companyName,omitempty"`
	// CompanyAbbreviation is the code that appears in agreement numbers.
	CompanyAbbreviation string `json:"companyAbbreviation,omitempty"`

	// Products lists what this person may use, so a client can render a product
	// switcher without a second call.
	Products []string `json:"products"`

	// Access is the full per-product detail, for a client that spans both.
	Access map[string]productAccess `json:"access"`
}

type productAccess struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	Features    []string `json:"features"`

	// GrantsAll marks an administrator: everything the company is entitled to,
	// without the keys being enumerated.
	//
	// Without it a client cannot tell an administrator from a user holding no
	// permissions at all — both arrive with an empty list — so every gated
	// control in the UI would be hidden from exactly the people who should see
	// all of them. The server already knew; it simply was not saying.
	GrantsAll bool `json:"grantsAll"`
}

func buildIdentity(user *models.User, principal authctx.Principal) identity {
	out := identity{
		ID:              user.ID.String(),
		Email:           deref(user.Email),
		Username:        deref(user.Username),
		FullName:        deref(user.FullName),
		Phone:           deref(user.Phone),
		Language:        user.Language,
		IsPlatformStaff: user.IsPlatformStaff,
		Access:          map[string]productAccess{},
		Products:        []string{},
	}
	if user.CompanyID != nil {
		out.CompanyID = user.CompanyID.String()
	}
	if user.Company != nil {
		out.CompanyRole = user.Company.Role
		out.CompanyName = user.Company.Name
		out.CompanyAbbreviation = deref(user.Company.Abbreviation)
	}

	for product, access := range principal.Access {
		out.Products = append(out.Products, string(product))
		out.Access[string(product)] = productAccess{
			Role:      access.Role,
			GrantsAll: access.GrantsAll,
			// Always an array, never null. A root account legitimately holds no
			// keys — it is unrestricted within its company's entitlement — and
			// a client checking `permissions.length` on null throws rather than
			// falling through to the entitlement check. The token itself keeps
			// omitempty, where the saving is worth having; a response read by a
			// browser does not need it and cannot afford the ambiguity.
			Permissions: emptyIfNil(access.Permissions),
			Features:    emptyIfNil(access.Features),
		}
	}

	// Flatten this service's own product to the top level.
	if current, ok := principal.Access[authctx.CurrentProduct()]; ok {
		out.Role = current.Role
		out.Permissions = emptyIfNil(current.Permissions)
	}

	// Platform staff hold no tenant role. Reporting one keeps clients that
	// switch on role working, rather than each inventing its own convention.
	if user.IsPlatformStaff && out.Role == "" {
		out.Role = "superadmin"
	}

	return out
}

// emptyIfNil turns a nil slice into an empty one, so it marshals as [] rather
// than null.
func emptyIfNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// writeAuthError maps service errors onto HTTP status codes, without leaking
// which part of a credential was wrong.
func writeAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials), errors.Is(err, services.ErrTokenInvalid):
		response.Unauthorized(c, "Invalid credentials")
	case errors.Is(err, services.ErrAccountSuspended):
		response.Forbidden(c, "Akun anda telah dihapus atau di non-aktifkan")
	case errors.Is(err, services.ErrAccountDeleted):
		response.Unauthorized(c, "Akun anda telah dihapus atau di non-aktifkan")
	case errors.Is(err, services.ErrSessionRevoked):
		response.Unauthorized(c, "Harap login kembali")
	case errors.Is(err, services.ErrRateLimited):
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"success": false,
			"message": "Too many attempts. Please try again later.",
		})
	case errors.Is(err, repository.ErrNotFound):
		response.NotFound(c, "Not found")
	default:
		response.InternalError(c, "Authentication failed")
	}
}

// principalUserID pulls the caller's id, writing a 401 and reporting false when
// there is no usable principal.
func principalUserID(c *gin.Context) (uuid.UUID, bool) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return uuid.Nil, false
	}
	id, err := uuid.Parse(principal.UserID)
	if err != nil {
		response.Unauthorized(c, "Invalid principal")
		return uuid.Nil, false
	}
	return id, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
