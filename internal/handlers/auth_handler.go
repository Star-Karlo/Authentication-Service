// Package handlers exposes the authentication service over HTTP.
package handlers

import (
	"errors"
	"net/http"

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

	response.OK(c, result)
}

type registerRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Password    string `json:"password" binding:"required"`
	FullName    string `json:"fullName"`
	Role        string `json:"role" binding:"required"`
	CompanyName string `json:"companyName"`
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
		Username:    req.Username,
		Email:       req.Email,
		Phone:       req.Phone,
		Password:    req.Password,
		FullName:    req.FullName,
		Role:        req.Role,
		CompanyName: req.CompanyName,
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
		Permission models.Permission `json:"permission"`
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
		Username:   req.Username,
		Email:      req.Email,
		Phone:      req.Phone,
		Password:   req.Password,
		FullName:   req.FullName,
		Role:       req.Role,
		ParentID:   &parentID,
		Permission: req.Permission,
	}
	if principal.CompanyID != "" {
		companyID, perr := uuid.Parse(principal.CompanyID)
		if perr != nil {
			response.BadRequest(c, "Invalid company on principal")
			return
		}
		input.CompanyID = &companyID
	}

	user, err := h.users.Register(c.Request.Context(), input)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
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
	userID, ok := principalUserID(c)
	if !ok {
		return
	}

	user, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.NotFound(c, "User not found")
		return
	}

	response.OK(c, user)
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
