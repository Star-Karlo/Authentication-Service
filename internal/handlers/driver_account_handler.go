package handlers

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

// DriverAccountHandler is the K-Trip onboarding screen's API.
type DriverAccountHandler struct {
	accounts *services.DriverAccountService
}

func NewDriverAccountHandler(s *services.DriverAccountService) *DriverAccountHandler {
	return &DriverAccountHandler{accounts: s}
}

func (h *DriverAccountHandler) fail(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, services.ErrValidation):
		response.BadRequest(c, err.Error())
	case errors.Is(err, services.ErrForbidden):
		response.Forbidden(c, err.Error())
	case errors.Is(err, repository.ErrNotFound):
		response.NotFound(c, "No such account.")
	default:
		if err != nil && err.Error() != "" && len(err.Error()) < 160 {
			response.BadRequest(c, err.Error())
			return
		}
		response.InternalError(c, fallback)
	}
}

// Create registers a driver's login and (optionally) WhatsApps the credentials.
//
// @Summary  Register a driver's K-Trip account
// @Tags     Drivers
// @Security BearerAuth
// @Router   /drivers/accounts [post]
func (h *DriverAccountHandler) Create(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}
	companyID, ok := scopeCompany(c)
	if !ok {
		return
	}
	actorID, err := uuid.Parse(principal.UserID)
	if err != nil {
		response.Unauthorized(c, "Invalid principal")
		return
	}
	var req struct {
		FullName     string `json:"fullName" binding:"required"`
		Phone        string `json:"phone" binding:"required"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		SendWhatsApp *bool  `json:"sendWhatsapp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	send := req.SendWhatsApp == nil || *req.SendWhatsApp
	out, err := h.accounts.Create(c.Request.Context(), actorID, companyID, services.CreateDriverAccountInput{
		FullName: req.FullName, Phone: req.Phone, Username: req.Username, Password: req.Password, SendWhatsApp: send,
	})
	if err != nil {
		h.fail(c, err, "Could not register the driver.")
		return
	}
	response.OKWithMessage(c, "Driver account created.", out)
}

// List shows the accounts registered under the company and their first-login state.
//
// @Summary  List driver accounts
// @Tags     Drivers
// @Security BearerAuth
// @Router   /drivers/accounts [get]
func (h *DriverAccountHandler) List(c *gin.Context) {
	companyID, ok := scopeCompany(c)
	if !ok {
		return
	}
	out, err := h.accounts.List(c.Request.Context(), companyID)
	if err != nil {
		h.fail(c, err, "Could not list driver accounts.")
		return
	}
	response.OK(c, out)
}

// Lookup finds a self-registered driver by username.
//
// @Summary  Look up a driver by username
// @Tags     Drivers
// @Security BearerAuth
// @Router   /drivers/accounts/lookup [get]
func (h *DriverAccountHandler) Lookup(c *gin.Context) {
	companyID, ok := scopeCompany(c)
	if !ok {
		return
	}
	username := c.Query("username")
	if username == "" {
		response.BadRequest(c, "username is required")
		return
	}
	out, err := h.accounts.Lookup(c.Request.Context(), companyID, username)
	if err != nil {
		h.fail(c, err, "Could not look up that username.")
		return
	}
	response.OK(c, out)
}

// Adopt attaches a self-registered driver to the company.
//
// @Summary  Adopt a self-registered driver
// @Tags     Drivers
// @Security BearerAuth
// @Router   /drivers/accounts/{id}/adopt [post]
func (h *DriverAccountHandler) Adopt(c *gin.Context) {
	companyID, ok := scopeCompany(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "That is not a valid account id.")
		return
	}
	out, err := h.accounts.Adopt(c.Request.Context(), companyID, id)
	if err != nil {
		h.fail(c, err, "Could not adopt that account.")
		return
	}
	response.OKWithMessage(c, "Driver joined your company.", out)
}
