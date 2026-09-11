package handlers

import (
	"errors"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

// EntitlementHandler serves the Karlo staff endpoints for deciding what a
// company has bought.
//
// Every route here is platform-staff-only, enforced at the router. A company
// administrator must never reach these: the difference between "what we sold
// you" and "who at your company may use it" is the difference between our
// decision and theirs, and collapsing the two would let a customer grant
// themselves modules.
type EntitlementHandler struct {
	entitlements *services.EntitlementService
}

func NewEntitlementHandler(e *services.EntitlementService) *EntitlementHandler {
	return &EntitlementHandler{entitlements: e}
}

// Catalogue lists what can be sold for a product.
//
// @Summary  List sellable features
// @Tags     Entitlement
// @Security BearerAuth
// @Param    product query string false "Product (tms or fms); defaults to tms"
// @Success  200 {array} authctx.Feature
// @Router   /admin/features [get]
func (h *EntitlementHandler) Catalogue(c *gin.Context) {
	product := authctx.Product(c.DefaultQuery("product", string(authctx.ProductTMS)))
	if !authctx.IsKnownProduct(product) {
		response.BadRequest(c, "Unknown product: "+string(product))
		return
	}
	response.OK(c, h.entitlements.Catalogue(product))
}

// List returns a company's entitlement, revoked rows included.
//
// @Summary  List a company's entitlement
// @Tags     Entitlement
// @Security BearerAuth
// @Param    id path string true "Company ID"
// @Success  200 {array} models.CompanyModule
// @Router   /admin/companies/{id}/entitlements [get]
func (h *EntitlementHandler) List(c *gin.Context) {
	companyID, ok := pathID(c)
	if !ok {
		return
	}
	rows, err := h.entitlements.ListForCompany(c.Request.Context(), companyID)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, rows)
}

// grantRequest is the body of a grant.
type grantRequest struct {
	Product string `json:"product" binding:"required"`
	Module  string `json:"module" binding:"required"`
	// Dates are plain YYYY-MM-DD: an entitlement runs for whole days, and
	// carrying a time would invite a timezone argument about whether a trial
	// ended at midnight in Jakarta or in UTC.
	ValidFrom  string                 `json:"validFrom"`
	ValidUntil string                 `json:"validUntil"`
	Limits     map[string]interface{} `json:"limits"`
	Note       string                 `json:"note"`
}

// Grant gives a company a module, or changes the terms of one it holds.
//
// @Summary  Grant a company a module
// @Tags     Entitlement
// @Security BearerAuth
// @Param    id path string true "Company ID"
// @Success  200 {object} models.CompanyModule
// @Router   /admin/companies/{id}/entitlements [put]
func (h *EntitlementHandler) Grant(c *gin.Context) {
	companyID, ok := pathID(c)
	if !ok {
		return
	}
	actor, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	var body grantRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	from, err := optionalDate(body.ValidFrom)
	if err != nil {
		response.BadRequest(c, "validFrom must be YYYY-MM-DD")
		return
	}
	until, err := optionalDate(body.ValidUntil)
	if err != nil {
		response.BadRequest(c, "validUntil must be YYYY-MM-DD")
		return
	}

	in := services.GrantInput{
		CompanyID:  companyID,
		Product:    body.Product,
		Module:     body.Module,
		ValidFrom:  from,
		ValidUntil: until,
		Limits:     body.Limits,
	}
	if body.Note != "" {
		in.Note = &body.Note
	}

	row, err := h.entitlements.Grant(c.Request.Context(), actor, in)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, row)
}

// Revoke disables a module, keeping the row so the history survives.
//
// @Summary  Revoke a company's module
// @Tags     Entitlement
// @Security BearerAuth
// @Param    id path string true "Company ID"
// @Param    product path string true "Product"
// @Param    module path string true "Module"
// @Success  200 {object} response.Envelope
// @Router   /admin/companies/{id}/entitlements/{product}/{module} [delete]
func (h *EntitlementHandler) Revoke(c *gin.Context) {
	companyID, ok := pathID(c)
	if !ok {
		return
	}
	actor, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	err := h.entitlements.Revoke(c.Request.Context(), actor,
		companyID, c.Param("product"), c.Param("module"))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			response.NotFound(c, "That company does not hold this module")
			return
		}
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "Module revoked. Tokens already issued keep it "+
		"until they expire, at most fifteen minutes.", nil)
}

// History returns who changed a company's entitlement and when.
//
// @Summary  Entitlement history
// @Tags     Entitlement
// @Security BearerAuth
// @Param    id path string true "Company ID"
// @Param    limit query int false "Maximum entries (default 50, max 200)"
// @Success  200 {array} models.CompanyModuleEvent
// @Router   /admin/companies/{id}/entitlements/history [get]
func (h *EntitlementHandler) History(c *gin.Context) {
	companyID, ok := pathID(c)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))

	events, err := h.entitlements.History(c.Request.Context(), companyID, limit)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, events)
}

// optionalDate parses a YYYY-MM-DD value, treating empty as absent rather than
// as the zero date — which would otherwise expire every grant in year one.
func optionalDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
