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
)

// RoleHandler serves a company's own roles.
//
// Roles are the company's, not the platform's: each defines its own — "Sales",
// "Planner", "Finance" — and assigns them to its people. That is what makes the
// permission model dynamic, and it is why these endpoints are scoped to the
// caller's company with no way to name another.
type RoleHandler struct {
	roles *repository.RoleRepository
}

func NewRoleHandler(roles *repository.RoleRepository) *RoleHandler {
	return &RoleHandler{roles: roles}
}

func roleCaller(c *gin.Context) (authctx.Principal, uuid.UUID, bool) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return principal, uuid.Nil, false
	}
	companyID, err := uuid.Parse(principal.CompanyID)
	if err != nil {
		response.Forbidden(c, "Only a company has roles.")
		return principal, uuid.Nil, false
	}
	return principal, companyID, true
}

type roleResponse struct {
	models.Role
	// Assignable is what this company may actually grant: the catalogue,
	// narrowed to the features it holds. Returned with the roles so an editor
	// does not have to ask twice and cannot offer a key that would be refused.
	Assignable []authctx.PermissionSpec `json:"assignable,omitempty"`
}

// List returns the company's roles and what it may grant.
//
// @Summary  List roles
// @Tags     Roles
// @Security BearerAuth
// @Success  200 {object} response.Envelope
// @Router   /roles [get]
func (h *RoleHandler) List(c *gin.Context) {
	principal, companyID, ok := roleCaller(c)
	if !ok {
		return
	}

	roles, err := h.roles.ListForCompany(c.Request.Context(), companyID)
	if err != nil {
		response.InternalError(c, "Could not list roles.")
		return
	}

	response.OK(c, gin.H{
		"roles": roles,
		// The grantable set, from the token's own product access. An
		// administrator cannot hand out what the company has not been sold, so
		// offering it in the editor would be offering a checkbox that does
		// nothing.
		"assignable": principal.GrantablePermissions(authctx.ProductTMS),
	})
}

type roleRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description *string  `json:"description"`
	Permissions []string `json:"permissions"`

	// GrantsAll marks an administrator role. Permissions is ignored when set:
	// listing them instead would go stale the day the company buys another
	// module, and the administrator would silently not have it.
	GrantsAll bool `json:"grantsAll"`
}

// Create defines a new role.
//
// @Summary  Create a role
// @Tags     Roles
// @Security BearerAuth
// @Success  201 {object} models.Role
// @Router   /roles [post]
func (h *RoleHandler) Create(c *gin.Context) {
	principal, companyID, ok := roleCaller(c)
	if !ok {
		return
	}

	var req roleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	permissions, err := h.vetted(principal, req)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	role := &models.Role{
		CompanyID:   companyID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: permissions,
		GrantsAll:   req.GrantsAll,
	}

	if err := h.roles.Create(c.Request.Context(), role); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			response.Conflict(c, "A role with that name already exists.")
			return
		}
		response.InternalError(c, "Could not create the role.")
		return
	}
	response.Created(c, role)
}

// Update changes a role's name or what it grants.
//
// @Summary  Update a role
// @Tags     Roles
// @Security BearerAuth
// @Success  200 {object} models.Role
// @Router   /roles/{id} [put]
func (h *RoleHandler) Update(c *gin.Context) {
	principal, companyID, ok := roleCaller(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid role id")
		return
	}

	var req roleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	existing, err := h.roles.FindByID(c.Request.Context(), companyID, id)
	if err != nil {
		response.NotFound(c, "Role not found")
		return
	}

	// A system role is one the platform created and depends on — the
	// Administrator every company gets. Renaming it is harmless; changing what
	// it grants is not, because "administrator" is what the company falls back
	// on when everything else is misconfigured.
	if existing.IsSystem && !existing.GrantsAll && req.GrantsAll != existing.GrantsAll {
		response.Forbidden(c, "This role is maintained by the platform and cannot be redefined.")
		return
	}

	permissions, err := h.vetted(principal, req)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	fields := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
		"permissions": models.StringArray(permissions),
		"grants_all":  req.GrantsAll,
	}

	if err := h.roles.Update(c.Request.Context(), companyID, id, fields); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			response.Conflict(c, "A role with that name already exists.")
			return
		}
		response.InternalError(c, "Could not update the role.")
		return
	}

	updated, err := h.roles.FindByID(c.Request.Context(), companyID, id)
	if err != nil {
		response.InternalError(c, "Saved, but could not read the role back.")
		return
	}
	response.OK(c, updated)
}

// Delete removes a role no one holds.
//
// @Summary  Delete a role
// @Tags     Roles
// @Security BearerAuth
// @Success  200 {object} response.Envelope
// @Router   /roles/{id} [delete]
func (h *RoleHandler) Delete(c *gin.Context) {
	_, companyID, ok := roleCaller(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid role id")
		return
	}

	if err := h.roles.Delete(c.Request.Context(), companyID, id); err != nil {
		switch {
		case errors.Is(err, repository.ErrConflict):
			// Somebody still holds it. Deleting anyway would leave those
			// accounts pointing at nothing, which reads as "no permissions"
			// and locks people out with no explanation.
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"success": false,
				"message": "People still hold this role. Move them to another role first.",
			})
		case errors.Is(err, repository.ErrNotFound):
			response.NotFound(c, "Role not found")
		default:
			response.InternalError(c, "Could not delete the role.")
		}
		return
	}
	response.OKWithMessage(c, "Role removed.", nil)
}

// vetted narrows the requested permissions to what this company may grant.
//
// Refused rather than filtered, deliberately. A key silently dropped produces a
// role the administrator believes grants something it does not, and the gap
// only shows when somebody cannot do their job.
func (h *RoleHandler) vetted(principal authctx.Principal, req roleRequest) ([]string, error) {
	if req.GrantsAll {
		// An administrator role lists nothing: it is everything the company
		// holds, now and after the next purchase.
		return nil, nil
	}

	grantable := map[string]bool{}
	for _, spec := range principal.GrantablePermissions(authctx.ProductTMS) {
		grantable[qualify(authctx.ProductTMS, spec.Key)] = true
		grantable[spec.Key] = true
	}

	out := make([]string, 0, len(req.Permissions))
	for _, key := range req.Permissions {
		if !grantable[key] {
			return nil, errors.New("your company cannot grant " + key)
		}
		out = append(out, qualify(authctx.ProductTMS, stripProduct(key)))
	}
	return out, nil
}

// qualify puts a bare catalogue key into the product-qualified form a role
// stores: "order.read" becomes "tms:order.read".
//
// Roles span products and have no column saying which, so an unqualified key on
// one cannot be placed — access_repository skips it rather than guessing, which
// means an unqualified key grants nothing at all and does so silently.
func qualify(product authctx.Product, key string) string {
	return string(product) + ":" + key
}

// stripProduct removes a product prefix so a key can be re-qualified without
// becoming "tms:tms:order.read".
func stripProduct(key string) string {
	for _, prefix := range []string{"tms:", "fms:"} {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			return key[len(prefix):]
		}
	}
	return key
}
