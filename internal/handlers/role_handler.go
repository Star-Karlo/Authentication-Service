package handlers

import (
	"errors"
	"log/slog"
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
// permission model dynamic.
//
// Which company a request is about is never taken from the body: it is the
// caller's own, or the client Karlo staff are acting for via X-Acting-For,
// resolved by scopeCompany. A tenant therefore cannot name another, while
// staff administering a client see that client's roles and the catalogue it is
// actually entitled to.
type RoleHandler struct {
	roles   *repository.RoleRepository
	modules *repository.ModuleRepository
}

func NewRoleHandler(roles *repository.RoleRepository, modules *repository.ModuleRepository) *RoleHandler {
	return &RoleHandler{roles: roles, modules: modules}
}

func roleCaller(c *gin.Context) (authctx.Principal, uuid.UUID, bool) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return principal, uuid.Nil, false
	}
	// Own company, or the client staff are acting for.
	companyID, ok := scopeCompany(c)
	if !ok {
		return principal, uuid.Nil, false
	}
	return principal, companyID, true
}

// List returns the company's roles and what it may grant.
//
// @Summary  List roles
// @Tags     Roles
// @Security BearerAuth
// @Success  200 {object} response.Envelope
// @Router   /roles [get]
// roleProduct is which product's keys a request is about.
//
// A role spans every product its company holds — one "Supervisor" row can
// carry tms: and fms: keys — but an editor only ever knows one catalogue.
// So each request names its product (default tms, which is what every
// existing caller meant), vetting runs against that catalogue, and a write
// touches only that product's keys. An FMS editor saving a role cannot
// strip the TMS keys it never saw, and vice versa.
func roleProduct(c *gin.Context) (authctx.Product, bool) {
	product := authctx.Product(c.DefaultQuery("product", string(authctx.ProductTMS)))
	if len(authctx.CatalogFor(product)) == 0 {
		response.BadRequest(c, "Unknown product: "+string(product))
		return "", false
	}
	return product, true
}

func (h *RoleHandler) List(c *gin.Context) {
	principal, companyID, ok := roleCaller(c)
	if !ok {
		return
	}
	product, ok := roleProduct(c)
	if !ok {
		return
	}

	roles, err := h.roles.ListForCompany(c.Request.Context(), companyID)
	if err != nil {
		response.InternalError(c, "Could not list roles.")
		return
	}

	// An editor asking about one product sees only that product's keys, so
	// it can round-trip what it is shown without knowing the other
	// catalogue exists. The stored row is untouched.
	if c.Query("product") != "" {
		for i := range roles {
			roles[i].Permissions = keysOf(product, roles[i].Permissions)
		}
	}

	response.OK(c, gin.H{
		"roles": roles,
		// The grantable set for the company being administered — NOT for the
		// caller. An administrator cannot hand out what the company has not
		// been sold, so offering it in the editor would be offering a checkbox
		// that does nothing.
		//
		// The caller's own access is the wrong source whenever the two differ,
		// and for Karlo staff they always do: a staff principal holds every
		// feature there is, so the extra-permissions dialog offered a client's
		// member all 65 TMS keys while the client was entitled to 15. Ticking
		// any of the rest made the save refuse the whole list — "not entitled
		// to invoice, which gates invoice.read" — so nothing was stored and
		// reopening the dialog showed it empty. Scoping the offer to the
		// company that the save is vetted against is what keeps the editor
		// from proposing a key the save will reject.
		"assignable": h.assignableFor(c, companyID, principal, product),
	})
}

// assignableFor is what the company being administered may actually grant.
//
// It resolves the company's entitlement rather than reading the caller's token,
// and falls back to the caller's own grantable set only when there is no
// company to resolve — an unaffiliated principal — so a failure here can never
// silently offer more than a company holds.
func (h *RoleHandler) assignableFor(
	c *gin.Context,
	companyID uuid.UUID,
	principal authctx.Principal,
	product authctx.Product,
) []authctx.PermissionSpec {
	if h.modules == nil || companyID == uuid.Nil {
		return principal.GrantablePermissions(product)
	}
	held, err := h.modules.ActiveForCompany(c.Request.Context(), companyID, product)
	if err != nil {
		slog.ErrorContext(c.Request.Context(), "could not resolve grantable permissions",
			"companyId", companyID, "product", product, "error", err)
		return principal.GrantablePermissions(product)
	}
	return authctx.GrantableFrom(product, held)
}

// keysOf is the subset of a role's qualified keys belonging to one product.
func keysOf(product authctx.Product, keys []string) models.StringArray {
	prefix := string(product) + ":"
	out := models.StringArray{}
	for _, k := range keys {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, k)
		}
	}
	return out
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

	product, ok := roleProduct(c)
	if !ok {
		return
	}

	var req roleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	permissions, err := h.vetted(principal, product, req)
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

	product, ok := roleProduct(c)
	if !ok {
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

	permissions, err := h.vetted(principal, product, req)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	fields := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
		"grants_all":  req.GrantsAll,
	}

	// Only this product's keys are replaced; the other product's survive
	// untouched. Done in the UPDATE itself rather than read-merge-write here,
	// so two administrators saving the same role from two products cannot
	// overwrite each other's half.
	if err := h.roles.Update(c.Request.Context(), companyID, id, fields,
		repository.ReplaceProductKeys(string(product), permissions)); err != nil {
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
func (h *RoleHandler) vetted(principal authctx.Principal, product authctx.Product, req roleRequest) ([]string, error) {
	if req.GrantsAll {
		// An administrator role lists nothing: it is everything the company
		// holds, now and after the next purchase.
		return nil, nil
	}

	grantable := map[string]bool{}
	for _, spec := range principal.GrantablePermissions(product) {
		grantable[qualify(product, spec.Key)] = true
		grantable[spec.Key] = true
	}

	out := make([]string, 0, len(req.Permissions))
	for _, key := range req.Permissions {
		if !grantable[key] {
			return nil, errors.New("your company cannot grant " + key)
		}
		out = append(out, qualify(product, stripProduct(key)))
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
