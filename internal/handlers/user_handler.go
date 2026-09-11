package handlers

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
)

type UserHandler struct {
	users *services.UserService
}

func NewUserHandler(users *services.UserService) *UserHandler {
	return &UserHandler{users: users}
}

// List pages accounts. Administrators see everything; anyone else is scoped to
// their own company, enforced here rather than trusted from a query parameter.
//
// @Summary  List users
// @Tags     Users
// @Security BearerAuth
// @Success  200 {object} response.Meta
// @Router   /users [get]
func (h *UserHandler) List(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	params := parseQuery(c, repository.UserListFields())
	if badQuery(c, params) {
		return
	}

	var (
		users []models.User
		total int64
		err   error
	)

	if principal.HasRole("superadmin", "admin") {
		users, total, err = h.users.List(c.Request.Context(), params)
	} else {
		companyID, perr := uuid.Parse(principal.CompanyID)
		if perr != nil {
			response.Forbidden(c, "Access Denied")
			return
		}
		users, total, err = h.users.ListCompanyMembers(c.Request.Context(), companyID, nil, params)
	}

	if err != nil {
		response.InternalError(c, "Failed to list users")
		return
	}

	// Attach each member's role in THIS product.
	//
	// models.User.Role is json:"-" because it is a deprecated column that
	// nothing reads any more — access became per product. The effect was that a
	// member list arrived with every role null, so a screen could not tell a
	// warehouse PIC from an ordinary member, which is most of what a member
	// list is for.
	response.Paginated(c, h.withProductRoles(c.Request.Context(), users), &response.Meta{
		Page:       params.Page,
		Limit:      params.PageSize,
		TotalRows:  total,
		TotalPages: params.TotalPages(total),
	})
}

// Get returns one account.
//
// @Summary  Get user
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} models.User
// @Router   /users/{id} [get]
func (h *UserHandler) Get(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}

	user, err := h.users.GetByID(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c, "User not found")
		return
	}

	// A caller may read their own record, anyone in their company, or anything
	// at all if they administer the platform.
	principal, _ := authctx.Gin(c)
	if !principal.HasRole("superadmin", "admin") &&
		principal.UserID != user.ID.String() &&
		(user.CompanyID == nil || principal.CompanyID != user.CompanyID.String()) {
		response.Forbidden(c, "Access Denied")
		return
	}

	response.OK(c, user)
}

// UpdateMe applies a self-service profile change.
//
// @Summary  Update own profile
// @Tags     Users
// @Security BearerAuth
// @Success  200 {object} object
// @Router   /users/me [put]
func (h *UserHandler) UpdateMe(c *gin.Context) {
	userID, ok := principalUserID(c)
	if !ok {
		return
	}

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.users.UpdateProfile(c.Request.Context(), userID, body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	response.OKWithMessage(c, "Profile updated", nil)
}

// Update applies an administrative change to another account.
//
// @Summary  Update user
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} object
// @Router   /users/{id} [put]
func (h *UserHandler) Update(c *gin.Context) {
	actorID, ok := principalUserID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.users.AdminUpdate(c.Request.Context(), actorID, targetID, body); err != nil {
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "User updated", nil)
}

// AssignRole moves a colleague to a different role.
//
// @Summary  Assign a role
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} object
// @Router   /users/{id}/role [put]
func (h *UserHandler) AssignRole(c *gin.Context) {
	actorID, ok := principalUserID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	var body struct {
		RoleID string `json:"roleId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	roleID, err := uuid.Parse(body.RoleID)
	if err != nil {
		response.BadRequest(c, "Invalid roleId")
		return
	}

	if err := h.users.AssignRole(c.Request.Context(), actorID, targetID, roleID); err != nil {
		writeServiceError(c, err)
		return
	}
	response.OKWithMessage(c, "Role assigned. They will see the change on their next sign-in.", nil)
}

// SetPermission replaces a sub-account's permission map.
//
// @Summary  Set user permissions
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} object
// @Router   /users/{id}/permission [put]
func (h *UserHandler) SetPermission(c *gin.Context) {
	actorID, ok := principalUserID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	var body struct {
		// The product this grant applies to. Required and explicit: a person may
		// hold different roles and permissions in TMS and FMS, so a grant that
		// did not say which would be ambiguous.
		Product string `json:"product" binding:"required"`
		// Permission keys from that product's catalogue, e.g. "order.read".
		Permissions []string `json:"permissions" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	product := authctx.Product(body.Product)
	if len(authctx.CatalogFor(product)) == 0 {
		response.BadRequest(c, "Unknown product: "+body.Product)
		return
	}

	if err := h.users.SetPermission(c.Request.Context(), actorID, targetID, product, body.Permissions); err != nil {
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "Permissions updated. The user must sign in again.", nil)
}

// Suspend suspends or restores an account.
//
// @Summary  Suspend or restore user
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} object
// @Router   /users/{id}/suspend [put]
func (h *UserHandler) Suspend(c *gin.Context) {
	actorID, ok := principalUserID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	var body struct {
		Suspended bool `json:"suspended"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	if err := h.users.SetSuspended(c.Request.Context(), actorID, targetID, body.Suspended); err != nil {
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "User updated", nil)
}

// Delete soft-deletes an account.
//
// @Summary  Delete user
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} object
// @Router   /users/{id} [delete]
func (h *UserHandler) Delete(c *gin.Context) {
	actorID, ok := principalUserID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	if err := h.users.Delete(c.Request.Context(), actorID, targetID); err != nil {
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "User deleted", nil)
}

// parseQuery reads the legacy listing parameters against a field allowlist.
func parseQuery(c *gin.Context, fields query.FieldSet) query.Params {
	return query.Parse(
		c.DefaultQuery("page", "0"),
		c.DefaultQuery("pageSize", "20"),
		c.Query("filtered"),
		c.Query("sorted"),
		c.Query("search"),
		fields,
	)
}

// memberSummary is a user as a member list needs them: the record plus their
// role in this product.
type memberSummary struct {
	*models.User
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// withProductRoles resolves each user's role and permissions for this service's
// product. One query for the whole page rather than one per row.
func (h *UserHandler) withProductRoles(ctx context.Context, users []models.User) []memberSummary {
	out := make([]memberSummary, 0, len(users))
	for i := range users {
		row := memberSummary{User: &users[i], Permissions: []string{}}

		access, err := h.users.ListProductAccessForService(ctx, users[i].ID)
		if err == nil {
			for _, a := range access {
				if a.Product == string(authctx.CurrentProduct()) && a.Enabled {
					// Only the EXTRAS live here now; the role name comes from
					// the role itself, below.
					if a.Permissions != nil {
						row.Permissions = a.Permissions
					}
				}
			}
		}
		// Karlo staff hold no tenant role; report one so a client switching on
		// role keeps working rather than each inventing its own convention.
		if row.Role == "" && users[i].IsPlatformStaff {
			row.Role = "superadmin"
		}
		out = append(out, row)
	}
	return out
}

// callerID resolves the acting user from the token.
func callerID(c *gin.Context) (uuid.UUID, bool) {
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

// pathID parses the :id path parameter, writing a 400 when it is malformed.
func pathID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid id")
		return uuid.Nil, false
	}
	return id, true
}

func writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		response.NotFound(c, "Not found")
	case errors.Is(err, services.ErrForbidden):
		response.Forbidden(c, "Access Denied")
	case errors.Is(err, repository.ErrConflict):
		response.Conflict(c, "Already exists")
	default:
		response.BadRequest(c, err.Error())
	}
}

// accessRequest is the body of a product-access grant.
type accessRequest struct {
	Product string `json:"product" binding:"required"`
	// Role is the tenant role in that product's vocabulary. Empty keeps the
	// role the account already has, which is what a caller who only wants to
	// change permissions should send.
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	// Enabled defaults to true when omitted; a caller disabling access should
	// use the DELETE route, which records the intent properly.
	Enabled *bool `json:"enabled"`
}

// ListAccess returns a member's access across every product.
//
// @Summary  List a user's product access
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {array} models.ProductAccess
// @Router   /users/{id}/access [get]
func (h *UserHandler) ListAccess(c *gin.Context) {
	actorID, ok := callerID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	rows, err := h.users.ListProductAccess(c.Request.Context(), actorID, targetID)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, rows)
}

// SetAccess gives a member access to a product, or changes it.
//
// @Summary  Grant a user access to a product
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Success  200 {object} response.Envelope
// @Router   /users/{id}/access [put]
func (h *UserHandler) SetAccess(c *gin.Context) {
	actorID, ok := callerID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	var body accessRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	err := h.users.SetProductAccess(c.Request.Context(), actorID, targetID,
		authctx.Product(body.Product), body.Role, body.Permissions, enabled)
	if err != nil {
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "Access updated. The account must sign in again "+
		"for it to take effect.", nil)
}

// RevokeAccess takes a product away from a member.
//
// @Summary  Revoke a user's access to a product
// @Tags     Users
// @Security BearerAuth
// @Param    id path string true "User ID"
// @Param    product path string true "Product"
// @Success  200 {object} response.Envelope
// @Router   /users/{id}/access/{product} [delete]
func (h *UserHandler) RevokeAccess(c *gin.Context) {
	actorID, ok := callerID(c)
	if !ok {
		return
	}
	targetID, ok := pathID(c)
	if !ok {
		return
	}

	err := h.users.RevokeProductAccess(c.Request.Context(), actorID, targetID,
		authctx.Product(c.Param("product")))
	if err != nil {
		writeServiceError(c, err)
		return
	}

	response.OKWithMessage(c, "Access revoked and sessions ended.", nil)
}

// badQuery answers 400 when a listing request could not be understood, and
// reports whether the handler should stop.
//
// A filter the server does not understand must never be silently dropped: the
// response would be 200 with real rows and only the count wrong, which is far
// harder to notice than an error.
func badQuery(c *gin.Context, p query.Params) bool {
	if p.Err == nil {
		return false
	}
	response.BadRequest(c, p.Err.Error())
	return true
}
