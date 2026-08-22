package handlers

import (
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

	response.Paginated(c, users, &response.Meta{
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
