package handlers

import (
	"math"

	"github.com/gin-gonic/gin"

	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/repository"
)

// CompanyHandler serves the platform-wide company directory.
//
// Karlo staff only. Every other listing in this service is scoped to the
// caller's own company; this one deliberately is not, because administering
// across tenants is what the staff flag means.
type CompanyHandler struct {
	companies *repository.CompanyRepository
}

func NewCompanyHandler(companies *repository.CompanyRepository) *CompanyHandler {
	return &CompanyHandler{companies: companies}
}

// companyFields is the allowlist for filtering and sorting the directory.
//
// `role` is here because it is the whole point of the screen: shippers and
// transporters are the same table told apart by it.
var companyFields = query.FieldSet{
	"name":         "name",
	"role":         "role",
	"abbreviation": "abbreviation",
	"entityType":   "entity_type",
	"createdAt":    "created_at",
}

// List pages every company on the platform.
//
// This replaces deriving the directory from /users, which could only ever show
// companies that had a member — so an unclaimed placeholder, the exact thing a
// transporter creates before a client signs in, was invisible on the screen
// meant to list it.
//
// @Summary  List companies
// @Tags     Admin
// @Security BearerAuth
// @Success  200 {object} response.Envelope
// @Router   /admin/companies [get]
func (h *CompanyHandler) List(c *gin.Context) {
	p := query.Parse(
		c.Query("page"), c.Query("pageSize"),
		c.Query("filtered"), c.Query("sorted"), c.Query("search"),
		companyFields,
	)
	if p.Err != nil {
		response.BadRequest(c, p.Err.Error())
		return
	}

	// `role` as a plain query parameter as well as through the filter list:
	// the directory always wants one side of the market, and making every
	// caller encode a JSON filter for the common case is friction.
	if role := c.Query("role"); role != "" {
		p.Filters = append(p.Filters, query.Filter{
			Field: "role", Value: role, Operator: query.OpEq,
		})
	}

	companies, total, err := h.companies.List(c.Request.Context(), p)
	if err != nil {
		response.InternalError(c, "Could not list companies.")
		return
	}

	pages := 0
	if p.PageSize > 0 {
		pages = int(math.Ceil(float64(total) / float64(p.PageSize)))
	}
	response.Paginated(c, companies, &response.Meta{
		Page: p.Page, Limit: p.PageSize, TotalRows: total, TotalPages: pages,
	})
}
