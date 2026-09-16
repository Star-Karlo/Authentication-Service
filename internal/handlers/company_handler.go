package handlers

import (
	"errors"
	"math"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
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
	modules   *repository.ModuleRepository
}

func NewCompanyHandler(companies *repository.CompanyRepository, modules *repository.ModuleRepository) *CompanyHandler {
	return &CompanyHandler{companies: companies, modules: modules}
}

// companyRow is a company as the directory lists it: the record plus which
// products it actually holds, so a screen can say "FMS only" without a
// second request per row.
type companyRow struct {
	models.Company
	Products []string `json:"products"`
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

	rows := make([]companyRow, 0, len(companies))
	for i := range companies {
		row := companyRow{Company: companies[i], Products: []string{}}
		for _, product := range []authctx.Product{authctx.ProductTMS, authctx.ProductFMS} {
			held, err := h.modules.ActiveForCompany(c.Request.Context(), companies[i].ID, product)
			if err == nil && len(held) > 0 {
				row.Products = append(row.Products, string(product))
			}
		}
		rows = append(rows, row)
	}

	pages := 0
	if p.PageSize > 0 {
		pages = int(math.Ceil(float64(total) / float64(p.PageSize)))
	}
	response.Paginated(c, rows, &response.Meta{
		Page: p.Page, Limit: p.PageSize, TotalRows: total, TotalPages: pages,
	})
}

// profileRequest is the printable company profile. Every field is optional
// and a field left out is left alone; an explicit "" clears it. Identity —
// role, NPWP, NIB, suspension — is not here: those are platform decisions,
// not something a company edits about itself.
type profileRequest struct {
	Name       *string `json:"name"`
	LegalName  *string `json:"legalName"`
	Address    *string `json:"address"`
	City       *string `json:"city"`
	Province   *string `json:"province"`
	PostalCode *string `json:"postalCode"`
	Country    *string `json:"country"`
	Phone      *string `json:"phone"`
	Email      *string `json:"email"`
	Website    *string `json:"website"`
	LogoKey    *string `json:"logoKey"`
	// The console's Profil Perusahaan edits these too. LogoURL is the
	// legacy public-URL column; the console stores a small compressed data
	// URL there, which is why the request body is capped in the handler.
	LogoURL        *string                 `json:"logoUrl"`
	NPWP           *string                 `json:"npwp"`
	CompanyProfile *string                 `json:"companyProfile"`
	BankAccount    *map[string]interface{} `json:"bankAccount"`
	Profile        *map[string]interface{} `json:"profile"`
}

// maxProfileBody bounds the profile request: a compressed logo data URL is
// tens of kilobytes, and nothing else on the form is large.
const maxProfileBody = 512 << 10

func (r profileRequest) fields() (map[string]interface{}, error) {
	out := map[string]interface{}{}
	set := func(col string, v *string) {
		if v != nil {
			out[col] = nilIfBlank(strings.TrimSpace(*v))
		}
	}
	if r.Name != nil && strings.TrimSpace(*r.Name) == "" {
		return nil, errors.New("name cannot be empty")
	}
	set("name", r.Name)
	set("legal_name", r.LegalName)
	set("address", r.Address)
	set("city", r.City)
	set("province", r.Province)
	set("postal_code", r.PostalCode)
	set("phone", r.Phone)
	set("email", r.Email)
	set("website", r.Website)
	set("logo_key", r.LogoKey)
	set("logo_url", r.LogoURL)
	set("npwp", r.NPWP)
	set("company_profile", r.CompanyProfile)
	if r.BankAccount != nil {
		out["bank_account"] = models.JSONMap(*r.BankAccount)
	}
	if r.Profile != nil {
		out["profile"] = models.JSONMap(*r.Profile)
	}
	if r.Country != nil {
		cc := strings.ToUpper(strings.TrimSpace(*r.Country))
		if len(cc) != 2 {
			return nil, errors.New("country must be an ISO 3166-1 alpha-2 code")
		}
		out["country"] = cc
	}
	return out, nil
}

func nilIfBlank(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// Me returns the caller's own company (or the one staff are acting for).
//
// @Summary  My company
// @Tags     Companies
// @Security BearerAuth
// @Success  200 {object} models.Company
// @Router   /companies/me [get]
func (h *CompanyHandler) Me(c *gin.Context) {
	id, ok := scopeCompany(c)
	if !ok {
		return
	}
	company, err := h.companies.FindByID(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c, "Company not found")
		return
	}
	response.OK(c, company)
}

// UpdateMe edits the caller's own company profile.
//
// @Summary  Update my company profile
// @Tags     Companies
// @Security BearerAuth
// @Param    body body profileRequest true "Profile"
// @Success  200 {object} models.Company
// @Router   /companies/me [put]
func (h *CompanyHandler) UpdateMe(c *gin.Context) {
	id, ok := scopeCompany(c)
	if !ok {
		return
	}
	h.updateProfile(c, id)
}

// Update edits any company's profile; platform staff only.
//
// @Summary  Update a company profile
// @Tags     Companies
// @Security BearerAuth
// @Param    id   path string         true "Company ID"
// @Param    body body profileRequest true "Profile"
// @Success  200 {object} models.Company
// @Router   /admin/companies/{id} [put]
func (h *CompanyHandler) Update(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	h.updateProfile(c, id)
}

func (h *CompanyHandler) updateProfile(c *gin.Context, id uuid.UUID) {
	var req profileRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxProfileBody)
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	fields, err := req.fields()
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.companies.UpdateFields(c.Request.Context(), id, fields); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			response.NotFound(c, "Company not found")
			return
		}
		response.InternalError(c, "Could not update the company.")
		return
	}
	company, err := h.companies.FindByID(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c, "Company not found")
		return
	}
	response.OK(c, company)
}

// scopeCompany is the company a request is about: the caller's own, or the
// client a Karlo staff member is acting for (X-Acting-For, staff only).
//
// One helper because "which company" is the same question on roles,
// members, shippers and the profile — and answering it differently in one
// handler is how staff acting for a client end up editing Karlo's own row.
func scopeCompany(c *gin.Context) (uuid.UUID, bool) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return uuid.Nil, false
	}
	raw := principal.CompanyID
	if principal.IsPlatformStaff {
		if acting := strings.TrimSpace(c.GetHeader("X-Acting-For")); acting != "" {
			raw = acting
		}
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		response.Forbidden(c, "Only a company has a profile.")
		return uuid.Nil, false
	}
	return id, true
}
