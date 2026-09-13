package handlers

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/services"
)

// ShipperHandler exposes the placeholder-and-claim flow: a transporter records
// a shipper who has no Karlo account, trades with them, and later hands them a
// link that turns the record into their own tenant.
type ShipperHandler struct {
	shippers *services.ShipperService
	hash     func(string) (string, error)
}

func NewShipperHandler(shippers *services.ShipperService, hash func(string) (string, error)) *ShipperHandler {
	return &ShipperHandler{shippers: shippers, hash: hash}
}

type createShipperRequest struct {
	Name string `json:"name" binding:"required"`
	// Abbreviation is the code used in agreement numbers with this client.
	// Derived from the name when omitted.
	Abbreviation *string `json:"abbreviation"`
	EntityType   string  `json:"entityType"`
	NPWP         *string `json:"npwp"`
	NIB          *string `json:"nib"`
	Address      *string `json:"address"`
	CityID       *string `json:"cityId"`
	Phone        *string `json:"phone"`
}

// Create records a shipper, or links to an existing one.
//
// The response says WHICH happened. "Created" and "you are now linked to a
// shipper that already existed" are different outcomes, and a transporter who
// is not told the difference will assume they created something new and be
// surprised when another company's name appears on it.
//
// @Summary  Create or link a shipper
// @Tags     Shippers
// @Security BearerAuth
// @Router   /shippers [post]
func (h *ShipperHandler) Create(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}
	companyID, ok := scopeCompany(c)
	if !ok {
		return
	}
	actorID, _ := uuid.Parse(principal.UserID)

	var body createShipperRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "A name is required.")
		return
	}

	result, err := h.shippers.CreateShipper(c.Request.Context(), companyID, actorID,
		services.CreateShipperInput{
			Name:         body.Name,
			Abbreviation: body.Abbreviation,
			EntityType:   body.EntityType,
			NPWP:         body.NPWP,
			NIB:          body.NIB,
			Address:      body.Address,
			CityID:       body.CityID,
			Phone:        body.Phone,
		})
	if err != nil {
		if errors.Is(err, services.ErrValidation) {
			response.BadRequest(c, err.Error())
			return
		}
		response.InternalError(c, "Could not record the shipper.")
		return
	}

	message := "Shipper created."
	if result.Existing {
		message = "That tax number is already registered, so you have been " +
			"linked to the existing shipper rather than a duplicate being created."
	}
	response.OKWithMessage(c, message, result)
}

// List returns the shippers this transporter deals with.
//
// @Summary  List shippers
// @Tags     Shippers
// @Security BearerAuth
// @Router   /shippers [get]
func (h *ShipperHandler) List(c *gin.Context) {
	companyID, ok := scopeCompany(c)
	if !ok {
		return
	}

	shippers, err := h.shippers.ListShippers(c.Request.Context(), companyID)
	if err != nil {
		response.InternalError(c, "Could not list your shippers.")
		return
	}
	response.OK(c, shippers)
}

// IssueClaimLink generates the link a shipper uses to take ownership.
//
// The token is returned ONCE, here, and never stored — only its hash is kept.
// A caller that loses it must issue another, which is deliberate: a link that
// could be retrieved later would be a credential sitting in the database.
//
// @Summary  Issue a claim link
// @Tags     Shippers
// @Security BearerAuth
// @Router   /shippers/{id}/claim-link [post]
func (h *ShipperHandler) IssueClaimLink(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}
	actorID, _ := uuid.Parse(principal.UserID)

	shipperID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "That is not a valid shipper id.")
		return
	}

	token, expires, err := h.shippers.IssueClaimLink(c.Request.Context(), shipperID, actorID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAlreadyClaimed):
			response.BadRequest(c, "That company already has users, so it has been claimed.")
		case errors.Is(err, services.ErrClaimNotFound):
			response.NotFound(c, "No such shipper.")
		default:
			response.InternalError(c, "Could not issue a claim link.")
		}
		return
	}

	response.OKWithMessage(c,
		"Share this link with the shipper. It is shown once and cannot be retrieved again.",
		gin.H{"token": token, "expiresAt": expires})
}

// PreviewClaim tells whoever opened a link what they are about to claim.
//
// PUBLIC, necessarily: the whole point is that the claimant has no account yet,
// so there is no token they could authenticate with.
//
// It returns a name and nothing else. The link is a bearer credential that may
// have been forwarded or mis-sent, so anyone holding it can see enough to
// recognise their own business and no more.
//
// @Summary  Preview a claim link
// @Tags     Shippers
// @Router   /claim/{token} [get]
func (h *ShipperHandler) PreviewClaim(c *gin.Context) {
	name, err := h.shippers.PreviewClaim(c.Request.Context(), c.Param("token"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrClaimExpired):
			response.BadRequest(c, "That link has expired. Ask for a new one.")
		default:
			// A missing link and an invalid one give the same answer, so the
			// endpoint cannot be used to discover which tokens exist.
			response.NotFound(c, "That link is not valid.")
		}
		return
	}
	response.OK(c, gin.H{"companyName": name})
}

type claimRequest struct {
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Username string `json:"username"`
	Password string `json:"password" binding:"required"`
	FullName string `json:"fullName"`
	NPWP     string `json:"npwp" binding:"required"`
}

// Claim turns the placeholder into a working tenant.
//
// PUBLIC for the same reason as the preview. The link IS the authentication:
// holding it is what proves the claimant was given it.
//
// @Summary  Claim a company
// @Tags     Shippers
// @Router   /claim/{token} [post]
func (h *ShipperHandler) Claim(c *gin.Context) {
	var body claimRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "A password and a tax number (NPWP) are required.")
		return
	}

	result, err := h.shippers.Claim(c.Request.Context(), services.ClaimInput{
		Token:    c.Param("token"),
		Email:    body.Email,
		Phone:    body.Phone,
		Username: body.Username,
		Password: body.Password,
		FullName: body.FullName,
		NPWP:     body.NPWP,
	}, h.hash)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNPWPRequired):
			response.BadRequest(c, "A tax number (NPWP) is required to claim a company.")
		case errors.Is(err, services.ErrClaimExpired):
			response.BadRequest(c, "That link has expired. Ask for a new one.")
		case errors.Is(err, services.ErrAlreadyClaimed):
			response.BadRequest(c, "That company has already been claimed.")
		case errors.Is(err, services.ErrClaimNotFound):
			response.NotFound(c, "That link is not valid.")
		case errors.Is(err, services.ErrValidation):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "Could not complete the claim.")
		}
		return
	}

	message := "Your company is ready. Sign in with the account you just created."
	if result.DuplicateOfCompanyID != nil {
		// Worth saying out loud: another transporter had recorded this business
		// separately, and their orders now belong to this company too.
		message = "Your company is ready. Another record of the same business " +
			"was found and merged, so its history is included."
	}
	response.OKWithMessage(c, message, result)
}
