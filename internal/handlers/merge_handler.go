package handlers

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/services"
)

// MergeHandler folds a duplicate company into the real one.
//
// Platform staff only. Merging moves records between tenants, so it is not a
// tenant-level action however convenient that would be: a transporter deciding
// that two of THEIR shippers are the same is a judgement about somebody else's
// business, and getting it wrong moves one company's orders into another's.
type MergeHandler struct {
	merges *services.MergeService
}

func NewMergeHandler(merges *services.MergeService) *MergeHandler {
	return &MergeHandler{merges: merges}
}

type mergeRequest struct {
	// DuplicateID is the company that will STOP being used. Named rather than
	// inferred: which of two rows survives is a decision, and a caller who has
	// to name both is a caller who has thought about which is which.
	DuplicateID string `json:"duplicateId" binding:"required"`
}

// Merge folds the duplicate into the company named in the path.
//
// @Summary  Merge a duplicate company
// @Tags     Companies
// @Security BearerAuth
// @Router   /companies/{id}/merge [post]
func (h *MergeHandler) Merge(c *gin.Context) {
	principal, ok := authctx.Gin(c)
	if !ok {
		response.Unauthorized(c, "No token provided.")
		return
	}

	survivorID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "That is not a valid company id.")
		return
	}

	var body mergeRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Name the duplicate company to merge in.")
		return
	}
	duplicateID, err := uuid.Parse(body.DuplicateID)
	if err != nil {
		response.BadRequest(c, "That is not a valid company id.")
		return
	}

	actorID, _ := uuid.Parse(principal.UserID)
	result, err := h.merges.Merge(c.Request.Context(), survivorID, duplicateID, &actorID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrMergeIntoSelf):
			response.BadRequest(c, "A company cannot be merged into itself.")
		case errors.Is(err, services.ErrAlreadyMerged):
			response.BadRequest(c, err.Error())
		case errors.Is(err, services.ErrSurvivorHasUsers):
			response.BadRequest(c, "Both companies have people signed in. Merging "+
				"would move accounts between tenants, so it must be resolved by hand.")
		case errors.Is(err, services.ErrValidation):
			response.BadRequest(c, err.Error())
		default:
			response.InternalError(c, "Could not merge the companies.")
		}
		return
	}

	response.OKWithMessage(c,
		"Merged. The duplicate now forwards to this company, so existing "+
			"references to it still resolve.", result)
}
