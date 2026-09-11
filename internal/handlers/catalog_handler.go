package handlers

import (
	"github.com/gin-gonic/gin"

	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/response"
	"github.com/karlo/authentication-service/internal/repository"
)

// CatalogHandler serves the permission catalogue.
//
// This is what a role editor is built from. Without it the role model works and
// nothing can drive a UI for it: the keys existed only in Go source, so a
// screen offering "which permissions does this role have" had no list to show.
type CatalogHandler struct {
	catalog *repository.CatalogRepository
}

func NewCatalogHandler(catalog *repository.CatalogRepository) *CatalogHandler {
	return &CatalogHandler{catalog: catalog}
}

// List returns every permission key for a product, grouped and labelled.
//
//	GET /api/v1/permissions/catalog?product=tms&includeInactive=false
func (h *CatalogHandler) List(c *gin.Context) {
	product := c.DefaultQuery("product", string(authctx.CurrentProduct()))
	if authctx.CatalogFor(authctx.Product(product)) == nil {
		response.BadRequest(c, "Unknown product: "+product+". Expected tms or fms.")
		return
	}

	// Retired keys are hidden by default. They are the ones a role may still
	// list while granting nothing, so an administrator auditing roles wants
	// them and somebody building a role does not.
	entries, err := h.catalog.List(c.Request.Context(), product,
		c.Query("includeInactive") == "true")
	if err != nil {
		response.InternalError(c, "Could not load the permission catalogue.")
		return
	}

	// Grouped for display, since a flat list of 54 keys is unusable.
	type group struct {
		Name        string                    `json:"name"`
		Permissions []repository.CatalogEntry `json:"permissions"`
	}
	var groups []group
	index := map[string]int{}
	for _, e := range entries {
		if i, ok := index[e.Group]; ok {
			groups[i].Permissions = append(groups[i].Permissions, e)
			continue
		}
		index[e.Group] = len(groups)
		groups = append(groups, group{Name: e.Group, Permissions: []repository.CatalogEntry{e}})
	}
	if groups == nil {
		groups = []group{}
	}

	response.OK(c, gin.H{"product": product, "groups": groups, "total": len(entries)})
}

// SetLabel rewords one permission for this deployment.
//
//	PUT /api/v1/permissions/catalog/:key/label   {"label": "Lihat pesanan"}
//
// An empty label clears the override and restores the code's wording. Only the
// wording is editable: a request cannot create a key, change what gates it, or
// revive a retired one.
func (h *CatalogHandler) SetLabel(c *gin.Context) {
	var body struct {
		Product string `json:"product"`
		Label   string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, "Send a JSON body with a label.")
		return
	}
	if body.Product == "" {
		body.Product = string(authctx.CurrentProduct())
	}

	err := h.catalog.SetLabel(c.Request.Context(), body.Product, c.Param("key"), body.Label)
	if err != nil {
		if err == repository.ErrNotFound {
			response.NotFound(c, "No such permission in this product's catalogue.")
			return
		}
		response.InternalError(c, "Could not update the label.")
		return
	}
	response.OK(c, gin.H{"key": c.Param("key"), "label": body.Label})
}
