package services

import (
	"context"
	"errors"
	"fmt"
	"github.com/karlo/authentication-service/internal/platform/revocation"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/repository"
)

// EntitlementService is what a Karlo staff member uses to decide which modules
// a company has bought.
//
// This is the commercial boundary of the whole system: a permission grants
// nothing unless the company holds the feature gating it, so everything a
// customer can reach ultimately traces back to a row written here. Until now
// those rows could only be written by hand in SQL, which meant the act of
// selling a module left no record of who sold it or when.
//
// It is deliberately separate from UserService. Granting a company a module and
// granting a person a permission are different decisions made by different
// people — Karlo sells the module, the customer decides who inside uses it —
// and keeping them apart is what stops a company administrator from quietly
// widening their own entitlement.
type EntitlementService struct {
	modules   *repository.ModuleRepository
	companies *repository.CompanyRepository
	audit     *repository.AuditRepository
	announcer repository.Announcer
}

// SetAnnouncer gives the service somewhere to publish entitlement changes.
func (s *EntitlementService) SetAnnouncer(a repository.Announcer) { s.announcer = a }

// announceCompany tells the other services that everyone at this company is
// carrying a token that no longer describes what they may reach.
//
// Per COMPANY rather than per person, because entitlement is a company-level
// fact: withdrawing a module must stop working for everyone at once, not
// person by person as each token happens to expire. It is one announcement
// however many people work there.
func (s *EntitlementService) announceCompany(ctx context.Context, companyID uuid.UUID) {
	if s.announcer == nil {
		return
	}
	err := s.announcer.Publish(ctx, revocation.Event{
		Kind: revocation.KindCompany,
		ID:   companyID.String(),
		At:   time.Now().UTC(),
	})
	if err != nil {
		slog.WarnContext(ctx, "entitlement changed but not announced; it takes "+
			"effect when tokens expire rather than immediately",
			"company_id", companyID, "error", err)
	}
}

func NewEntitlementService(
	modules *repository.ModuleRepository,
	companies *repository.CompanyRepository,
	audit *repository.AuditRepository,
) *EntitlementService {
	return &EntitlementService{modules: modules, companies: companies, audit: audit}
}

// GrantInput describes one entitlement decision.
type GrantInput struct {
	CompanyID uuid.UUID
	Product   string
	Module    string

	// ValidFrom and ValidUntil express a trial or a fixed-term contract. Both
	// are optional; a grant with neither runs until it is revoked.
	ValidFrom  *time.Time
	ValidUntil *time.Time

	// Limits carries per-module quotas — seats, monthly volume — for modules
	// sold in tiers rather than simply on or off.
	Limits map[string]interface{}

	Note *string
}

// Grant gives a company a module, or updates the terms of one it already has.
//
// The feature must exist in the product's registry. Granting an unknown name
// would write a row that gates nothing: no permission references it, so the
// company would appear to hold something and reach nothing, and the mistake
// would surface as a support ticket rather than an error.
func (s *EntitlementService) Grant(ctx context.Context, actor authctx.Principal, in GrantInput) (*models.CompanyModule, error) {
	product := authctx.Product(in.Product)
	if !authctx.IsKnownProduct(product) {
		return nil, fmt.Errorf("%w: %q is not a product", ErrValidation, in.Product)
	}
	if !authctx.IsSellableFeature(product, in.Module) {
		return nil, fmt.Errorf("%w: %q is not a %s feature that can be sold",
			ErrValidation, in.Module, in.Product)
	}
	if in.ValidFrom != nil && in.ValidUntil != nil && in.ValidUntil.Before(*in.ValidFrom) {
		return nil, fmt.Errorf("%w: the grant would expire before it starts", ErrValidation)
	}

	if _, err := s.companies.FindByID(ctx, in.CompanyID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: no such company", repository.ErrNotFound)
		}
		return nil, err
	}

	actorID, err := actorUUID(actor)
	if err != nil {
		return nil, err
	}

	row := &models.CompanyModule{
		CompanyID:       in.CompanyID,
		Product:         in.Product,
		Module:          in.Module,
		Enabled:         true,
		ValidFrom:       in.ValidFrom,
		ValidUntil:      in.ValidUntil,
		Limits:          models.JSONMap(in.Limits),
		GrantedByUserID: actorID,
		Note:            in.Note,
	}
	if err := s.modules.Grant(ctx, row, actorID); err != nil {
		return nil, err
	}

	s.record(ctx, actorID, in.CompanyID, models.ModuleGranted, in.Product, in.Module)
	// Granting also needs announcing: everyone's token lists the OLD feature
	// set, so a newly bought module stays unreachable until they sign in again
	// unless the tokens are refreshed.
	s.announceCompany(ctx, in.CompanyID)
	return row, nil
}

// Revoke disables an entitlement, keeping the row so the history survives.
//
// It announces the change rather than revoking anyone's session. Entitlement is
// embedded in a token, so without the announcement a withdrawn module would
// keep working until every token expired — up to two hours. The announcement
// makes it immediate WITHOUT signing anybody out: the next request rebuilds
// their access, and someone whose remaining permissions are unaffected notices
// nothing.
func (s *EntitlementService) Revoke(ctx context.Context, actor authctx.Principal, companyID uuid.UUID, product, module string) error {
	actorID, err := actorUUID(actor)
	if err != nil {
		return err
	}
	if err := s.modules.Revoke(ctx, companyID, product, module, actorID); err != nil {
		return err
	}
	s.record(ctx, actorID, companyID, models.ModuleRevoked, product, module)
	s.announceCompany(ctx, companyID)
	return nil
}

// ListForCompany returns every entitlement row a company has, including the
// disabled ones — a support question is usually about access that stopped
// working, and an answer that omits the revoked rows cannot address it.
func (s *EntitlementService) ListForCompany(ctx context.Context, companyID uuid.UUID) ([]models.CompanyModule, error) {
	return s.modules.ListForCompany(ctx, companyID)
}

// History returns who changed a company's entitlement and when.
func (s *EntitlementService) History(ctx context.Context, companyID uuid.UUID, limit int) ([]models.CompanyModuleEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return s.modules.History(ctx, companyID, limit)
}

// Catalogue returns what a Karlo staff member can sell for a product, so the
// administration screen offers a list rather than a free-text box.
func (s *EntitlementService) Catalogue(product authctx.Product) []authctx.Feature {
	return authctx.SellableFeatures(product)
}

// record writes the audit entry. A failure to audit does not fail the grant:
// the entitlement change has already been committed with its own history row,
// and refusing the request afterwards would leave the caller believing nothing
// happened when something did.
func (s *EntitlementService) record(ctx context.Context, actorID *uuid.UUID, companyID uuid.UUID, action, product, module string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Write(ctx, &models.AuditEntry{
		ActorUserID: actorID,
		Event:       action,
		Succeeded:   true,
		Detail: models.JSONMap{
			"companyId": companyID.String(),
			"product":   product,
			"module":    module,
		},
	})
}

// actorUUID pulls the acting user's id out of the principal.
func actorUUID(actor authctx.Principal) (*uuid.UUID, error) {
	if actor.UserID == "" {
		return nil, nil
	}
	id, err := uuid.Parse(actor.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: the caller has no usable identity", ErrValidation)
	}
	return &id, nil
}
