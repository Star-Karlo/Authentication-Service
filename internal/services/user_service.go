package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	"github.com/karlo/authentication-service/internal/platform/authctx"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/repository"
	"gorm.io/gorm"
)

// ErrForbidden signals an authorisation failure inside the service layer.
var ErrForbidden = errors.New("forbidden")

// ErrValidation signals a malformed input, as distinct from a refused one.
var ErrValidation = errors.New("validation failed")

// UserService manages accounts and their permissions.
type UserService struct {
	users     *repository.UserRepository
	roles     *repository.RoleRepository
	companies *repository.CompanyRepository
	modules   *repository.ModuleRepository
	access    *repository.AccessRepository
	sessions  *repository.SessionRepository
	audit     *repository.AuditRepository
	auth      *AuthService
}

func NewUserService(
	users *repository.UserRepository,
	roles *repository.RoleRepository,
	companies *repository.CompanyRepository,
	modules *repository.ModuleRepository,
	access *repository.AccessRepository,
	sessions *repository.SessionRepository,
	audit *repository.AuditRepository,
	auth *AuthService,
) *UserService {
	return &UserService{users: users, roles: roles, companies: companies, modules: modules, access: access, sessions: sessions, audit: audit, auth: auth}
}

// RegisterInput describes a new account.
type RegisterInput struct {
	Username string
	Email    string
	Phone    string
	Password string
	FullName string
	Role     string
	// ParentID is set when a company invites a member; the new account inherits
	// that company and is subject to permission checks.
	ParentID  *uuid.UUID
	CompanyID *uuid.UUID
	// RoleID is the role the new account will hold. Required when inviting a
	// member; ignored when a registration creates a new tenant, since that
	// account becomes the administrator.
	RoleID *uuid.UUID
	// CompanyName creates a new company alongside the administrator account.
	CompanyName string
	// CompanyAbbreviation, optional. Uppercased and trimmed; the agreement
	// numbering reads it verbatim.
	CompanyAbbreviation string

	// Permissions are the keys a member is granted at creation. Empty for a
	// root account, which is unrestricted within its company's entitlement.
	Permissions []string

	// Unaffiliated creates an account that belongs to no company yet: a
	// driver registering from K-Trip before any transporter has adopted
	// them. Without it, a registration with no parent and no company stands
	// up a whole new tenant, which is the last thing a driver should be able
	// to do from a phone. The account has no role and reaches nothing until
	// a planner looks the username up and adopts it (DriverAccountService).
	Unaffiliated bool
}

// Register creates an account, and a company when the account is a root one.
func (s *UserService) Register(ctx context.Context, in RegisterInput) (*models.User, error) {
	if err := ValidatePasswordStrength(in.Password); err != nil {
		return nil, err
	}
	if in.Email == "" && in.Phone == "" && in.Username == "" {
		return nil, errors.New("one of email, phone or username is required")
	}
	// A role is required only when this registration creates a COMPANY, where
	// it says which side of the market the company trades on — shipper or
	// transporter — and drives which screens the tenant sees.
	//
	// It is NOT a person's access any more. Someone joining an existing company
	// gets that from the role they are assigned, so requiring it here would ask
	// the caller for a value nothing reads.
	if in.Unaffiliated && (in.ParentID != nil || in.CompanyID != nil) {
		return nil, fmt.Errorf("%w: an unaffiliated registration cannot name a company", ErrValidation)
	}
	if in.ParentID == nil && in.CompanyID == nil && !in.Unaffiliated && in.Role == "" {
		return nil, errors.New("role is required when registering a new company: " +
			"it says whether the company ships or transports")
	}

	if err := s.assertIdentifiersFree(ctx, in); err != nil {
		return nil, err
	}

	hash, err := s.auth.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	companyID := in.CompanyID
	// True when this registration is standing up a whole new tenant, in which
	// case the account becomes its administrator. An unaffiliated driver is
	// the one case with no parent and no company that does NOT create one.
	newTenant := in.ParentID == nil && in.CompanyID == nil && !in.Unaffiliated

	var user *models.User

	// Registration writes up to four rows — company, user, entitlement and
	// product access — and a company is unusable without all of them. Done as
	// separate statements, a failure partway through leaves exactly the state
	// each of those writes exists to prevent: a company with no modules, or an
	// account with no access row, which authenticates successfully and then
	// reaches nothing. Nobody notices until the customer tries to work.
	//
	// So the whole sequence is one transaction. The repositories are rebound to
	// it through WithTx; anything left on the outer handle would commit
	// independently and defeat the point.
	err = s.users.Transaction(ctx, func(tx *gorm.DB) error {
		users := s.users.WithTx(tx)
		companies := s.companies.WithTx(tx)
		modules := s.modules.WithTx(tx)
		access := s.access.WithTx(tx)

		// A registration with no parent and no company creates a new tenant.
		if newTenant {
			company := &models.Company{
				Name:         firstNonEmpty(in.CompanyName, in.FullName, in.Email),
				Role:         in.Role,
				Abbreviation: abbreviationOrNil(in.CompanyAbbreviation),
				Settings: models.CompanySettings{
					PPNPercentage:   0.02,
					PPH23Percentage: 0.11,
				},
			}
			if err := companies.Create(ctx, company); err != nil {
				return fmt.Errorf("register: %w", err)
			}
			companyID = &company.ID
		}

		// Seat limit, checked INSIDE the transaction and behind a row lock.
		//
		// Without the lock, two administrators inviting the last seat at the
		// same moment would both count N-1, both pass, and the company would
		// end up one over. Locking the company row makes the second wait for
		// the first, so it counts the seat that was just taken.
		//
		// Only for someone JOINING a company — registering a new one creates
		// its first account, and a company cannot be over its limit before it
		// exists.
		if !newTenant && companyID != nil {
			var limit int
			err := tx.Raw(`SELECT max_users FROM companies WHERE id = ? FOR UPDATE`,
				*companyID).Scan(&limit).Error
			if err != nil {
				return fmt.Errorf("register: read seat limit: %w", err)
			}
			if limit > 0 {
				used, cerr := users.CountActiveUsers(ctx, *companyID)
				if cerr != nil {
					return fmt.Errorf("register: count seats: %w", cerr)
				}
				if used >= int64(limit) {
					return fmt.Errorf("%w: this company has %d of %d seats in use; "+
						"remove an account or ask Karlo to raise the limit",
						ErrValidation, used, limit)
				}
			}
		}

		user = &models.User{
			Username:     nilIfEmpty(strings.TrimSpace(in.Username)),
			Email:        nilIfEmpty(strings.ToLower(strings.TrimSpace(in.Email))),
			Phone:        nilIfEmpty(strings.TrimSpace(in.Phone)),
			PasswordHash: hash,
			FullName:     nilIfEmpty(in.FullName),
			CompanyID:    companyID,
			Language:     "id",
		}

		if err := users.Create(ctx, user); err != nil {
			if errors.Is(err, repository.ErrConflict) {
				return errors.New("an account with these details already exists")
			}
			return fmt.Errorf("register: %w", err)
		}

		// A new company gets its starting entitlement.
		//
		// Without this a company could register, authenticate, and then reach
		// nothing at all: every module check consults company_modules, and an
		// account with no rows there fails all of them.
		if newTenant && companyID != nil {
			if err := modules.GrantDefaults(ctx, tx, *companyID,
				authctx.ProductTMS, authctx.DefaultTMSFeatures()); err != nil {
				return fmt.Errorf("register: grant default entitlement: %w", err)
			}
		}

		// And the account gets a role, because a role is the only way access is
		// granted now. Without one the person authenticates successfully and is
		// refused everywhere — the failure looks like a permissions bug rather
		// than an incomplete registration.
		if companyID != nil {
			roles := s.roles.WithTx(tx)

			roleID := in.RoleID
			if roleID == nil {
				if !newTenant {
					// A member invited without a role named. Refusing is better
					// than guessing: guessing high grants access nobody chose,
					// and guessing low creates an account that cannot work and
					// looks broken.
					return fmt.Errorf("%w: a role is required when inviting a member", ErrValidation)
				}
				// The founder of a new tenant administers it. There is nobody
				// else who could have been given the role.
				admin, aerr := roles.EnsureAdministrator(ctx, *companyID)
				if aerr != nil {
					return fmt.Errorf("register: administrator role: %w", aerr)
				}
				roleID = &admin.ID
			} else {
				// A named role must belong to this company. Without the check,
				// an id from another tenant would grant that tenant's access.
				if _, rerr := roles.FindByID(ctx, *companyID, *roleID); rerr != nil {
					return fmt.Errorf("%w: that role does not belong to this company", ErrForbidden)
				}
			}

			if err := users.SetRole(ctx, user.ID, *roleID); err != nil {
				return fmt.Errorf("register: assign role: %w", err)
			}
			// Reflect it on the returned value too. The write went to the
			// database, not to this struct, so a caller inspecting the account
			// it just created would see no role and reasonably conclude the
			// registration was incomplete.
			user.RoleID = roleID
		}

		// Any extra permissions the inviter chose, on top of the role.
		if len(in.Permissions) > 0 {
			if err := access.GrantProductAccess(ctx, &models.ProductAccess{
				UserID:      user.ID,
				Product:     string(authctx.ProductTMS),
				Permissions: in.Permissions,
				Enabled:     true,
			}); err != nil {
				return fmt.Errorf("register: grant extra access: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserService) assertIdentifiersFree(ctx context.Context, in RegisterInput) error {
	checks := []struct {
		value string
		fn    func(context.Context, string) (bool, error)
		label string
	}{
		{strings.ToLower(strings.TrimSpace(in.Email)), s.users.ExistsByEmail, "email"},
		{strings.TrimSpace(in.Username), s.users.ExistsByUsername, "username"},
		{strings.TrimSpace(in.Phone), s.users.ExistsByPhone, "phone"},
	}
	for _, c := range checks {
		if c.value == "" {
			continue
		}
		taken, err := c.fn(ctx, c.value)
		if err != nil {
			return fmt.Errorf("register: check %s: %w", c.label, err)
		}
		if taken {
			return fmt.Errorf("%s is already registered", c.label)
		}
	}
	return nil
}

// GetByID resolves one user.
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.users.FindByID(ctx, id)
}

// GetMany resolves several users, used by the gRPC batch endpoints.
func (s *UserService) GetMany(ctx context.Context, ids []uuid.UUID, includeDeleted bool) ([]models.User, error) {
	return s.users.FindByIDs(ctx, ids, includeDeleted)
}

// List pages accounts for an administrator.
func (s *UserService) List(ctx context.Context, p query.Params) ([]models.User, int64, error) {
	return s.users.List(ctx, p)
}

// ListCompanyMembers pages the members of one company.
func (s *UserService) ListCompanyMembers(ctx context.Context, companyID uuid.UUID, roles []string, p query.Params) ([]models.User, int64, error) {
	return s.users.ListByCompany(ctx, companyID, roles, p)
}

// profileUpdatable is the allowlist of fields a user may change on themselves.
// Anything not named here — role, permission, company, verification flags —
// cannot be set by the account holder, whatever the request body contains.
var profileUpdatable = map[string]string{
	"fullName":              "full_name",
	"phone":                 "phone",
	"address":               "address",
	"cityId":                "city_id",
	"photoUrl":              "photo_url",
	"language":              "language",
	"birthDate":             "birth_date",
	"emergencyContactName":  "emergency_contact_name",
	"emergencyContactPhone": "emergency_contact_phone",
}

// UpdateProfile applies a self-service profile change.
func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, input map[string]interface{}) error {
	fields := projectAllowed(input, profileUpdatable)
	if len(fields) == 0 {
		return errors.New("no updatable fields supplied")
	}
	return s.users.UpdateFields(ctx, userID, fields)
}

// adminUpdatable additionally allows the fields only an administrator may set.
var adminUpdatable = mergeMaps(profileUpdatable, map[string]string{
	"role":            "role",
	"isVerified":      "is_verified",
	"isEmailVerified": "is_email_verified",
	"isPhoneVerified": "is_phone_verified",
	"email":           "email",
	"username":        "username",
})

// AdminUpdate applies an administrative change to another account.
func (s *UserService) AdminUpdate(ctx context.Context, actorID, targetID uuid.UUID, input map[string]interface{}) error {
	fields := projectAllowed(input, adminUpdatable)
	if len(fields) == 0 {
		return errors.New("no updatable fields supplied")
	}
	if err := s.users.UpdateFields(ctx, targetID, fields); err != nil {
		return err
	}
	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID, Event: "user.updated", Succeeded: true,
		Detail: models.JSONMap{"fields": keysOf(fields)},
	})
	return nil
}

// SetPermission replaces a sub-account's permission map.
//
// Four rules are enforced:
//
//  1. The actor and the target belong to the same company.
//  2. A root account cannot carry a permission map, because within its
//     company's entitlement it is unrestricted and a map there would mislead.
//  3. Every module named is one the COMPANY is entitled to. This is the rule
//     that makes the two-tier model hold: an administrator cannot grant
//     accounting to a colleague when the company was never sold accounting.
//     Without it the permission editor would offer modules that silently
//     grant nothing, and an entitlement bought later would retroactively
//     activate permissions nobody reviewed.
//  4. Every module and action named actually exists, so a typo becomes an
//     error rather than a permission that never matches anything.
func (s *UserService) SetPermission(ctx context.Context, actorID, targetID uuid.UUID, product authctx.Product, permissions []string) error {
	actor, err := s.users.FindByID(ctx, actorID)
	if err != nil {
		return err
	}
	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return err
	}

	if actor.CompanyID == nil || target.CompanyID == nil || *actor.CompanyID != *target.CompanyID {
		return ErrForbidden
	}
	// An administrator already has everything the company holds, so extras
	// would grant nothing and imply a limit that does not exist.
	if role, rerr := s.roleOf(ctx, target); rerr == nil && role != nil && role.GrantsAll {
		return errors.New("an administrator role already grants everything; extra permissions would add nothing")
	}

	if err := s.assertGrantable(ctx, *target.CompanyID, product, permissions); err != nil {
		return err
	}

	if err := s.access.GrantProductAccess(ctx, &models.ProductAccess{
		UserID:          targetID,
		Product:         string(product),
		Permissions:     permissions,
		Enabled:         true,
		GrantedByUserID: &actorID,
	}); err != nil {
		return err
	}

	// The permission map is embedded in issued tokens, so it only takes effect
	// once those are gone. Revoking forces a refresh.
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("permission updated but sessions not revoked: %w", err)
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID,
		Event: models.AuditPermissionChange, Succeeded: true,
	})
	return nil
}

// SetSuspended suspends or restores an account, revoking sessions on suspend.
func (s *UserService) SetSuspended(ctx context.Context, actorID, targetID uuid.UUID, suspended bool) error {
	if err := s.users.UpdateFields(ctx, targetID, map[string]interface{}{"is_suspended": suspended}); err != nil {
		return err
	}

	event := models.AuditUserUnsuspended
	if suspended {
		event = models.AuditUserSuspended
		if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
			return fmt.Errorf("user suspended but sessions not revoked: %w", err)
		}
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID, Event: event, Succeeded: true,
	})
	return nil
}

// Delete soft-deletes an account and ends its sessions.
func (s *UserService) Delete(ctx context.Context, actorID, targetID uuid.UUID) error {
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("delete: revoke sessions: %w", err)
	}
	if err := s.users.SoftDelete(ctx, targetID); err != nil {
		return err
	}
	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID, Event: models.AuditUserDeleted, Succeeded: true,
	})
	return nil
}

// CheckPermission answers a module.action question for one user.
//
// It resolves the SAME way a request does — role, plus that person's extras,
// narrowed by what the company is entitled to — rather than consulting a
// separate source.
//
// It used to end in `user.Permission.Allows(module, action)`, reading a jsonb
// column that stopped being maintained at 000003 and stopped meaning anything
// at 000006. Every caller of this gRPC method was therefore told "no" for
// permissions the person genuinely held through their role. Administrators were
// unaffected, because the grants_all check above returned first — which is
// exactly why it survived: the accounts most likely to be tested were the ones
// it did not break.
func (s *UserService) CheckPermission(ctx context.Context, userID uuid.UUID, module, action string) (bool, error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user.IsSuspended {
		return false, nil
	}

	// Platform staff are staff everywhere, ahead of any tenant consideration.
	if user.IsPlatformStaff {
		return true, nil
	}

	access, err := s.access.BuildAccess(ctx, userID, user.CompanyID)
	if err != nil {
		return false, fmt.Errorf("check permission: %w", err)
	}

	principal := authctx.Principal{
		UserID:          userID.String(),
		IsPlatformStaff: user.IsPlatformStaff,
		Access:          access,
	}
	if user.CompanyID != nil {
		principal.CompanyID = user.CompanyID.String()
	}

	// The catalogue key is "module.action"; the caller passes the halves.
	return principal.HasPermission(authctx.CurrentProduct(), module+"."+action), nil
}

// IdentifierAvailable reports whether a login identifier is free.
func (s *UserService) IdentifierAvailable(ctx context.Context, kind, value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, errors.New("value is required")
	}

	var (
		taken bool
		err   error
	)
	switch kind {
	case "email":
		taken, err = s.users.ExistsByEmail(ctx, strings.ToLower(value))
	case "username":
		taken, err = s.users.ExistsByUsername(ctx, value)
	case "phone":
		taken, err = s.users.ExistsByPhone(ctx, value)
	default:
		return false, fmt.Errorf("unknown identifier kind %q", kind)
	}
	if err != nil {
		return false, err
	}
	return !taken, nil
}

// projectAllowed maps a client-supplied body onto database columns using an
// allowlist. Keys absent from the allowlist are dropped silently, which is the
// correct behaviour for a partial update: the caller asked for something they
// may not do, and the rest of their request is still valid.
func projectAllowed(input map[string]interface{}, allowed map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		if col, ok := allowed[k]; ok {
			out[col] = v
		}
	}
	return out
}

func mergeMaps(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "Unnamed Company"
}

var _ = time.Now

// assertGrantable rejects a permission set that reaches outside the company's
// entitlement, or that names something that does not exist.
//
// The entitlement check reads each permission's GATING FEATURE from the
// catalogue rather than splitting the key on its dot. In FMS `fuel.view` is
// gated by `live` and `dashcams.manage` by `camera`; deriving the gate from the
// key would refuse permissions the company legitimately holds.
func (s *UserService) assertGrantable(ctx context.Context, companyID uuid.UUID, product authctx.Product, permissions []string) error {
	entitled, err := s.modules.ActiveForCompany(ctx, companyID, product)
	if err != nil {
		return fmt.Errorf("resolve company entitlement: %w", err)
	}

	held := make(map[string]bool, len(entitled))
	for _, m := range entitled {
		held[m] = true
	}

	for _, key := range permissions {
		feature, known := authctx.FeatureFor(product, key)
		if !known {
			return fmt.Errorf("%w: %q is not a %s permission", ErrValidation, key, product)
		}
		// An ungated permission — master data, administration — needs no
		// entitlement.
		if feature == "" {
			continue
		}
		if !held[feature] {
			return fmt.Errorf(
				"%w: your company is not entitled to %q, which gates %q",
				ErrForbidden, feature, key)
		}
	}

	return nil
}

// GrantablePermissions returns what an administrator of this company may assign
// in a product.
//
// This is what the permission editor should render: the catalogue narrowed to
// the company's entitlement. A company without accounting sees no accounting
// section at all, rather than one that appears to work and then does nothing.
func (s *UserService) GrantablePermissions(ctx context.Context, companyID uuid.UUID, product authctx.Product) ([]authctx.PermissionSpec, error) {
	entitled, err := s.modules.ActiveForCompany(ctx, companyID, product)
	if err != nil {
		return nil, fmt.Errorf("resolve company entitlement: %w", err)
	}

	held := make(map[string]bool, len(entitled))
	for _, m := range entitled {
		held[m] = true
	}

	var out []authctx.PermissionSpec
	for _, spec := range authctx.CatalogFor(product) {
		if spec.Feature == "" || held[spec.Feature] {
			out = append(out, spec)
		}
	}
	return out, nil
}

// SetProductAccess gives a member access to a product, or changes the access
// they have.
//
// This is the other half of what a company administrator does. SetPermission
// decides what a member may do inside a product they can already reach;
// this decides whether they can reach it at all — a person with no
// user_product_access row for a product authenticates successfully and is then
// refused by every route in it, with no way for their own company to fix that.
//
// The company's entitlement bounds it: a company cannot grant its people access
// to a product it does not hold. That is checked against company_modules rather
// than assumed, because the two are written by different people at different
// times and only one of them is us.
func (s *UserService) SetProductAccess(ctx context.Context, actorID, targetID uuid.UUID, product authctx.Product, role string, permissions []string, enabled bool) error {
	if !authctx.IsKnownProduct(product) {
		return fmt.Errorf("%w: %q is not a product", ErrValidation, product)
	}

	actor, err := s.users.FindByID(ctx, actorID)
	if err != nil {
		return err
	}
	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return err
	}

	// A company administrator acts only within their own company. Karlo staff
	// are not bound by that, which is the whole point of the flag.
	if !actor.IsPlatformStaff {
		if actor.CompanyID == nil || target.CompanyID == nil || *actor.CompanyID != *target.CompanyID {
			return ErrForbidden
		}
	}

	if target.CompanyID != nil {
		held, err := s.modules.ActiveForCompany(ctx, *target.CompanyID, product)
		if err != nil {
			return fmt.Errorf("resolve company entitlement: %w", err)
		}
		if len(held) == 0 {
			return fmt.Errorf(
				"%w: your company holds no %s modules, so there is nothing to grant access to",
				ErrForbidden, product)
		}
		if err := s.assertGrantable(ctx, *target.CompanyID, product, permissions); err != nil {
			return err
		}
	}

	if err := s.access.GrantProductAccess(ctx, &models.ProductAccess{
		UserID:          targetID,
		Product:         string(product),
		Permissions:     permissions,
		Enabled:         enabled,
		GrantedByUserID: &actorID,
	}); err != nil {
		return err
	}

	// Access is embedded in issued tokens, so it takes effect only once those
	// are gone. This matters more here than for a permission change: revoking
	// a product must not leave someone using it for another fifteen minutes.
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("access updated but sessions not revoked: %w", err)
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID,
		Event: models.AuditPermissionChange, Succeeded: true,
		Detail: models.JSONMap{"product": string(product), "enabled": enabled},
	})
	return nil
}

// RevokeProductAccess takes a product away from a member.
//
// The row is disabled rather than deleted, so the grant history survives and a
// support question about access that used to work has an answer.
func (s *UserService) RevokeProductAccess(ctx context.Context, actorID, targetID uuid.UUID, product authctx.Product) error {
	actor, err := s.users.FindByID(ctx, actorID)
	if err != nil {
		return err
	}
	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return err
	}
	if !actor.IsPlatformStaff {
		if actor.CompanyID == nil || target.CompanyID == nil || *actor.CompanyID != *target.CompanyID {
			return ErrForbidden
		}
	}

	if err := s.access.RevokeProductAccess(ctx, targetID, string(product)); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("access revoked but sessions not revoked: %w", err)
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID,
		Event: models.AuditPermissionChange, Succeeded: true,
		Detail: models.JSONMap{"product": string(product), "enabled": false},
	})
	return nil
}

// ListProductAccess returns a member's access across every product.
func (s *UserService) ListProductAccess(ctx context.Context, actorID, targetID uuid.UUID) ([]models.ProductAccess, error) {
	actor, err := s.users.FindByID(ctx, actorID)
	if err != nil {
		return nil, err
	}
	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if !actor.IsPlatformStaff {
		if actor.CompanyID == nil || target.CompanyID == nil || *actor.CompanyID != *target.CompanyID {
			return nil, ErrForbidden
		}
	}
	return s.access.ListForUser(ctx, targetID)
}

// ListProductAccessForService returns a user's per-product access without an
// actor check, for internal use where the caller has already been authorised.
//
// Separate from ListProductAccess so the permission check on that path cannot
// be skipped by accident: a function that takes no actor cannot forget to
// verify one.
func (s *UserService) ListProductAccessForService(ctx context.Context, userID uuid.UUID) ([]models.ProductAccess, error) {
	return s.access.ListForUser(ctx, userID)
}

// roleOf loads the role an account holds, or nil when it holds none — which is
// only platform staff, who belong to no company.
func (s *UserService) roleOf(ctx context.Context, user *models.User) (*models.Role, error) {
	if user == nil || user.RoleID == nil || user.CompanyID == nil {
		return nil, nil
	}
	return s.roles.FindByID(ctx, *user.CompanyID, *user.RoleID)
}

// AssignRole moves a colleague to a different role.
//
// A dedicated method rather than a field on AdminUpdate, because the role id
// needs a check the generic path cannot make: the role must belong to the SAME
// company. Without it an administrator could paste another company's role id
// and grant their people that company's permissions — the ids are opaque, so
// nothing about the request would look wrong.
func (s *UserService) AssignRole(ctx context.Context, actorID, targetID, roleID uuid.UUID) error {
	actor, err := s.users.FindByID(ctx, actorID)
	if err != nil {
		return err
	}
	if actor.CompanyID == nil {
		return errors.New("only a company may assign roles")
	}

	target, err := s.users.FindByID(ctx, targetID)
	if err != nil {
		return err
	}
	// Same company, unless the caller is Karlo staff acting across tenants.
	if !actor.IsPlatformStaff &&
		(target.CompanyID == nil || *target.CompanyID != *actor.CompanyID) {
		return ErrForbidden
	}

	// The role must be the TARGET's company's, not the actor's — those differ
	// when Karlo staff assign on a client's behalf.
	roleOwner := *actor.CompanyID
	if target.CompanyID != nil {
		roleOwner = *target.CompanyID
	}
	if _, err := s.roles.FindByID(ctx, roleOwner, roleID); err != nil {
		return errors.New("that role does not belong to this company")
	}

	if err := s.users.UpdateFields(ctx, targetID, map[string]interface{}{"role_id": roleID}); err != nil {
		return err
	}

	// Access is embedded in issued tokens, so a role change takes effect only
	// once those are gone. Without this the person keeps their old permissions
	// for the life of a token they are already holding.
	if _, err := s.sessions.RevokeAllForUser(ctx, targetID); err != nil {
		return fmt.Errorf("role assigned but sessions not revoked: %w", err)
	}

	s.auth.writeAudit(ctx, &models.AuditEntry{
		UserID: &targetID, ActorUserID: &actorID,
		Event: models.AuditPermissionChange, Succeeded: true,
		Detail: models.JSONMap{"roleId": roleID.String()},
	})
	return nil
}

// abbreviationOrNil normalises a company abbreviation, or leaves it unset.
func abbreviationOrNil(s string) *string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return nil
	}
	return &s
}

// GrantPlatformStaff marks a user as Karlo staff. Called by RegisterMember
// under one rule, decided by the platform owner: a user a staff member
// creates INTO Karlo's own company is staff; a user created into any
// customer's company — by staff acting for it, or by the customer's own
// administrator — is not, whatever role they hold. The audit row is what
// lets "who made this person staff" be answered later.
func (s *UserService) GrantPlatformStaff(ctx context.Context, actorID, userID uuid.UUID) error {
	if err := s.users.UpdateFields(ctx, userID, map[string]interface{}{"is_platform_staff": true}); err != nil {
		return fmt.Errorf("grant platform staff: %w", err)
	}
	if s.audit != nil {
		_ = s.audit.Write(ctx, &models.AuditEntry{
			UserID:      &userID,
			ActorUserID: &actorID,
			Event:       "platform_staff.granted",
			Succeeded:   true,
			Detail:      models.JSONMap{"reason": "created into the platform company by platform staff"},
		})
	}
	return nil
}
