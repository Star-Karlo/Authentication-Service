package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/karlo/authentication-service/internal/models"
)

// ShipperService lets a transporter record a shipper that has no Karlo account
// yet, and lets that shipper later claim it.
//
// The shape of the problem: a transporter needs to name a shipper on an order
// before the shipper has ever heard of Karlo. So a real company row has to
// exist without being a working tenant — which it is not, because it has no
// users, and an account is the only thing that can authenticate.
type ShipperService struct {
	db    *gorm.DB
	audit auditWriter
}

func NewShipperService(db *gorm.DB, audit auditWriter) *ShipperService {
	return &ShipperService{db: db, audit: audit}
}

// ClaimTokenTTL is how long a claim link works for.
//
// Long, deliberately. This is not a password reset: the link is emailed or sent
// by WhatsApp to a business that may take a week to act on it, and a link that
// expires before anyone reads it generates a support request rather than
// security.
const ClaimTokenTTL = 14 * 24 * time.Hour

var (
	ErrShipperExists  = errors.New("a shipper with that tax number already exists")
	ErrClaimNotFound  = errors.New("that claim link is not valid")
	ErrClaimExpired   = errors.New("that claim link has expired")
	ErrAlreadyClaimed = errors.New("that company has already been claimed")
	ErrNPWPRequired   = errors.New("a tax number is required to claim a company")
)

// CreateShipperInput describes a shipper a transporter deals with.
type CreateShipperInput struct {
	Name string

	// Abbreviation is the short code that appears in agreement numbers with
	// this client: AGR-<transporter>-<client>-000001. Optional — derived from
	// the name when omitted — but offered because the transporter creating the
	// record usually knows what their people already call this customer, and a
	// derived code they have to correct later is one that has already appeared
	// on a contract.
	Abbreviation *string

	// EntityType is "company" or "personal". A personal shipper is an
	// individual: NPWP and a bank account, no NIB.
	EntityType string

	// NPWP is optional. A transporter creating a placeholder usually does not
	// know it — that is the whole point of a placeholder — but when supplied it
	// is what identifies the business.
	NPWP    *string
	NIB     *string
	Address *string
	CityID  *string
	Phone   *string

	// PicName and IndustrySector go into the company's free-form profile.
	PicName        *string
	IndustrySector *string
}

// CreateShipperResult says what happened, because "created" and "you are now
// linked to one that already existed" are different outcomes and the caller
// should be able to tell the user which.
type CreateShipperResult struct {
	Company  *models.Company `json:"company"`
	Existing bool            `json:"existing"`
}

var nonDigits = regexp.MustCompile(`[^0-9]`)

// normaliseTaxID strips formatting so 01.234.567.8-901.000 and 012345678901000
// compare equal. It must match the SQL function of the same name that backs the
// unique index; if the two ever disagree, a duplicate slips through the lookup
// and is then refused by the database with an error nobody can act on.
func normaliseTaxID(v string) string { return nonDigits.ReplaceAllString(v, "") }

// CreateShipper records a shipper for a transporter, or links to the existing
// one if the tax number is already known.
//
// Two transporters dealing with the same business must reach the SAME row —
// otherwise the shipper claims one of them and the other transporter's orders
// point at an abandoned company. When the tax number matches, this links rather
// than creating, and says so.
func (s *ShipperService) CreateShipper(ctx context.Context, transporterID uuid.UUID, actorID uuid.UUID, in CreateShipperInput) (*CreateShipperResult, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, fmt.Errorf("%w: a name is required", ErrValidation)
	}
	if in.EntityType == "" {
		in.EntityType = "company"
	}
	if in.EntityType != "company" && in.EntityType != "personal" {
		return nil, fmt.Errorf("%w: entityType must be company or personal", ErrValidation)
	}
	// A personal shipper is an individual and has no business registration.
	// Accepting one would record a number that cannot exist.
	if in.EntityType == "personal" && in.NIB != nil && *in.NIB != "" {
		return nil, fmt.Errorf("%w: a personal shipper has no NIB", ErrValidation)
	}

	result := &CreateShipperResult{}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// If the tax number is known, look first.
		//
		// Relying on the unique index alone would work — the insert would fail
		// — but a constraint violation is not something a transporter can act
		// on. Looking first turns it into "you are now linked to this shipper".
		if in.NPWP != nil && normaliseTaxID(*in.NPWP) != "" {
			var existing models.Company
			err := tx.Where("normalise_tax_id(npwp) = ? AND deleted_at IS NULL",
				normaliseTaxID(*in.NPWP)).First(&existing).Error
			if err == nil {
				result.Company = &existing
				result.Existing = true
				return s.link(tx, transporterID, existing.ID, actorID)
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("create shipper: look up tax number: %w", err)
			}
		}

		company := &models.Company{
			Name:               in.Name,
			Abbreviation:       in.Abbreviation,
			Role:               "shipper",
			EntityType:         in.EntityType,
			NPWP:               in.NPWP,
			NIB:                in.NIB,
			Address:            in.Address,
			CityID:             in.CityID,
			Phone:              in.Phone,
			Profile:            profileFrom(in),
			CreatedByCompanyID: &transporterID,
			Settings: models.CompanySettings{
				PPNPercentage:   0.02,
				PPH23Percentage: 0.11,
			},
		}
		if err := tx.Create(company).Error; err != nil {
			// Lost a race with another transporter creating the same shipper
			// between the lookup and the insert. The unique index is what makes
			// that safe; this turns it back into the same friendly answer.
			if strings.Contains(err.Error(), "idx_companies_npwp") ||
				strings.Contains(err.Error(), "idx_companies_nib") {
				return ErrShipperExists
			}
			return fmt.Errorf("create shipper: %w", err)
		}

		result.Company = company
		return s.link(tx, transporterID, company.ID, actorID)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *ShipperService) link(tx *gorm.DB, transporterID, shipperID, actorID uuid.UUID) error {
	// A zero actor becomes NULL rather than a zero uuid, which no user has and
	// the foreign key rejects. Machine-initiated links have no actor.
	var actor interface{}
	if actorID != uuid.Nil {
		actor = actorID
	}
	err := tx.Exec(`
		INSERT INTO company_links (transporter_company_id, shipper_company_id, linked_by_user_id)
		VALUES (?, ?, ?)
		ON CONFLICT DO NOTHING
	`, transporterID, shipperID, actor).Error
	if err != nil {
		return fmt.Errorf("link shipper: %w", err)
	}
	return nil
}

// ListShippers returns the shippers a transporter deals with.
func (s *ShipperService) ListShippers(ctx context.Context, transporterID uuid.UUID) ([]models.Company, error) {
	var out []models.Company
	err := s.db.WithContext(ctx).
		Joins("JOIN company_links l ON l.shipper_company_id = companies.id").
		Where("l.transporter_company_id = ? AND companies.deleted_at IS NULL", transporterID).
		Order("companies.name").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("list shippers: %w", err)
	}
	return out, nil
}

// ListTransporters is the other side of the same link: the 3PL vendors a
// shipper deals with, for its Transporter List.
func (s *ShipperService) ListTransporters(ctx context.Context, shipperID uuid.UUID) ([]models.Company, error) {
	var out []models.Company
	err := s.db.WithContext(ctx).
		Joins("JOIN company_links l ON l.transporter_company_id = companies.id").
		Where("l.shipper_company_id = ? AND companies.deleted_at IS NULL", shipperID).
		Order("companies.name").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("list transporters: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Claiming
// ---------------------------------------------------------------------------

// IssueClaimLink generates a link that lets a shipper take ownership of the
// company recorded for them.
//
// The token is returned ONCE, here, and never stored — only its SHA-256 is
// kept. A database leak then exposes no usable links, which matters more than
// it would for a password reset: this link transfers ownership of a company and
// everything recorded against it.
//
// Re-issuing overwrites, so a company has at most one live link by
// construction. That also means a lost link is fixed by issuing another, and
// the old one stops working the moment the new one exists.
func (s *ShipperService) IssueClaimLink(ctx context.Context, companyID uuid.UUID, actorID uuid.UUID) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, fmt.Errorf("issue claim link: %w", err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	expires := time.Now().UTC().Add(ClaimTokenTTL)

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var users int64
		if err := tx.Model(&models.User{}).
			Where("company_id = ? AND deleted_at IS NULL", companyID).
			Count(&users).Error; err != nil {
			return fmt.Errorf("issue claim link: %w", err)
		}
		// A company with people in it is already somebody's. Issuing a link
		// would offer a stranger administrator access to a live tenant.
		if users > 0 {
			return ErrAlreadyClaimed
		}

		res := tx.Exec(`
			UPDATE companies
			SET claim_token_hash = ?, claim_expires_at = ?, claim_issued_by_user_id = ?,
			    updated_at = NOW()
			WHERE id = ? AND deleted_at IS NULL
		`, hex.EncodeToString(sum[:]), expires, actorID, companyID)
		if res.Error != nil {
			return fmt.Errorf("issue claim link: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrClaimNotFound
		}
		return nil
	})
	if err != nil {
		return "", time.Time{}, err
	}

	_ = s.audit.Write(ctx, &models.AuditEntry{
		ActorUserID: &actorID,
		Event:       models.AuditClaimIssued,
		Succeeded:   true,
		Detail:      models.JSONMap{"companyId": companyID.String()},
	})

	return token, expires, nil
}

// PreviewClaim tells whoever opened a link what they are about to claim.
//
// Deliberately thin: a name, and nothing else. The link is a bearer credential
// that may have been forwarded or mis-sent, so anyone holding it can see enough
// to recognise their own business and no more — not the address, not the tax
// number, and certainly not the orders already recorded against it.
func (s *ShipperService) PreviewClaim(ctx context.Context, token string) (string, error) {
	sum := sha256.Sum256([]byte(token))

	var row struct {
		Name      string
		ExpiresAt *time.Time
	}
	err := s.db.WithContext(ctx).
		Raw(`SELECT name, claim_expires_at AS expires_at FROM companies
		     WHERE claim_token_hash = ? AND deleted_at IS NULL`,
			hex.EncodeToString(sum[:])).Scan(&row).Error
	if err != nil {
		return "", fmt.Errorf("preview claim: %w", err)
	}
	if row.Name == "" {
		return "", ErrClaimNotFound
	}
	if row.ExpiresAt == nil || row.ExpiresAt.Before(time.Now()) {
		return "", ErrClaimExpired
	}
	return row.Name, nil
}

// ClaimInput is the account the claimant is creating for themselves.
type ClaimInput struct {
	Token    string
	Email    string
	Phone    string
	Username string
	Password string
	FullName string

	// NPWP is REQUIRED. A placeholder can exist without one — the transporter
	// who created it usually does not know it — but a claimed company is a real
	// business, and the tax number is what says which business it is.
	//
	// It also surfaces duplicates, but only PARTLY, and the limit is worth
	// being explicit about: a duplicate is found by matching this number
	// against companies that already carry one. If BOTH transporters recorded
	// the shipper without a tax number, there is nothing to match against —
	// claiming simply sets the number on this row, and the other row stays
	// invisible until somebody merges it by hand.
	//
	// So this catches the case where at least one transporter knew the number.
	// The rest is what the merge tool exists for.
	NPWP string
}

// ClaimResult reports what happened, including a duplicate found on the way.
type ClaimResult struct {
	CompanyID            uuid.UUID  `json:"companyId"`
	UserID               uuid.UUID  `json:"userId"`
	RoleID               uuid.UUID  `json:"roleId"`
	DuplicateOfCompanyID *uuid.UUID `json:"duplicateOfCompanyId,omitempty"`
}

// Claim turns a placeholder into a working tenant.
//
// The company row does NOT change identity: the same id gains its first user
// and an Administrator role. That is the property the whole design exists for —
// every order and agreement already recorded against this shipper stays linked,
// because nothing moved.
//
// The tax number is required here even though it was optional at creation, and
// this is where a duplicate surfaces. If another company already holds it, the
// two rows are the same business: they are merged, and this row is the one that
// survives, because it is the one with a real person attached.
func (s *ShipperService) Claim(ctx context.Context, in ClaimInput, hash func(string) (string, error)) (*ClaimResult, error) {
	if strings.TrimSpace(in.NPWP) == "" || normaliseTaxID(in.NPWP) == "" {
		return nil, ErrNPWPRequired
	}
	if in.Email == "" && in.Phone == "" && in.Username == "" {
		return nil, fmt.Errorf("%w: one of email, phone or username is required", ErrValidation)
	}
	if len(in.Password) < 8 {
		return nil, fmt.Errorf("%w: the password must be at least 8 characters", ErrValidation)
	}

	passwordHash, err := hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("claim: %w", err)
	}

	sum := sha256.Sum256([]byte(in.Token))
	tokenHash := hex.EncodeToString(sum[:])
	result := &ClaimResult{}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Lock the row: the claim consumes the token, and two people opening
		// the same link at once must not both create an administrator.
		var company models.Company
		err := tx.Raw(`SELECT * FROM companies
		               WHERE claim_token_hash = ? AND deleted_at IS NULL FOR UPDATE`,
			tokenHash).Scan(&company).Error
		if err != nil {
			return fmt.Errorf("claim: %w", err)
		}
		if company.ID == uuid.Nil {
			return ErrClaimNotFound
		}
		if company.ClaimExpiresAt == nil || company.ClaimExpiresAt.Before(time.Now()) {
			return ErrClaimExpired
		}

		// Belt and braces with IssueClaimLink's check: a user may have been
		// created between issuing and claiming.
		var existingUsers int64
		if err := tx.Model(&models.User{}).
			Where("company_id = ? AND deleted_at IS NULL", company.ID).
			Count(&existingUsers).Error; err != nil {
			return fmt.Errorf("claim: %w", err)
		}
		if existingUsers > 0 {
			return ErrAlreadyClaimed
		}

		// Is this business already recorded under another row?
		var other models.Company
		derr := tx.Where("normalise_tax_id(npwp) = ? AND id <> ? AND deleted_at IS NULL",
			normaliseTaxID(in.NPWP), company.ID).First(&other).Error
		switch {
		case derr == nil:
			// A duplicate, found exactly when the design predicted: two
			// transporters each recorded this shipper without a tax number.
			//
			// THIS row survives, not the other one — it is the row the claimant
			// holds a link to, and the one about to have a real person on it.
			// The other is folded in, and its transporter relationships move
			// across so that transporter keeps reaching their customer.
			result.DuplicateOfCompanyID = &other.ID
			if err := s.foldIn(tx, company.ID, other.ID); err != nil {
				return err
			}
		case errors.Is(derr, gorm.ErrRecordNotFound):
			// Nothing to merge.
		default:
			return fmt.Errorf("claim: look for a duplicate: %w", derr)
		}

		// The company becomes real: it keeps its id, gains the tax number, and
		// the link is consumed.
		if err := tx.Exec(`
			UPDATE companies SET
				npwp = ?, claim_token_hash = NULL, claim_expires_at = NULL,
				updated_at = NOW()
			WHERE id = ?
		`, in.NPWP, company.ID).Error; err != nil {
			return fmt.Errorf("claim: record the tax number: %w", err)
		}

		// Its administrator role.
		var roleText string
		if err := tx.Raw(`
			INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
			VALUES (?, 'Administrator',
				'Full access to everything this company is entitled to. Created automatically and cannot be deleted.',
				'{}'::text[], TRUE, TRUE)
			ON CONFLICT (company_id, name) DO UPDATE SET grants_all = TRUE, is_system = TRUE
			RETURNING id::text
		`, company.ID).Scan(&roleText).Error; err != nil {
			return fmt.Errorf("claim: create the administrator role: %w", err)
		}
		roleID, perr := uuid.Parse(roleText)
		if perr != nil {
			return fmt.Errorf("claim: unreadable role id: %w", perr)
		}

		// And its first person, who administers it.
		user := &models.User{
			CompanyID:    &company.ID,
			RoleID:       &roleID,
			PasswordHash: passwordHash,
			Language:     "id",
		}
		if in.Email != "" {
			lower := strings.ToLower(strings.TrimSpace(in.Email))
			user.Email = &lower
		}
		if in.Phone != "" {
			user.Phone = &in.Phone
		}
		if in.Username != "" {
			user.Username = &in.Username
		}
		if in.FullName != "" {
			user.FullName = &in.FullName
		}
		if err := tx.Create(user).Error; err != nil {
			if strings.Contains(err.Error(), "duplicate key") {
				return fmt.Errorf("%w: an account with those details already exists", ErrValidation)
			}
			return fmt.Errorf("claim: create the administrator: %w", err)
		}

		// Entitlement, or the new tenant authenticates and reaches nothing.
		if err := tx.Exec(`
			INSERT INTO company_modules (company_id, product, module, enabled)
			SELECT ?, 'tms', m.module, TRUE
			FROM (VALUES ('order'),('agreement'),('invoice'),('shipment'),('truck'),
				('warehouse'),('customer'),('dashboard'),('notification'),
				('collaboration'),('masterData')) AS m(module)
			ON CONFLICT (company_id, product, module) DO NOTHING
		`, company.ID).Error; err != nil {
			return fmt.Errorf("claim: grant entitlement: %w", err)
		}
		if err := tx.Exec(`
			INSERT INTO company_product_settings (company_id, product, entitlement_mode)
			VALUES (?, 'tms', 'grant') ON CONFLICT (company_id, product) DO NOTHING
		`, company.ID).Error; err != nil {
			return fmt.Errorf("claim: entitlement mode: %w", err)
		}

		result.CompanyID = company.ID
		result.UserID = user.ID
		result.RoleID = roleID
		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = s.audit.Write(ctx, &models.AuditEntry{
		UserID:    &result.UserID,
		Event:     models.AuditClaimCompleted,
		Succeeded: true,
		Detail: models.JSONMap{
			"companyId": result.CompanyID.String(),
		},
	})
	return result, nil
}

// foldIn merges `loser` into `keep`, for the duplicate found during a claim.
//
// Narrower than MergeService.Merge: the loser here is always a placeholder with
// no users, because a company with people in it could not have been recorded
// twice without somebody noticing.
func (s *ShipperService) foldIn(tx *gorm.DB, keepID, loserID uuid.UUID) error {
	var loserUsers int64
	if err := tx.Model(&models.User{}).
		Where("company_id = ? AND deleted_at IS NULL", loserID).
		Count(&loserUsers).Error; err != nil {
		return fmt.Errorf("claim: count the duplicate's users: %w", err)
	}
	if loserUsers > 0 {
		// Two real tenants sharing a tax number is not something to resolve
		// automatically: it would move people between companies.
		return fmt.Errorf("%w: another company with that tax number already has "+
			"users; contact Karlo support to resolve it", ErrValidation)
	}

	if err := tx.Exec(`
		INSERT INTO company_links (transporter_company_id, shipper_company_id, linked_by_user_id)
		SELECT transporter_company_id, ?, linked_by_user_id
		FROM company_links WHERE shipper_company_id = ?
		ON CONFLICT DO NOTHING
	`, keepID, loserID).Error; err != nil {
		return fmt.Errorf("claim: move the duplicate's links: %w", err)
	}
	if err := tx.Exec(`DELETE FROM company_links WHERE shipper_company_id = ?`, loserID).Error; err != nil {
		return fmt.Errorf("claim: clear the duplicate's links: %w", err)
	}

	// Release the tax number before the surviving row takes it, or both hold it
	// for the length of a statement and the unique index refuses.
	if err := tx.Exec(`
		UPDATE companies SET npwp = NULL, nib = NULL,
			merged_into_company_id = ?, merged_at = NOW(),
			deleted_at = NOW(), updated_at = NOW()
		WHERE id = ?
	`, keepID, loserID).Error; err != nil {
		return fmt.Errorf("claim: fold in the duplicate: %w", err)
	}
	return nil
}

// profileFrom is the free-form part of a new customer's record.
func profileFrom(in CreateShipperInput) models.JSONMap {
	out := models.JSONMap{}
	if in.PicName != nil && strings.TrimSpace(*in.PicName) != "" {
		out["picName"] = strings.TrimSpace(*in.PicName)
	}
	if in.IndustrySector != nil && strings.TrimSpace(*in.IndustrySector) != "" {
		out["industrySector"] = strings.TrimSpace(*in.IndustrySector)
	}
	return out
}
