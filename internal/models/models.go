// Package models holds the GORM entities for the authentication database.
//
// These mirror migrations/000001_init.up.sql. The SQL file is the source of
// truth: GORM tags describe the schema, they do not create it.
package models

import (
	"strings"

	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/karlo/authentication-service/internal/platform/abbrev"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Permission is the module -> action -> bool map stored in a JSONB column.
type Permission map[string]map[string]bool

// Value implements driver.Valuer.
func (p Permission) Value() (driver.Value, error) {
	if p == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(p)
}

// Scan implements sql.Scanner.
func (p *Permission) Scan(src interface{}) error {
	if src == nil {
		*p = Permission{}
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("models: cannot scan %T into Permission", src)
	}
	return json.Unmarshal(b, p)
}

// Allows reports whether the map grants module.action.
func (p Permission) Allows(module, action string) bool {
	if p == nil {
		return false
	}
	actions, ok := p[module]
	if !ok {
		return false
	}
	return actions[action]
}

// JSONMap is a generic JSONB column.
type JSONMap map[string]interface{}

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func (m *JSONMap) Scan(src interface{}) error {
	if src == nil {
		*m = JSONMap{}
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("models: cannot scan %T into JSONMap", src)
	}
	return json.Unmarshal(b, m)
}

// JSONList is a JSONB column holding an array of strings.
//
// It exists because JSONMap cannot represent one: a column declared
// `JSONB NOT NULL DEFAULT '[]'` hands every freshly-inserted row an array, and
// scanning that into a map fails. The failure surfaces at login, on the SELECT,
// so a user created with the column left at its default cannot sign in at all.
type JSONList []string

func (l JSONList) Value() (driver.Value, error) {
	if l == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(l)
}

func (l *JSONList) Scan(src interface{}) error {
	if src == nil {
		*l = JSONList{}
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("models: cannot scan %T into JSONList", src)
	}
	return json.Unmarshal(b, l)
}

// CompanySettings are the per-company business toggles.
type CompanySettings struct {
	CancelWithValidate               bool    `json:"cancelWithValidate"`
	FinishWithGeofencing             bool    `json:"finishWithGeofencing"`
	ActiveAgreementVerifiedOnly      bool    `json:"activeAgreementVerifiedOnly"`
	PPNPercentage                    float64 `json:"ppnPercentage"`
	PPH23Percentage                  float64 `json:"pph23Percentage"`
	UseStrictAgreement               bool    `json:"useStrictAgreement"`
	MaxDriverAvailableAfterOrderDone int     `json:"maxDriverAvailableAfterOrderDone"`
	AccessTolls                      bool    `json:"accessTolls"`
}

func (s CompanySettings) Value() (driver.Value, error) { return json.Marshal(s) }

func (s *CompanySettings) Scan(src interface{}) error {
	if src == nil {
		*s = CompanySettings{}
		return nil
	}
	b, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("models: cannot scan %T into CompanySettings", src)
	}
	return json.Unmarshal(b, s)
}

// Company is a tenant.
type Company struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// DerivedFromLegacyUserID is the Mongo id of the USER this company was
	// derived from. There were no companies in the legacy data — each
	// parentless user became one — so naming it legacy_id said what it held
	// but not what it meant. It is also the import's idempotency key.
	DerivedFromLegacyUserID *string `gorm:"column:derived_from_legacy_user_id" json:"derivedFromLegacyUserId,omitempty"`

	Name string `gorm:"not null" json:"name"`

	// Role is which side of the market this company trades on: shipper or
	// transporter. It drives which screens the tenant sees. Unrelated to the
	// per-person roles table — this is a property of the business.
	Role string `gorm:"not null" json:"role"`

	// Abbreviation is the short code that appears in agreement numbers:
	// AGR-<transporter>-<client>-000001. Derived from the name on creation and
	// editable afterwards.
	//
	// NOT unique, deliberately. Two companies can genuinely share three
	// letters, and refusing the second registration for a cosmetic clash would
	// be worse than the clash — uniqueness of the agreement number comes from
	// its sequence, not from these codes.
	Abbreviation *string `gorm:"column:abbreviation" json:"abbreviation,omitempty"`

	// FMSTenantID is fms_app.tenants.id for a company that came from FMS.
	//
	// FMS is bigint-keyed end to end and its row-level security compares
	// every query against this value, so it rides in the access token and
	// FMS sets app.current_tenant from it directly. One primary key here,
	// one recorded alias, nobody translating at runtime. NULL for every
	// company that never was an FMS tenant.
	FMSTenantID *int64 `gorm:"column:fms_tenant_id" json:"fmsTenantId,omitempty"`

	NPWP           *string `gorm:"column:npwp" json:"npwp,omitempty"`
	Address        *string `json:"address,omitempty"`
	CityID         *string `gorm:"column:city_id" json:"cityId,omitempty"`
	ProvinceID     *string `gorm:"column:province_id" json:"provinceId,omitempty"`
	CompanyProfile *string `json:"companyProfile,omitempty"`
	LogoURL        *string `gorm:"column:logo_url" json:"logoUrl,omitempty"`
	BannerURL      *string `gorm:"column:banner_url" json:"bannerUrl,omitempty"`

	Settings        CompanySettings `gorm:"type:jsonb" json:"settings"`
	BankAccount     JSONMap         `gorm:"type:jsonb" json:"bankAccount,omitempty"`
	EmailRecipients StringArray     `gorm:"type:text[]" json:"emailRecipients"`

	IsVerified  bool `gorm:"not null;default:false" json:"isVerified"`
	IsSuspended bool `gorm:"not null;default:false" json:"isSuspended"`

	// Slug is the FMS-facing URL identifier. FMS resolves a tenant by it, so a
	// company migrating from FMS keeps the URLs its users have bookmarked.
	Slug *string `gorm:"column:slug" json:"slug,omitempty"`

	// DefaultMaxDevices is the company-wide session cap, which a user's own
	// MaxDevices overrides. 0 is unlimited.
	DefaultMaxDevices int `gorm:"column:default_max_devices;not null;default:0" json:"defaultMaxDevices"`

	// MaxUsers is how many ACTIVE accounts this company may hold. 0 is
	// unlimited.
	//
	// Soft-deleted accounts do not occupy a seat — removing somebody should
	// free theirs. Suspended accounts DO, because a suspension is temporary and
	// the person is expected back; freeing the seat would let somebody else
	// take it and make their return fail.
	MaxUsers int `gorm:"column:max_users;not null;default:0" json:"maxUsers"`

	// EntityType is whether this shipper is a registered business or an
	// individual. Both are named as the shipper on an order, so both are a
	// companies row; a personal shipper has an NPWP and a bank account but no
	// NIB, which is why NIB cannot be the identity key and NPWP is.
	EntityType string `gorm:"column:entity_type;not null;default:company" json:"entityType"`

	// NIB is the Nomor Induk Berusaha, which replaced SIUP and TDP in 2018.
	// Company-only.
	NIB *string `gorm:"column:nib" json:"nib,omitempty"`

	// MergedIntoCompanyID is set when this row was found to be a duplicate.
	//
	// The row is kept rather than deleted because orders, agreements and
	// invoices live in another service and reference this id — deleting it
	// would break them. A forwarding pointer lets each service resolve an old
	// id and move its own rows in its own time.
	MergedIntoCompanyID *uuid.UUID `gorm:"column:merged_into_company_id" json:"mergedIntoCompanyId,omitempty"`
	MergedAt            *time.Time `gorm:"column:merged_at" json:"mergedAt,omitempty"`

	// CreatedByCompanyID is the transporter that stood this company up on
	// behalf of a shipper with no account.
	//
	// The one fact about a claim that cannot be derived, and the permission
	// check for who may re-issue or revoke the link — without it, any company
	// could issue a claim link for any other.
	CreatedByCompanyID *uuid.UUID `gorm:"type:uuid" json:"createdByCompanyId,omitempty"`

	// ClaimTokenHash is the SHA-256 of the live claim link, or nil.
	//
	// json:"-" because this is a credential, even a hashed one, and companies
	// rows are serialised to API clients. It cannot be reversed into a working
	// link, so a leak grants nobody anything — but there is no reason to send
	// it, so it is never sent.
	//
	// Single-use: cleared when claimed. Re-issuing overwrites, so a company has
	// at most one live link by construction rather than by a constraint that
	// something has to enforce.
	ClaimTokenHash *string `gorm:"column:claim_token_hash" json:"-"`

	ClaimExpiresAt      *time.Time `gorm:"column:claim_expires_at" json:"claimExpiresAt,omitempty"`
	ClaimIssuedByUserID *uuid.UUID `gorm:"column:claim_issued_by_user_id" json:"claimIssuedByUserId,omitempty"`

	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

// BeforeCreate derives the abbreviation when the caller did not supply one.
//
// A hook rather than a line at each creation site. There are two of those today
// — ordinary registration and a transporter standing up a placeholder shipper —
// and a third would silently produce companies with no code, which shows up
// much later as an agreement numbered AGR--ASB-000001.
func (c *Company) BeforeCreate(*gorm.DB) error {
	if c.Abbreviation == nil || strings.TrimSpace(*c.Abbreviation) == "" {
		code := abbrev.FromName(c.Name)
		c.Abbreviation = &code
		return nil
	}
	code := abbrev.Normalise(*c.Abbreviation)
	c.Abbreviation = &code
	return nil
}

func (Company) TableName() string { return "companies" }

// A placeholder company is one with no users.
//
// Deliberately NOT a column. A flag would be a second copy of that fact, and
// the schema allowed it to disagree — is_placeholder could be true on a company
// with three people in it, and nothing prevented it. Ask the question instead:
//
//	SELECT c.* FROM companies c
//	WHERE NOT EXISTS (SELECT 1 FROM users u
//	                  WHERE u.company_id = c.id AND u.deleted_at IS NULL)
//
// and "when was it claimed" is MIN(users.created_at) for that company.

// User is a person who can authenticate.
type User struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	LegacyID  *string    `gorm:"column:legacy_id" json:"legacyId,omitempty"`
	CompanyID *uuid.UUID `gorm:"type:uuid" json:"companyId,omitempty"`

	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
	// PasswordHash carries `json:"-"` so it can never be serialised into a
	// response by accident. The legacy login endpoint returned the whole user
	// document, hash included.
	PasswordHash string  `gorm:"column:password_hash;not null" json:"-"`
	FullName     *string `json:"fullName,omitempty"`

	// IsPlatformStaff marks a Karlo employee, who administers across tenants
	// and bypasses company entitlement in both products.
	//
	// Product-neutral by design: FMS calls this platform_admin and TMS called
	// it superadmin/admin, but a Karlo employee is staff across both products
	// rather than an administrator of one, so it does not belong in a
	// per-product table.
	IsPlatformStaff bool `gorm:"not null;default:false" json:"isPlatformStaff"`

	// FMSUserID is fms_app.users.id for a person who came from FMS. FMS rows
	// that name a person (dashboard layouts, API token authors, report
	// owners) key on it, so it rides in the token next to the tenant alias.
	// NULL for everyone who never had an FMS login.
	FMSUserID *int64 `gorm:"column:fms_user_id" json:"fmsUserId,omitempty"`

	// RoleID is how this person's access is granted. Every account in a company
	// has one; only platform staff, who belong to no company, do not.
	RoleID *uuid.UUID `gorm:"type:uuid" json:"roleId,omitempty"`

	// MaxDevices caps concurrent sessions. 0 defers to the company default,
	// which is itself 0 for unlimited — so nothing is restricted until an
	// administrator decides to restrict it.
	MaxDevices int `gorm:"column:max_devices;not null;default:0" json:"maxDevices"`

	BirthDate *time.Time `gorm:"type:date" json:"birthDate,omitempty"`
	Address   *string    `json:"address,omitempty"`
	CityID    *string    `gorm:"column:city_id" json:"cityId,omitempty"`
	PhotoURL  *string    `gorm:"column:photo_url" json:"photoUrl,omitempty"`
	Language  string     `gorm:"not null;default:id" json:"language"`

	EmergencyContactName  *string  `json:"emergencyContactName,omitempty"`
	EmergencyContactPhone *string  `json:"emergencyContactPhone,omitempty"`
	AlternativePhones     JSONList `gorm:"type:jsonb" json:"alternativePhones,omitempty"`

	IsEmailVerified bool `gorm:"not null;default:false" json:"isEmailVerified"`
	IsPhoneVerified bool `gorm:"not null;default:false" json:"isPhoneVerified"`
	IsVerified      bool `gorm:"not null;default:false" json:"isVerified"`
	IsSuspended     bool `gorm:"not null;default:false" json:"isSuspended"`
	// The column tag is explicit: GORM's default naming would derive
	// "accepted_tn_c_at" from the capital C, which does not exist.
	AcceptedTnCAt *time.Time `gorm:"column:accepted_tnc_at" json:"acceptedTncAt,omitempty"`

	LastLoginAt *time.Time     `json:"lastLoginAt,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`

	Company *Company `gorm:"foreignKey:CompanyID" json:"company,omitempty"`
}

func (User) TableName() string { return "users" }

// IsRootAccount is gone deliberately.
//
// "Root" was a property of the ACCOUNT — one privileged user per company,
// everyone else narrowed. Access is now a property of the ROLE, so the question
// is not whether someone is root but whether their role grants everything:
// Role.GrantsAll. That also allows what root could not — a company with two
// administrators, or none, or an administrator who leaves without stranding the
// company.
//
// Anything that used to ask IsRootAccount() should load the user's role and
// read GrantsAll.

// Session is one issued credential, revocable independently of the others.
type Session struct {
	ID      uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID  uuid.UUID `gorm:"type:uuid;not null" json:"userId"`
	TokenID uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"tokenId"`
	// RefreshTokenHash is SHA-256 hex of the refresh token.
	RefreshTokenHash *string `gorm:"column:refresh_token_hash" json:"-"`

	SingleDevice bool    `gorm:"not null;default:false" json:"singleDevice"`
	DeviceID     *string `gorm:"column:device_id" json:"deviceId,omitempty"`
	Platform     *string `json:"platform,omitempty"`
	UserAgent    *string `gorm:"column:user_agent" json:"-"`
	IPAddress    *string `gorm:"column:ip_address;type:inet" json:"-"`

	ExpiresAt  time.Time  `gorm:"not null" json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt time.Time  `json:"lastUsedAt"`
}

func (Session) TableName() string { return "sessions" }

// IsActive reports whether the session may still authorise a request.
func (s *Session) IsActive() bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(time.Now())
}

// DeviceToken is one device's push registration.
type DeviceToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null" json:"userId"`
	PushToken string     `gorm:"column:push_token;not null" json:"pushToken"`
	Platform  *string    `json:"platform,omitempty"`
	DeviceID  *string    `gorm:"column:device_id" json:"deviceId,omitempty"`
	IsActive  bool       `gorm:"not null;default:true" json:"isActive"`
	FailedAt  *time.Time `json:"failedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

func (DeviceToken) TableName() string { return "device_tokens" }

// APIKey replaces the hardcoded static tokens from the monolith.
type APIKey struct {
	ID   uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	Name string    `gorm:"not null" json:"name"`
	// KeyHash is SHA-256 hex. The plaintext key is returned once, at creation.
	KeyHash   string      `gorm:"column:key_hash;not null;uniqueIndex" json:"-"`
	KeyPrefix string      `gorm:"column:key_prefix;not null" json:"keyPrefix"`
	UserID    *uuid.UUID  `gorm:"type:uuid" json:"userId,omitempty"`
	CompanyID *uuid.UUID  `gorm:"type:uuid" json:"companyId,omitempty"`
	Scopes    StringArray `gorm:"type:text[]" json:"scopes"`

	IsActive   bool       `gorm:"not null;default:true" json:"isActive"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

func (APIKey) TableName() string { return "api_keys" }

// IsUsable reports whether the key may authenticate a request right now.
func (k *APIKey) IsUsable() bool {
	if !k.IsActive || k.RevokedAt != nil {
		return false
	}
	return k.ExpiresAt == nil || k.ExpiresAt.After(time.Now())
}

// UserDocument is one uploaded identity or company document.
type UserDocument struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID    *uuid.UUID `gorm:"type:uuid" json:"userId,omitempty"`
	CompanyID *uuid.UUID `gorm:"type:uuid" json:"companyId,omitempty"`

	DocType         string     `gorm:"column:doc_type;not null" json:"docType"`
	DocNumber       *string    `gorm:"column:doc_number" json:"docNumber,omitempty"`
	FileURL         *string    `gorm:"column:file_url" json:"fileUrl,omitempty"`
	Status          string     `gorm:"not null;default:pending" json:"status"`
	RejectionReason *string    `json:"rejectionReason,omitempty"`
	VerifiedBy      *uuid.UUID `gorm:"type:uuid" json:"verifiedBy,omitempty"`
	VerifiedAt      *time.Time `json:"verifiedAt,omitempty"`
	ExpiresAt       *time.Time `gorm:"type:date" json:"expiresAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (UserDocument) TableName() string { return "user_documents" }

// Document statuses.
const (
	DocStatusPending  = "pending"
	DocStatusVerified = "verified"
	DocStatusRejected = "rejected"
)

// CollaborationInvite is gone. Inviting somebody to a company is now the claim
// flow — see company_claim_tokens — which does the same thing safely: the token
// is hashed, single-use and expiring, where this table stored a plain value
// that never expired.

// Invite statuses.
const (
	InviteStatusPending  = "pending"
	InviteStatusAccepted = "accepted"
	InviteStatusRejected = "rejected"
	InviteStatusExpired  = "expired"
	InviteStatusRevoked  = "revoked"
)

// AuditEntry records an authentication-relevant event.
type AuditEntry struct {
	ID          int64      `gorm:"primaryKey" json:"id"`
	UserID      *uuid.UUID `gorm:"type:uuid" json:"userId,omitempty"`
	ActorUserID *uuid.UUID `gorm:"type:uuid" json:"actorUserId,omitempty"`
	Event       string     `gorm:"not null" json:"event"`
	Succeeded   bool       `gorm:"not null;default:true" json:"succeeded"`
	IPAddress   *string    `gorm:"column:ip_address;type:inet" json:"ipAddress,omitempty"`
	UserAgent   *string    `gorm:"column:user_agent" json:"-"`
	Detail      JSONMap    `gorm:"type:jsonb" json:"detail,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func (AuditEntry) TableName() string { return "auth_audit_log" }

// Audit event names.
const (
	AuditLoginSuccess     = "login.success"
	AuditLoginFailure     = "login.failure"
	AuditLogout           = "logout"
	AuditPasswordChanged  = "password.changed"
	AuditPasswordReset    = "password.reset"
	AuditUserSuspended    = "user.suspended"
	AuditUserUnsuspended  = "user.unsuspended"
	AuditUserDeleted      = "user.deleted"
	AuditPermissionChange = "permission.changed"
	AuditAPIKeyCreated    = "apikey.created"
	AuditAPIKeyRevoked    = "apikey.revoked"
	AuditSessionRevoked   = "session.revoked"
	AuditCompanyMerged    = "company.merged"
	AuditClaimIssued      = "claim.issued"
	AuditClaimCompleted   = "claim.completed"
)

// StringArray maps a Postgres text[] column.
type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return "{}", nil
	}
	out := "{"
	for i, s := range a {
		if i > 0 {
			out += ","
		}
		out += `"` + escapeArrayElem(s) + `"`
	}
	return out + "}", nil
}

func (a *StringArray) Scan(src interface{}) error {
	if src == nil {
		*a = nil
		return nil
	}
	var s string
	switch v := src.(type) {
	case []byte:
		s = string(v)
	case string:
		s = v
	default:
		return fmt.Errorf("models: cannot scan %T into StringArray", src)
	}
	parsed, err := parsePGArray(s)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

func escapeArrayElem(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '"' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}

// parsePGArray decodes the Postgres array literal form, handling quoted
// elements and backslash escapes.
func parsePGArray(s string) ([]string, error) {
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, errors.New("models: malformed postgres array")
	}
	body := s[1 : len(s)-1]
	if body == "" {
		return []string{}, nil
	}

	var (
		out     []string
		cur     []rune
		inQuote bool
		escaped bool
	)
	for _, r := range body {
		switch {
		case escaped:
			cur = append(cur, r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case r == ',' && !inQuote:
			out = append(out, string(cur))
			cur = cur[:0]
		default:
			cur = append(cur, r)
		}
	}
	return append(out, string(cur)), nil
}

// CompanyModule is one company's entitlement to one module.
//
// This is the first of the two tiers governing access. It answers "may this
// company use accounting at all", independently of what any individual user's
// permission map says. See platform/authctx for how the two combine.
type CompanyModule struct {
	CompanyID uuid.UUID `gorm:"type:uuid;primaryKey" json:"companyId"`

	// Product is part of the key. Both products have modules called dashboard,
	// notifications and reports meaning different things, so an entitlement
	// that did not name its product would grant the wrong one.
	Product string `gorm:"primaryKey" json:"product"`

	Module string `gorm:"primaryKey" json:"module"`

	// Enabled false is not the same as an absent row: it records that the
	// company once held the module, which matters when reinstating it and when
	// answering a support ticket about access that used to work.
	Enabled bool `gorm:"not null;default:true" json:"enabled"`

	ValidFrom  *time.Time `gorm:"type:date" json:"validFrom,omitempty"`
	ValidUntil *time.Time `gorm:"type:date" json:"validUntil,omitempty"`

	// Limits holds per-module quotas: seats, monthly volume, and so on.
	Limits JSONMap `gorm:"type:jsonb" json:"limits,omitempty"`

	GrantedByUserID *uuid.UUID `gorm:"type:uuid" json:"grantedByUserId,omitempty"`
	Note            *string    `json:"note,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (CompanyModule) TableName() string { return "company_modules" }

// IsActive reports whether the entitlement is in force at the given moment.
//
// Three things can put it out of force: being disabled, not having started, or
// having expired. A trial that ended yesterday is a row that still exists and
// still says which module it was for, but it grants nothing today.
func (m *CompanyModule) IsActive(at time.Time) bool {
	if !m.Enabled {
		return false
	}
	if m.ValidFrom != nil && at.Before(*m.ValidFrom) {
		return false
	}
	if m.ValidUntil != nil {
		// Dates are inclusive: an entitlement valid until the 31st still works
		// on the 31st.
		endOfDay := m.ValidUntil.Add(24*time.Hour - time.Nanosecond)
		if at.After(endOfDay) {
			return false
		}
	}
	return true
}

// CompanyModuleEvent records a change to an entitlement.
//
// Entitlement changes are commercial events: they decide what a customer can do
// and, indirectly, what they are billed. They are recorded rather than inferred
// from the current state.
type CompanyModuleEvent struct {
	ID          int64      `gorm:"primaryKey" json:"id"`
	CompanyID   uuid.UUID  `gorm:"type:uuid;not null" json:"companyId"`
	Product     string     `gorm:"not null" json:"product"`
	Module      string     `gorm:"not null" json:"module"`
	Action      string     `gorm:"not null" json:"action"`
	ActorUserID *uuid.UUID `gorm:"type:uuid" json:"actorUserId,omitempty"`
	Detail      JSONMap    `gorm:"type:jsonb" json:"detail,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func (CompanyModuleEvent) TableName() string { return "company_module_history" }

// Entitlement change actions.
const (
	ModuleGranted = "granted"
	ModuleRevoked = "revoked"
	ModuleUpdated = "updated"
)

// ProductAccess holds the extra permissions granted to ONE person, on top of
// their role.
//
// The role says what a job does; this says what an individual may do beyond it
// — the dispatcher who also reconciles invoices. Without it an administrator
// must either widen a whole role for one person or invent a role for one
// person, and both defeat the purpose of roles.
//
// Additive ONLY. Effective access is the role UNION these. A grant that could
// also subtract would mean reading two places to know what somebody can do, and
// a role change would silently do nothing for anyone carrying a subtraction.
type ProductAccess struct {
	UserID uuid.UUID `gorm:"type:uuid;primaryKey" json:"userId"`

	// Product qualifies the keys below, which are therefore stored
	// UNQUALIFIED — "order.read", not "tms:order.read". Roles are the other
	// way round because they span products and have no such column.
	Product string `gorm:"primaryKey" json:"product"`

	Permissions StringArray `gorm:"type:text[];not null;default:'{}'" json:"permissions"`

	// Disabling keeps the row, so a temporary withdrawal does not erase the
	// fact that the grant was ever made.
	Enabled bool `gorm:"not null;default:true" json:"enabled"`

	GrantedByUserID *uuid.UUID `gorm:"type:uuid" json:"grantedByUserId,omitempty"`
	Note            *string    `json:"note,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (ProductAccess) TableName() string { return "user_product_access" }

// ---------------------------------------------------------------------------
// Shared IAM: the concepts FMS needs and TMS did not have
// ---------------------------------------------------------------------------

// Role is a named set of permissions a company defines and assigns to people.
//
// This is how access is granted. A company describes its own structure —
// Dispatch, Finance, Yard Supervisor — rather than choosing from job titles the
// platform invented, and changing what a team may do is one edit instead of one
// per person.
//
// A role spans products. A person does one job, and that job does not stop at
// a product boundary: the same dispatcher plans loads in TMS and watches
// vehicles in FMS.
type Role struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	CompanyID uuid.UUID `gorm:"type:uuid;not null" json:"companyId"`

	Name        string  `gorm:"not null" json:"name"`
	Description *string `json:"description,omitempty"`

	// Permissions are PRODUCT-QUALIFIED catalogue keys: "tms:order.read",
	// "fms:live.view".
	//
	// Qualified because a role has no product column to disambiguate them. No
	// key collides between the two catalogues today, but `dashboard` is already
	// a subject in both, so an unqualified key is one FMS release away from
	// resolving to whichever catalogue happened to be consulted first.
	Permissions StringArray `gorm:"type:text[];not null;default:'{}'" json:"permissions"`

	// GrantsAll marks the administrator role: everything the company is
	// entitled to, without listing it.
	//
	// Listing it instead would go stale the day the company buys another
	// module — the administrator would silently not have it, which is the
	// opposite of what an administrator means. Permissions is ignored when
	// this is set.
	GrantsAll bool `gorm:"column:grants_all;not null;default:false" json:"grantsAll"`

	// IsSystem marks a role the platform created and a company may not delete.
	// Every company needs at least one role that can administer it; allowing
	// that one to be removed is how a company locks itself out.
	IsSystem bool `gorm:"column:is_system;not null;default:false" json:"isSystem"`

	CreatedByUserID *uuid.UUID `gorm:"type:uuid" json:"createdByUserId,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
}

func (Role) TableName() string { return "roles" }

// Entitlement modes: how to read the ABSENCE of a company_modules row.
const (
	// EntitlementGrant is opt-in. A module is held only when an enabled row
	// says so. What TMS has always done, and the safer reading: a company
	// cannot reach something nobody decided to sell them.
	EntitlementGrant = "grant"

	// EntitlementRevoke is opt-out. A module is held UNLESS a row disables it.
	// What FMS does today. An FMS tenant migrates as this and keeps working;
	// flipping it to grant without backfilling would take the tenant dark.
	EntitlementRevoke = "revoke"
)

// CompanyProductSettings records which of those two readings applies to one
// company in one product.
//
// It exists because TMS and FMS disagree about what an absent entitlement row
// means, and they fail in OPPOSITE directions — TMS closed, FMS open. Holding
// the answer as data rather than as an assumption in code is what makes the
// eventual convergence survivable: tenants move one at a time, each move is
// reversible, and a mistake affects one customer rather than all of them.
type CompanyProductSettings struct {
	CompanyID uuid.UUID `gorm:"type:uuid;primaryKey" json:"companyId"`
	Product   string    `gorm:"primaryKey" json:"product"`

	EntitlementMode string `gorm:"column:entitlement_mode;not null;default:grant" json:"entitlementMode"`

	// Set when a tenant is moved from opt-out to opt-in, so the convergence can
	// be audited: who moved, when, and who is left.
	ConvertedAt       *time.Time `json:"convertedAt,omitempty"`
	ConvertedByUserID *uuid.UUID `gorm:"type:uuid" json:"convertedByUserId,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (CompanyProductSettings) TableName() string { return "company_product_settings" }

// Session revocation reasons, recorded so a support question about an ended
// session has an answer beyond "it was revoked".
const (
	RevokedByLogout         = "logout"
	RevokedByRotation       = "rotated"
	RevokedByReuse          = "reuse_detected"
	RevokedByPasswordChange = "password_change"
	RevokedByAccessChange   = "access_change"
	RevokedBySuspension     = "suspended"
)
