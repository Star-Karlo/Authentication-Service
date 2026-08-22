// Package models holds the GORM entities for the authentication database.
//
// These mirror migrations/000001_init.up.sql. The SQL file is the source of
// truth: GORM tags describe the schema, they do not create it.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
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
	ID       uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	LegacyID *string   `gorm:"column:legacy_id" json:"legacyId,omitempty"`

	Name           string  `gorm:"not null" json:"name"`
	Role           string  `gorm:"not null" json:"role"`
	NPWP           *string `gorm:"column:npwp" json:"npwp,omitempty"`
	NoSIUP         *string `gorm:"column:no_siup" json:"noSiup,omitempty"`
	NoTDP          *string `gorm:"column:no_tdp" json:"noTdp,omitempty"`
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

	// FMSTenantID is this company's FMS-facing alias.
	//
	// FMS identifies a tenant by a bigint and its row-level security compares
	// against it on every query across live customer data. Recording the alias
	// here means neither product translates at runtime: the token carries both,
	// FMS reads this, TMS reads the UUID. One concept, one primary key, one
	// recorded alias for a system that predates the shared IAM — the same shape
	// as the legacy_id columns carried for the Mongo migration.
	//
	// Nil for a company that has never used FMS.
	FMSTenantID *int64 `gorm:"column:fms_tenant_id;uniqueIndex" json:"fmsTenantId,omitempty"`

	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

func (Company) TableName() string { return "companies" }

// User is a person who can authenticate.
type User struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	LegacyID  *string    `gorm:"column:legacy_id" json:"legacyId,omitempty"`
	CompanyID *uuid.UUID `gorm:"type:uuid" json:"companyId,omitempty"`
	ParentID  *uuid.UUID `gorm:"type:uuid" json:"parentId,omitempty"`

	Username *string `json:"username,omitempty"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
	// PasswordHash carries `json:"-"` so it can never be serialised into a
	// response by accident. The legacy login endpoint returned the whole user
	// document, hash included.
	PasswordHash string  `gorm:"column:password_hash;not null" json:"-"`
	FullName     *string `json:"fullName,omitempty"`

	// Role and Permission are DEPRECATED, superseded by user_product_access.
	// They are retained so a deploy that has to be reverted still finds the
	// data; the application no longer reads them.
	Role       string     `gorm:"not null" json:"-"`
	Permission Permission `gorm:"type:jsonb" json:"-"`

	// IsPlatformStaff marks a Karlo employee, who administers across tenants
	// and bypasses company entitlement in both products.
	//
	// Product-neutral by design: FMS calls this platform_admin and TMS called
	// it superadmin/admin, but a Karlo employee is staff across both products
	// rather than an administrator of one, so it does not belong in a
	// per-product table.
	IsPlatformStaff bool `gorm:"not null;default:false" json:"isPlatformStaff"`

	AccountType string `gorm:"not null;default:subAccount" json:"accountType"`

	BirthDate *time.Time `gorm:"type:date" json:"birthDate,omitempty"`
	Address   *string    `json:"address,omitempty"`
	CityID    *string    `gorm:"column:city_id" json:"cityId,omitempty"`
	PhotoURL  *string    `gorm:"column:photo_url" json:"photoUrl,omitempty"`
	Language  string     `gorm:"not null;default:id" json:"language"`

	EmergencyContactName  *string `json:"emergencyContactName,omitempty"`
	EmergencyContactPhone *string `json:"emergencyContactPhone,omitempty"`
	AlternativePhones     JSONMap `gorm:"type:jsonb" json:"alternativePhones,omitempty"`

	IsEmailVerified bool `gorm:"not null;default:false" json:"isEmailVerified"`
	IsPhoneVerified bool `gorm:"not null;default:false" json:"isPhoneVerified"`
	IsVerified      bool `gorm:"not null;default:false" json:"isVerified"`
	IsSuspended     bool `gorm:"not null;default:false" json:"isSuspended"`
	// The column tag is explicit: GORM's default naming would derive
	// "accepted_tn_c_at" from the capital C, which does not exist.
	AcceptedTnCAt *time.Time `gorm:"column:accepted_tnc_at" json:"acceptedTncAt,omitempty"`

	AverageRating *float64 `gorm:"type:numeric(3,2)" json:"averageRating,omitempty"`
	RatingCount   int      `gorm:"not null;default:0" json:"ratingCount"`

	LastLoginAt *time.Time     `json:"lastLoginAt,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`

	Company *Company `gorm:"foreignKey:CompanyID" json:"company,omitempty"`
}

func (User) TableName() string { return "users" }

// IsRootAccount reports whether the user is a company root account. Root
// accounts bypass module permission checks, matching legacy behaviour.
func (u *User) IsRootAccount() bool { return u.ParentID == nil }

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

// CollaborationInvite invites a company or person into a collaboration.
type CollaborationInvite struct {
	ID               uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	InviterUserID    uuid.UUID  `gorm:"type:uuid;not null" json:"inviterUserId"`
	InviterCompanyID uuid.UUID  `gorm:"type:uuid;not null" json:"inviterCompanyId"`
	InviteeCompanyID *uuid.UUID `gorm:"type:uuid" json:"inviteeCompanyId,omitempty"`
	InviteeEmail     *string    `json:"inviteeEmail,omitempty"`
	InviteePhone     *string    `json:"inviteePhone,omitempty"`

	Role       string     `gorm:"not null" json:"role"`
	Permission Permission `gorm:"type:jsonb" json:"permission"`
	TokenHash  *string    `gorm:"column:token_hash" json:"-"`

	Status      string     `gorm:"not null;default:pending" json:"status"`
	ExpiresAt   time.Time  `gorm:"not null" json:"expiresAt"`
	RespondedAt *time.Time `json:"respondedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func (CollaborationInvite) TableName() string { return "collaboration_invites" }

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
	Module    string    `gorm:"primaryKey" json:"module"`

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

// ProductAccess is one person's access to one product.
//
// Role and permissions live here rather than on the user because the two
// products share no vocabulary: TMS roles are job personas (shipper, driver),
// FMS roles are privilege tiers (operator, manager, admin). A single column
// would mean every consumer interpreting a value it cannot validate.
//
// No row means no access to that product, which is the common case — a TMS
// driver has a tms row and no fms row.
type ProductAccess struct {
	UserID  uuid.UUID `gorm:"type:uuid;primaryKey" json:"userId"`
	Product string    `gorm:"primaryKey" json:"product"`

	Role string `gorm:"not null" json:"role"`

	// Permissions are granted keys from the product's catalogue, flat rather
	// than nested. This is the shape FMS already uses in production, and the
	// nested form carried no information this does not.
	Permissions StringArray `gorm:"type:text[]" json:"permissions"`

	Enabled         bool       `gorm:"not null;default:true" json:"enabled"`
	GrantedByUserID *uuid.UUID `gorm:"type:uuid" json:"grantedByUserId,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (ProductAccess) TableName() string { return "user_product_access" }
