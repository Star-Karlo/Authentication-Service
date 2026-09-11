package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// plan is what the import will write, decided entirely before anything is
// written. Building it first is what makes the dry run meaningful: the report
// below describes exactly the work that -confirm would do, rather than an
// estimate of it.
type plan struct {
	companies []companyRow
	users     []userRow
	access    []accessRow

	// Anything that could not be mapped cleanly. These are reported rather
	// than silently dropped — a row that vanishes without comment is how a
	// customer discovers their account is missing.
	warnings map[string]int
	skipped  []string
}

type companyRow struct {
	ID       uuid.UUID
	LegacyID string
	Name     string
	Role     string
	NPWP     *string
	Address  *string
	CityID   *string
	Profile  *string
	Settings []byte
	Bank     []byte
	Verified bool
	Deleted  *time.Time
	Created  time.Time
}

type userRow struct {
	ID       uuid.UUID
	LegacyID string
	// CompanyLegacy is the legacy id of the company this account belongs to.
	// Kept alongside CompanyID because the UUID is only correct on a first
	// run; the legacy id is stable across every run.
	CompanyLegacy string
	CompanyID     *uuid.UUID
	ParentLegacy  string
	Username      *string
	Email         *string
	Phone         *string
	PasswordHash  string
	FullName      *string
	Role          string
	// IsAdmin marks the account that becomes its company's administrator: the
	// legacy root, the one with no parent.
	IsAdmin     bool
	Address     *string
	CityID      *string
	PhotoURL    *string
	Language    string
	AltPhones   []byte
	EmailOK     bool
	PhoneOK     bool
	Verified    bool
	Suspended   bool
	PlatformOK  bool
	Rating      *float64
	RatingCount int
	Deleted     *time.Time
	Created     time.Time
	Updated     time.Time
}

type accessRow struct {
	UserLegacy  string
	Role        string
	Permissions []string
}

func build(rows []row) (*plan, error) {
	p := &plan{warnings: map[string]int{}}

	// Pass 1: who is a company.
	//
	// A user with no parent is the top of a tenant, so their record becomes a
	// company AND their own account. `type` is not used for this: the export
	// has 11,578 rows typed `mainAccount` that DO have a parent, because the
	// field was reused as a job title.
	companyOf := map[string]uuid.UUID{}
	byLegacy := map[string]row{}
	for _, r := range rows {
		byLegacy[r.get("_id")] = r
	}

	for _, r := range rows {
		if r.get("parent") != "" {
			continue
		}
		id := uuid.New()
		companyOf[r.get("_id")] = id
		p.companies = append(p.companies, buildCompany(id, r))
	}

	// Pass 2: which company each account belongs to, by walking up to the root.
	//
	// Walking rather than reading `parent` once, because the export contains
	// chains: a warehouse PIC under a manager under a shipper. Only the top of
	// the chain has a company row.
	rootOf := map[string]string{}
	for _, r := range rows {
		id := r.get("_id")
		seen := map[string]bool{}
		cur := id
		for {
			if seen[cur] {
				// A cycle. Data corruption rather than a real hierarchy;
				// treated as its own root so the account still imports.
				p.warnings["parent chain is circular"]++
				break
			}
			seen[cur] = true
			parent := byLegacy[cur].get("parent")
			if parent == "" {
				break
			}
			if _, ok := byLegacy[parent]; !ok {
				// Two rows point at a parent that is not in the export.
				p.warnings["parent id missing from the export"]++
				break
			}
			cur = parent
		}
		rootOf[id] = cur
	}

	// Pass 3: resolve duplicate identifiers before building the user rows.
	keepEmail := resolveDuplicates(rows, "email", p, false)
	keepUsername := resolveDuplicates(rows, "username", p, false)
	keepPhone := resolveDuplicates(rows, "phone", p, true)

	for _, r := range rows {
		id := r.get("_id")

		role, staff := canonicalRole(r.get("role"))
		if role == "" {
			p.warnings["no usable role, imported as shipper"]++
			role = "shipper"
		}

		u := userRow{
			ID:           uuid.New(),
			LegacyID:     id,
			ParentLegacy: r.get("parent"),
			PasswordHash: r.get("password"),
			Role:         role,
			Language:     languageOf(r.get("lang")),
			PlatformOK:   staff,
			EmailOK:      r.boolean("isEmailVerified"),
			PhoneOK:      r.boolean("isPhoneVerified"),
			Verified:     r.boolean("isVerified"),
			Suspended:    r.boolean("isSuspend"),
			RatingCount:  intOf(r.get("ratingSummary.totalReviews")),
			Rating:       r.number("ratingSummary.average"),
			AltPhones:    alternativePhones(r),
		}
		u.IsAdmin = r.get("parent") == ""
		if cid, ok := companyOf[rootOf[id]]; ok {
			u.CompanyID = &cid
			u.CompanyLegacy = rootOf[id]
		}

		// Identifiers, cleared where another account won them.
		if v := r.get("email"); v != "" && keepEmail[id] {
			lower := strings.ToLower(v)
			u.Email = &lower
		}
		if v := r.get("username"); v != "" && keepUsername[id] {
			u.Username = &v
		}
		if v := r.get("phone"); v != "" && keepPhone[id] {
			u.Phone = clampOptional(v, 32)
		}

		u.FullName = clampOptional(r.get("fullName"), 255)
		u.Address = optional(r.get("address"))
		u.CityID = clampOptional(r.get("city"), 64)
		u.PhotoURL = optional(r.get("fotoProfile"))

		if r.boolean("deleted") {
			t := r.time("updatedAt")
			if t == nil {
				now := time.Now().UTC()
				t = &now
			}
			u.Deleted = t
		}
		u.Created = orNow(r.time("createdAt"))
		u.Updated = orNow(r.time("updatedAt"))

		p.users = append(p.users, u)

		// Permissions become a ROLE. An administrator is granted none
		// deliberately: grants_all covers everything the company holds, and
		// listing keys alongside it would imply a limit that does not exist.
		perms := []string{}
		if !u.IsAdmin {
			perms = legacyKeysOf(r)
		}
		p.access = append(p.access, accessRow{
			UserLegacy:  id,
			Role:        role,
			Permissions: perms,
		})
	}

	return p, nil
}

// resolveDuplicates decides which account keeps a shared identifier.
//
// The oldest wins. That is not arbitrary: the earliest account is the one most
// likely to have been used, and the later ones are usually a person signing up
// again after forgetting. The losers have the field cleared rather than being
// dropped — the unique indexes ignore NULL, so the accounts still import and
// can still sign in by whichever identifier they kept.
//
// dropPlaceholders additionally clears values that were entered to satisfy a
// required field: 08123456789 appears on 390 accounts and is nobody's number.
func resolveDuplicates(rows []row, column string, p *plan, dropPlaceholders bool) map[string]bool {
	type entry struct {
		id      string
		created time.Time
	}
	groups := map[string][]entry{}

	for _, r := range rows {
		v := strings.ToLower(r.get(column))
		if v == "" {
			continue
		}
		if dropPlaceholders && placeholderPhones[v] {
			continue
		}
		groups[v] = append(groups[v], entry{r.get("_id"), orNow(r.time("createdAt"))})
	}

	keep := map[string]bool{}
	for value, list := range groups {
		sort.Slice(list, func(i, j int) bool { return list[i].created.Before(list[j].created) })
		keep[list[0].id] = true
		if len(list) > 1 {
			p.warnings[fmt.Sprintf("%s shared by several accounts; kept the oldest", column)] += len(list) - 1
			_ = value
		}
	}
	return keep
}

func buildCompany(id uuid.UUID, r row) companyRow {
	c := companyRow{
		ID:       id,
		LegacyID: r.get("_id"),
		// NOT companyProfile. That field holds a free-text description — in the
		// real export, several are multi-paragraph marketing copy — and using
		// it as the name overflows a varchar(255) and is wrong even when it
		// fits. The person's own name is what the legacy UI displayed as the
		// company, so that is what the company is called.
		Name: clamp(firstNonEmpty(r.get("fullName"), r.get("username"), r.get("_id")), 255),
		Role: companyRoleOf(r.get("role")),
		// companies.npwp is varchar(32), narrower than most identifier columns —
		// which is exactly how the wrong width gets copied in from a neighbour.
		NPWP:     clampOptional(r.get("noNpwp"), 32),
		Address:  optional(r.get("address")),
		CityID:   clampOptional(r.get("city"), 64),
		Profile:  optional(r.get("companyProfile")),
		Verified: r.boolean("verifiedProfile"),
		Created:  orNow(r.time("createdAt")),
	}
	if r.boolean("deleted") {
		// Falling back rather than leaving nil: an unparseable timestamp must
		// not resurrect a deleted company as a live tenant.
		t := r.time("updatedAt")
		if t == nil {
			now := time.Now().UTC()
			t = &now
		}
		c.Deleted = t
	}

	// The commercial settings lived on the user document and belong to the
	// company: tax percentages decide what a customer is charged.
	// Every key the column default declares, plus the two the legacy data
	// carries that it does not.
	//
	// Writing a PARTIAL object would be silently wrong: an explicit value
	// replaces the default outright rather than merging with it, so a key
	// omitted here is simply absent — and an absent tax percentage reads as
	// zero. Getting that wrong on 6,156 companies is a billing fault, not a
	// display one, so the defaults are stated rather than inherited.
	c.Settings = jsonOf(map[string]interface{}{
		"cancelWithValidate":          r.boolean("setting.isCancelWithValidate"),
		"finishWithGeofencing":        r.boolean("setting.isFinishWithGeofencing"),
		"activeAgreementVerifiedOnly": r.boolean("setting.activeAgreementVerifiedOnly"),
		"useStrictAgreement":          r.boolean("useStrictAgreement"),
		"accessTolls":                 false,
		// The legacy defaults, used when the export leaves the field blank.
		// PPN 2% and PPh23 11% are the rates the system shipped with; a blank
		// column means "never changed", not "zero tax".
		"ppnPercentage":                    floatOr(r.get("setting.ppnPercentage"), 0.02),
		"pph23Percentage":                  floatOr(r.get("setting.pph23Percentage"), 0.11),
		"maxDriverAvailableAfterOrderDone": 0,
		// Carried from the legacy data although the default does not declare
		// them, because the values are real and dropping them would change how
		// those companies behave.
		"orderUnloadingVerifyPic": r.boolean("setting.orderUnloadingVerifyPic"),
		"detectLocationRadius":    floatOr(r.get("setting.detectLocationRadius"), 0),
	})

	name := firstNonEmpty(r.get("bankAccount.name"), r.get("bankAccount:.name"))
	if name != "" {
		c.Bank = jsonOf(map[string]interface{}{
			"name":     name,
			"number":   firstNonEmpty(r.get("bankAccount.number"), r.get("bankAccount:.number")),
			"behalfOf": firstNonEmpty(r.get("bankAccount.behalfOf"), r.get("bankAccount:.behalfOf")),
		})
	}
	return c
}

// companyRoleOf reduces a person's role to the side of the market the company
// trades on. companies.role is NOT NULL and drives which screens the tenant
// sees, so a driver's company is a transporter.
func companyRoleOf(raw string) string {
	role, _ := canonicalRole(raw)
	switch role {
	case "transporter", "driver":
		return "transporter"
	case "shipper", "warehousePic", "manager":
		return "shipper"
	case "":
		return "shipper"
	}
	return role
}

func legacyKeysOf(r row) []string {
	seen := map[string]bool{}
	out := []string{}
	for column, key := range legacyPermissions {
		if r.boolean(column) && !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func alternativePhones(r row) []byte {
	var list []string
	for _, key := range []string{"alternativePhone[0].phoneNumber", "alternativePhone[1].phoneNumber"} {
		if v := r.get(key); v != "" {
			list = append(list, v)
		}
	}
	if list == nil {
		list = []string{}
	}
	return jsonOf(list)
}

func languageOf(v string) string {
	switch strings.ToLower(v) {
	case "en":
		return "en"
	default:
		return "id"
	}
}

// clamp truncates to a column's width.
//
// Applied to every varchar-bound field rather than trusted: the legacy schema
// had no length limits, so any of them can exceed what this one declares, and
// the failure arrives as an abort partway through the import rather than as a
// validation error.
func clamp(v string, max int) string {
	if len(v) <= max {
		return v
	}
	return strings.TrimSpace(v[:max])
}

func clampOptional(v string, max int) *string {
	if v == "" {
		return nil
	}
	c := clamp(v, max)
	return &c
}

func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func orNow(t *time.Time) time.Time {
	if t == nil {
		return time.Now().UTC()
	}
	return *t
}

func intOf(v string) int {
	f := floatOr(v, 0)
	return int(f)
}

func floatOr(v string, def float64) float64 {
	if v == "" {
		return def
	}
	var f float64
	if _, err := fmt.Sscanf(v, "%g", &f); err != nil {
		return def
	}
	return f
}

func (p *plan) report() {
	fmt.Printf("companies to write : %d\n", len(p.companies))
	fmt.Printf("users to write     : %d\n", len(p.users))
	fmt.Printf("access rows        : %d\n", len(p.access))

	roles := map[string]int{}
	staff := 0
	for _, u := range p.users {
		roles[u.Role]++
		if u.PlatformOK {
			staff++
		}
	}
	fmt.Printf("platform staff     : %d\n\nroles:\n", staff)
	for _, r := range sortedKeys(roles) {
		fmt.Printf("   %-14s %d\n", r, roles[r])
	}

	if len(p.warnings) > 0 {
		fmt.Println("\nwarnings — these rows still import, but not unchanged:")
		for _, w := range sortedKeys(p.warnings) {
			fmt.Printf("   %-52s %d\n", w, p.warnings[w])
		}
	}
	if len(p.skipped) > 0 {
		fmt.Printf("\nSKIPPED %d rows:\n", len(p.skipped))
		for _, s := range p.skipped {
			fmt.Println("   " + s)
		}
	}
}

// apply writes the plan in one transaction.
//
// One transaction for 25,000 accounts is deliberate. A partial import is worse
// than none: it leaves companies without their people and people without their
// company, and there is no way to tell from the data which half ran.
func (p *plan) apply(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		fmt.Printf("\nwriting %d companies...\n", len(p.companies))

		// The id a row ENDS UP with, which is not always the one proposed.
		//
		// On a re-run the conflict target already exists and keeps its original
		// id, while the plan carries a freshly generated one. Using the
		// proposed id for the users would then point them at a company that was
		// never inserted — the foreign key catches it, but only after the first
		// 25,000 rows have been attempted. RETURNING gives the real id either
		// way, which is what makes a second run an update rather than a
		// failure.
		companyID := make(map[string]uuid.UUID, len(p.companies))

		for _, c := range p.companies {
			var returned string
			err := tx.Raw(`
				INSERT INTO companies (id, derived_from_legacy_user_id, name, role, npwp, 					address, city_id, company_profile, settings, bank_account,
					is_verified, deleted_at, created_at, updated_at)
				VALUES (?,?,?,?,?,?,?,?,?::jsonb,?::jsonb,?,?,?,NOW())
				ON CONFLICT (derived_from_legacy_user_id) DO UPDATE SET
					name = EXCLUDED.name, role = EXCLUDED.role,
					npwp = EXCLUDED.npwp, address = EXCLUDED.address,
					settings = EXCLUDED.settings, deleted_at = EXCLUDED.deleted_at,
					updated_at = NOW()
				RETURNING id
			`, c.ID, c.LegacyID, c.Name, c.Role, c.NPWP,
				c.Address, c.CityID, c.Profile, string(c.Settings), nullableJSON(c.Bank),
				c.Verified, c.Deleted, c.Created).Scan(&returned).Error
			if err != nil {
				return fmt.Errorf("company %s (%s): %w", c.LegacyID, c.Name, err)
			}
			got, perr := uuid.Parse(returned)
			if perr != nil {
				return fmt.Errorf("company %s returned an unreadable id %q: %w",
					c.LegacyID, returned, perr)
			}
			companyID[c.LegacyID] = got
		}

		// Users are written WITHOUT parent_id first. parent_id references
		// users, so a child inserted before its parent would violate the
		// foreign key — and the export is not ordered by hierarchy.
		userByLegacy := make(map[string]*userRow, len(p.users))
		for i := range p.users {
			userByLegacy[p.users[i].LegacyID] = &p.users[i]
		}

		fmt.Printf("writing %d users...\n", len(p.users))
		for i, u := range p.users {
			// Remap onto the id the company actually holds, which differs from
			// the proposed one on every run after the first.
			if u.CompanyLegacy != "" {
				if id, ok := companyID[u.CompanyLegacy]; ok {
					u.CompanyID = &id
				}
			}
			err := tx.Exec(`
				INSERT INTO users (id, legacy_id, company_id, username, email, phone,
					password_hash, full_name, address, city_id,
					photo_url, language, alternative_phones, is_email_verified,
					is_phone_verified, is_verified, is_suspended, is_platform_staff,
					deleted_at, created_at, updated_at)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?,?,?,?,?,?,?,?)
				ON CONFLICT (legacy_id) DO UPDATE SET
					company_id = EXCLUDED.company_id, updated_at = NOW()
			`, u.ID, u.LegacyID, u.CompanyID, u.Username, u.Email, u.Phone,
				u.PasswordHash, u.FullName, u.Address, u.CityID,
				u.PhotoURL, u.Language, string(u.AltPhones), u.EmailOK,
				u.PhoneOK, u.Verified, u.Suspended, u.PlatformOK,
				u.Deleted, u.Created, u.Updated).Error
			if err != nil {
				return fmt.Errorf("user %s (row %d): %w", u.LegacyID, i, err)
			}
		}

		// The legacy `parent` link is deliberately NOT carried across.
		//
		// It recorded who invited whom, which sounds worth keeping and is not:
		// nothing read it for any decision, and the audit log already records
		// account creation with an actor and a timestamp — a better record than
		// a bare column that can only ever hold one id.

		// Entitlement: every company gets the default TMS module set, which is
		// what the legacy system effectively granted everyone.
		fmt.Println("granting entitlement and access...")
		if err := tx.Exec(`
			INSERT INTO company_modules (company_id, product, module, enabled)
			SELECT c.id, 'tms', m.module, TRUE
			FROM companies c
			CROSS JOIN (VALUES ('order'),('agreement'),('invoice'),('shipment'),
				('truck'),('warehouse'),('customer'),('dashboard'),('notification')) AS m(module)
			WHERE c.derived_from_legacy_user_id IS NOT NULL
			ON CONFLICT (company_id, product, module) DO NOTHING
		`).Error; err != nil {
			return err
		}
		if err := tx.Exec(`
			INSERT INTO company_product_settings (company_id, product, entitlement_mode)
			SELECT id, 'tms', 'grant' FROM companies WHERE derived_from_legacy_user_id IS NOT NULL
			ON CONFLICT (company_id, product) DO NOTHING
		`).Error; err != nil {
			return err
		}

		// Roles, then assignment.
		//
		// One role per DISTINCT permission set per company, not one per user.
		// Fifty dispatchers with identical access become one role named for the
		// job, which is the point of roles at all; a private role each would
		// carry the old per-user model forward under a new name.
		fmt.Println("creating roles...")

		// Every company gets an administrator, and the legacy root accounts
		// hold it. grants_all rather than a key list: it stays correct when the
		// company is later sold another module.
		if err := tx.Exec(`
			INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
			SELECT id, 'Administrator',
				'Full access to everything this company is entitled to. Created automatically and cannot be deleted.',
				'{}'::text[], TRUE, TRUE
			FROM companies WHERE derived_from_legacy_user_id IS NOT NULL
			ON CONFLICT (company_id, name) DO UPDATE SET
				grants_all = TRUE, is_system = TRUE, updated_at = NOW()
		`).Error; err != nil {
			return fmt.Errorf("administrator roles: %w", err)
		}

		// Job roles, keyed by the exact set of permissions a group held. The
		// name is the legacy job title, numbered where one title covered
		// several distinct sets — merging those would silently widen somebody.
		type roleKey struct {
			company string
			perms   string
		}
		roleNames := map[roleKey]string{}
		nameUsed := map[string]bool{}

		for _, a := range p.access {
			u := userByLegacy[a.UserLegacy]
			if u == nil || u.CompanyLegacy == "" || u.IsAdmin {
				continue
			}
			key := roleKey{u.CompanyLegacy, strings.Join(a.Permissions, "\x00")}
			if _, seen := roleNames[key]; seen {
				continue
			}
			base := a.Role
			if base == "" {
				base = "Member"
			}
			name := base
			for n := 2; nameUsed[u.CompanyLegacy+"|"+name]; n++ {
				name = fmt.Sprintf("%s (%d)", base, n)
			}
			nameUsed[u.CompanyLegacy+"|"+name] = true
			roleNames[key] = name

			qualified := make([]string, 0, len(a.Permissions))
			for _, k := range a.Permissions {
				qualified = append(qualified, "tms:"+k)
			}
			if err := tx.Exec(`
				INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
				VALUES (?, ?, 'Migrated from the permissions this group already held.', ?::text[], FALSE, FALSE)
				ON CONFLICT (company_id, name) DO UPDATE SET
					permissions = EXCLUDED.permissions, updated_at = NOW()
			`, companyID[u.CompanyLegacy], name, pgArray(qualified)).Error; err != nil {
				return fmt.Errorf("role %q for %s: %w", name, u.CompanyLegacy, err)
			}
		}

		fmt.Println("assigning roles...")
		for _, a := range p.access {
			u := userByLegacy[a.UserLegacy]
			if u == nil || u.CompanyLegacy == "" {
				continue
			}
			name := "Administrator"
			if !u.IsAdmin {
				name = roleNames[roleKey{u.CompanyLegacy, strings.Join(a.Permissions, "\x00")}]
				if name == "" {
					continue
				}
			}
			if err := tx.Exec(`
				UPDATE users SET role_id = (
					SELECT id FROM roles WHERE company_id = ? AND name = ?
				) WHERE legacy_id = ?
			`, companyID[u.CompanyLegacy], name, a.UserLegacy).Error; err != nil {
				return fmt.Errorf("assigning %q to %s: %w", name, a.UserLegacy, err)
			}
		}

		return nil
	})
}

func nullableJSON(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// pgArray renders a Postgres text[] literal.
func pgArray(values []string) string {
	if len(values) == 0 {
		return "{}"
	}
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, `"`+strings.ReplaceAll(v, `"`, `\"`)+`"`)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}
