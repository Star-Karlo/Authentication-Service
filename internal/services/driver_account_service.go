package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/karlo/authentication-service/internal/clients"
	"github.com/karlo/authentication-service/internal/models"
	notificationv1 "github.com/karlo/authentication-service/internal/platform/genproto/karlo/notification/v1"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/repository"
)

// DriverRoleName is the per-company system role a driver's login holds.
// Created on first use with just what the K-Trip app needs.
const DriverRoleName = "Driver"

// DriverAccountService gives a master-data driver a login for K-Trip.
//
// Two ways in, both from the review:
//
//   - The planner registers the driver: an account is created here with a
//     generated password, and the driver gets the app link plus credentials
//     on WhatsApp. The planner sees the password once, in the response.
//   - The driver registered themselves in K-Trip first and gave the planner
//     their username: the planner looks it up and adopts the account into
//     the company.
//
// Either way the console then stamps the user id on the master-data driver,
// which is what the truck pairing and the business service key on.
type DriverAccountService struct {
	users     *repository.UserRepository
	roles     *repository.RoleRepository
	companies *repository.CompanyRepository
	register  func(context.Context, RegisterInput) (*models.User, error)
	notifier  clients.Notifier
	appLink   string
}

func NewDriverAccountService(
	users *repository.UserRepository,
	roles *repository.RoleRepository,
	companies *repository.CompanyRepository,
	register func(context.Context, RegisterInput) (*models.User, error),
	notifier clients.Notifier,
	appLink string,
) *DriverAccountService {
	if notifier == nil {
		notifier = clients.NoopNotifier{}
	}
	return &DriverAccountService{users: users, roles: roles, companies: companies, register: register, notifier: notifier, appLink: appLink}
}

type CreateDriverAccountInput struct {
	FullName string
	Phone    string
	Username string // optional; derived from the name when empty
	Password string // optional; generated when empty
	// SendWhatsApp delivers the credentials to the phone. Off when the
	// planner will hand them over in person.
	SendWhatsApp bool
}

type DriverAccount struct {
	UserID       uuid.UUID  `json:"userId"`
	Username     string     `json:"username"`
	FullName     string     `json:"fullName"`
	Phone        string     `json:"phone"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastLoginAt  *time.Time `json:"lastLoginAt,omitempty"`
	FirstLoginAt *time.Time `json:"firstLoginAt,omitempty"`
	// Password is set only on the response that created the account, and
	// never stored in the clear anywhere.
	Password     string `json:"password,omitempty"`
	WhatsAppSent bool   `json:"whatsappSent"`
}

var usernameChars = regexp.MustCompile(`[^a-z0-9._]`)

// Create registers the driver's login under the company and tells them.
func (s *DriverAccountService) Create(ctx context.Context, actorUserID, companyID uuid.UUID, in CreateDriverAccountInput) (*DriverAccount, error) {
	name := strings.TrimSpace(in.FullName)
	phone := strings.TrimSpace(in.Phone)
	if name == "" {
		return nil, fmt.Errorf("%w: a name is required", ErrValidation)
	}
	if phone == "" {
		return nil, fmt.Errorf("%w: a WhatsApp number is required", ErrValidation)
	}
	username := strings.TrimSpace(in.Username)
	if username == "" {
		username = usernameFrom(name)
	}
	password := in.Password
	generated := false
	if password == "" {
		password = generatePassword()
		generated = true
	}

	role, err := s.ensureDriverRole(ctx, companyID)
	if err != nil {
		return nil, err
	}
	user, err := s.register(ctx, RegisterInput{
		Username:  username,
		Phone:     phone,
		Password:  password,
		FullName:  name,
		ParentID:  &actorUserID,
		CompanyID: &companyID,
		RoleID:    &role.ID,
	})
	if err != nil {
		return nil, err
	}

	out := &DriverAccount{
		UserID: user.ID, Username: username, FullName: name, Phone: phone,
		Status: statusOf(user), CreatedAt: user.CreatedAt,
	}
	// Shown once. A password the planner typed is theirs to know already; a
	// generated one has to be shown or it exists nowhere.
	if generated || in.SendWhatsApp {
		out.Password = password
	}
	if in.SendWhatsApp {
		companyName := "Karlo"
		if co, err := s.companies.FindByID(ctx, companyID); err == nil && co != nil {
			companyName = co.Name
		}
		s.notifier.NotifyPhone(ctx, notificationv1.EventType_EVENT_TYPE_DRIVER_ACCOUNT_CREATED,
			phone, user.ID.String(), "driver-account:"+user.ID.String(),
			map[string]any{"companyName": companyName, "appLink": s.appLink, "username": username, "password": password})
		out.WhatsAppSent = true
	}
	return out, nil
}

// Lookup finds a self-registered driver by username, for the planner to
// confirm before adopting. Only accounts not yet in another company are
// returned: a driver on somebody else's books is not ours to take.
func (s *DriverAccountService) Lookup(ctx context.Context, companyID uuid.UUID, username string) (*DriverAccount, error) {
	u, err := s.users.FindByIdentifier(ctx, strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	if u.CompanyID != nil && *u.CompanyID != companyID {
		return nil, fmt.Errorf("%w: that username belongs to another company", ErrForbidden)
	}
	return toDriverAccount(u), nil
}

// Adopt attaches a self-registered driver to the company with the driver role.
func (s *DriverAccountService) Adopt(ctx context.Context, companyID, userID uuid.UUID) (*DriverAccount, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.CompanyID != nil && *u.CompanyID != companyID {
		return nil, fmt.Errorf("%w: that account belongs to another company", ErrForbidden)
	}
	role, err := s.ensureDriverRole(ctx, companyID)
	if err != nil {
		return nil, err
	}
	if err := s.users.UpdateFields(ctx, userID, map[string]interface{}{"company_id": companyID, "role_id": role.ID}); err != nil {
		return nil, err
	}
	u.CompanyID = &companyID
	u.RoleID = &role.ID
	return toDriverAccount(u), nil
}

// List is the "accounts registered" table: every driver login in the
// company with whether they have signed in yet.
func (s *DriverAccountService) List(ctx context.Context, companyID uuid.UUID) ([]DriverAccount, error) {
	role, err := s.roles.FindByName(ctx, companyID, DriverRoleName)
	if errors.Is(err, repository.ErrNotFound) {
		return []DriverAccount{}, nil
	}
	if err != nil {
		return nil, err
	}
	users, _, err := s.users.ListByCompany(ctx, companyID, nil, query.Params{Page: 0, PageSize: 500})
	if err != nil {
		return nil, err
	}
	out := make([]DriverAccount, 0, len(users))
	for i := range users {
		if users[i].RoleID != nil && *users[i].RoleID == role.ID {
			out = append(out, *toDriverAccount(&users[i]))
		}
	}
	return out, nil
}

func (s *DriverAccountService) ensureDriverRole(ctx context.Context, companyID uuid.UUID) (*models.Role, error) {
	role, err := s.roles.FindByName(ctx, companyID, DriverRoleName)
	if err == nil {
		return role, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	desc := "What the K-Trip driver app needs: see and advance the shipments assigned to you. Created automatically."
	role = &models.Role{
		CompanyID:   companyID,
		Name:        DriverRoleName,
		Description: &desc,
		Permissions: []string{"tms:shipment.read", "tms:shipment.update", "tms:order.read"},
		IsSystem:    true,
	}
	if err := s.roles.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("driver role: %w", err)
	}
	return role, nil
}

func toDriverAccount(u *models.User) *DriverAccount {
	a := &DriverAccount{UserID: u.ID, Status: statusOf(u), CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
	if u.Username != nil {
		a.Username = *u.Username
	}
	if u.FullName != nil {
		a.FullName = *u.FullName
	}
	if u.Phone != nil {
		a.Phone = *u.Phone
	}
	// First login is not stored separately; the first time last_login_at
	// is set is the first login, and for the table's purpose ("has the
	// driver signed in yet") that is the same fact.
	a.FirstLoginAt = u.LastLoginAt
	return a
}

// usernameFrom makes "Dwi Prasetyo" into "dwi.prasetyo" plus two digits, so
// two drivers with the same name do not collide on the first try.
func usernameFrom(name string) string {
	base := usernameChars.ReplaceAllString(strings.ToLower(strings.Join(strings.Fields(name), ".")), "")
	if len(base) > 20 {
		base = base[:20]
	}
	if base == "" {
		base = "driver"
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(90))
	return fmt.Sprintf("%s%02d", base, n.Int64()+10)
}

// generatePassword: eight characters a driver can type on a phone keyboard
// without confusion (no 0/O, 1/l/I), satisfying the strength rule.
func generatePassword() string {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"
	const digits = "23456789"
	var b strings.Builder
	for i := 0; i < 6; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b.WriteByte(letters[n.Int64()])
	}
	for i := 0; i < 2; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		b.WriteByte(digits[n.Int64()])
	}
	return b.String()
}

func statusOf(u *models.User) string {
	if u.IsSuspended {
		return "suspended"
	}
	return "active"
}
