// Package grpcserver implements the AuthService gRPC contract on top of the
// same service layer the HTTP handlers use, so the two cannot drift apart.
package grpcserver

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/karlo/authentication-service/internal/models"
	authv1 "github.com/karlo/authentication-service/internal/platform/genproto/karlo/auth/v1"
	"github.com/karlo/authentication-service/internal/platform/query"
	"github.com/karlo/authentication-service/internal/platform/safeconv"
	"github.com/karlo/authentication-service/internal/repository"
	"github.com/karlo/authentication-service/internal/services"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements authv1.AuthServiceServer.
type Server struct {
	authv1.UnimplementedAuthServiceServer

	auth      *services.AuthService
	users     *services.UserService
	companies *repository.CompanyRepository
	devices   *repository.DeviceTokenRepository
	userRepo  *repository.UserRepository
}

func New(
	auth *services.AuthService,
	users *services.UserService,
	companies *repository.CompanyRepository,
	devices *repository.DeviceTokenRepository,
	userRepo *repository.UserRepository,
) *Server {
	return &Server{auth: auth, users: users, companies: companies, devices: devices, userRepo: userRepo}
}

// ValidateToken resolves any credential into a principal.
//
// An invalid token is not a gRPC error: it is a valid answer to the question
// asked. Returning a status error would make callers unable to distinguish
// "this token is bad" from "the auth service is unreachable", and those demand
// very different handling.
func (s *Server) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	principal, user, err := s.auth.ValidateToken(ctx, req.GetToken())
	if err != nil {
		return &authv1.ValidateTokenResponse{
			Valid:  false,
			Reason: reasonFor(err),
		}, nil
	}

	kind := authv1.TokenKind_TOKEN_KIND_JWT
	if principal.TokenID == "" {
		kind = authv1.TokenKind_TOKEN_KIND_STATIC
	}

	return &authv1.ValidateTokenResponse{
		Valid: true,
		User:  toProtoUser(user),
		Kind:  kind,
	}, nil
}

func (s *Server) GetUser(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed user id")
	}

	var user *models.User
	if req.GetIncludeDeleted() {
		user, err = s.userRepo.FindByIDIncludingDeleted(ctx, id)
	} else {
		user, err = s.users.GetByID(ctx, id)
	}
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to load user")
	}

	return &authv1.GetUserResponse{User: toProtoUser(user)}, nil
}

// GetUsers resolves a batch. Ids that do not parse are skipped rather than
// failing the whole call, because a batch is usually assembled from several
// sources and one bad element should not lose the rest.
func (s *Server) GetUsers(ctx context.Context, req *authv1.GetUsersRequest) (*authv1.GetUsersResponse, error) {
	ids := make([]uuid.UUID, 0, len(req.GetIds()))
	for _, raw := range req.GetIds() {
		if id, err := uuid.Parse(raw); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return &authv1.GetUsersResponse{}, nil
	}

	users, err := s.users.GetMany(ctx, ids, req.GetIncludeDeleted())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load users")
	}

	out := make([]*authv1.User, 0, len(users))
	for i := range users {
		out = append(out, toProtoUser(&users[i]))
	}
	return &authv1.GetUsersResponse{Users: out}, nil
}

func (s *Server) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	id, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed user id")
	}

	allowed, err := s.users.CheckPermission(ctx, id, req.GetModule(), req.GetAction())
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return &authv1.CheckPermissionResponse{Allowed: false}, nil
		}
		return nil, status.Error(codes.Internal, "permission check failed")
	}

	return &authv1.CheckPermissionResponse{Allowed: allowed}, nil
}

func (s *Server) GetCompany(ctx context.Context, req *authv1.GetCompanyRequest) (*authv1.GetCompanyResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed company id")
	}

	company, err := s.companies.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "company not found")
		}
		return nil, status.Error(codes.Internal, "failed to load company")
	}

	return &authv1.GetCompanyResponse{Company: toProtoCompany(company)}, nil
}

func (s *Server) ListCompanyMembers(ctx context.Context, req *authv1.ListCompanyMembersRequest) (*authv1.ListCompanyMembersResponse, error) {
	companyID, err := uuid.Parse(req.GetCompanyId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed company id")
	}

	params := query.FromProto(req.GetQuery(), repository.UserListFields())
	users, total, err := s.users.ListCompanyMembers(ctx, companyID, req.GetRoles(), params)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list members")
	}

	out := make([]*authv1.User, 0, len(users))
	for i := range users {
		out = append(out, toProtoUser(&users[i]))
	}

	return &authv1.ListCompanyMembersResponse{
		Users:    out,
		PageInfo: params.PageInfo(total),
	}, nil
}

// ResolveDeliveryTargets is the notification service's read path into this
// database. It returns one target per active device token, plus a target
// carrying only the email and phone when a user has no device registered, so
// that email-only recipients are not silently dropped.
func (s *Server) ResolveDeliveryTargets(ctx context.Context, req *authv1.ResolveDeliveryTargetsRequest) (*authv1.ResolveDeliveryTargetsResponse, error) {
	ids := make([]uuid.UUID, 0, len(req.GetUserIds()))
	for _, raw := range req.GetUserIds() {
		if id, err := uuid.Parse(raw); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return &authv1.ResolveDeliveryTargetsResponse{}, nil
	}

	users, err := s.users.GetMany(ctx, ids, false)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load users")
	}

	tokens, err := s.devices.ActiveForUsers(ctx, ids)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to load device tokens")
	}

	tokensByUser := make(map[uuid.UUID][]string, len(users))
	for _, t := range tokens {
		tokensByUser[t.UserID] = append(tokensByUser[t.UserID], t.PushToken)
	}

	// Company email recipients are resolved once per company rather than once
	// per user, since many users share one.
	extraByCompany := map[uuid.UUID][]string{}

	out := make([]*authv1.DeliveryTarget, 0, len(users))
	for i := range users {
		u := &users[i]

		var extra []string
		if u.CompanyID != nil {
			if cached, ok := extraByCompany[*u.CompanyID]; ok {
				extra = cached
			} else if company, cerr := s.companies.FindByID(ctx, *u.CompanyID); cerr == nil {
				extra = company.EmailRecipients
				extraByCompany[*u.CompanyID] = extra
			}
		}

		// Each target is constructed fresh rather than copied from a
		// prototype. A protobuf message carries internal state including a
		// mutex, so copying one by value is a data race waiting to happen; go
		// vet rejects it for exactly that reason.
		newTarget := func(pushToken string) *authv1.DeliveryTarget {
			return &authv1.DeliveryTarget{
				UserId:               u.ID.String(),
				Email:                deref(u.Email),
				Phone:                deref(u.Phone),
				Language:             u.Language,
				ExtraEmailRecipients: extra,
				PushToken:            pushToken,
			}
		}

		userTokens := tokensByUser[u.ID]
		if len(userTokens) == 0 {
			// A user with no registered device is still reachable by email and
			// WhatsApp, so they must not be dropped from the result.
			out = append(out, newTarget(""))
			continue
		}
		for _, tok := range userTokens {
			out = append(out, newTarget(tok))
		}
	}

	return &authv1.ResolveDeliveryTargetsResponse{Targets: out}, nil
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

func toProtoUser(u *models.User) *authv1.User {
	if u == nil {
		return nil
	}

	perm := make(map[string]*authv1.PermissionModule, len(u.Permission))
	for module, actions := range u.Permission {
		perm[module] = &authv1.PermissionModule{Actions: actions}
	}

	out := &authv1.User{
		Id:          u.ID.String(),
		Username:    deref(u.Username),
		Email:       deref(u.Email),
		Phone:       deref(u.Phone),
		FullName:    deref(u.FullName),
		Role:        u.Role,
		AccountType: u.AccountType,
		IsSuspended: u.IsSuspended,
		IsVerified:  u.IsVerified,
		Deleted:     u.DeletedAt.Valid,
		Language:    u.Language,
		Permission:  perm,
		CreatedAt:   timestamppb.New(u.CreatedAt),
		UpdatedAt:   timestamppb.New(u.UpdatedAt),
	}
	if u.ParentID != nil {
		out.ParentId = u.ParentID.String()
	}
	if u.CompanyID != nil {
		out.CompanyId = u.CompanyID.String()
	}
	return out
}

func toProtoCompany(c *models.Company) *authv1.Company {
	if c == nil {
		return nil
	}
	return &authv1.Company{
		Id:      c.ID.String(),
		Name:    c.Name,
		Role:    c.Role,
		Npwp:    deref(c.NPWP),
		Address: deref(c.Address),
		Settings: &authv1.CompanySettings{
			CancelWithValidate:               c.Settings.CancelWithValidate,
			FinishWithGeofencing:             c.Settings.FinishWithGeofencing,
			ActiveAgreementVerifiedOnly:      c.Settings.ActiveAgreementVerifiedOnly,
			PpnPercentage:                    c.Settings.PPNPercentage,
			Pph23Percentage:                  c.Settings.PPH23Percentage,
			UseStrictAgreement:               c.Settings.UseStrictAgreement,
			MaxDriverAvailableAfterOrderDone: safeconv.NonNegativeInt32(c.Settings.MaxDriverAvailableAfterOrderDone),
			AccessTolls:                      c.Settings.AccessTolls,
		},
		CreatedAt: timestamppb.New(c.CreatedAt),
	}
}

// reasonFor renders a validation failure using the wording the legacy clients
// already display, so the split is invisible to them.
func reasonFor(err error) string {
	switch {
	case errors.Is(err, services.ErrSessionRevoked):
		return "Harap login kembali"
	case errors.Is(err, services.ErrAccountSuspended), errors.Is(err, services.ErrAccountDeleted):
		return "Akun anda telah dihapus atau di non-aktifkan"
	default:
		return "Silahkan untuk login ulang"
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
