// Package clients holds the authentication service's outbound connections.
package clients

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	notificationv1 "github.com/karlo/authentication-service/internal/platform/genproto/karlo/notification/v1"
	"github.com/karlo/authentication-service/internal/platform/grpcutil"
)

// Notifier delivers an event to the notification service, best-effort.
type Notifier interface {
	NotifyPhone(ctx context.Context, event notificationv1.EventType, phone, subjectID, idempotencyKey string, params map[string]any)
}

// Notification is the gRPC client. Like the business service's, it never
// fails the caller: an account that was created has been created whether or
// not the WhatsApp about it went out, and the console shows the credentials
// once so the planner can pass them on by hand.
type Notification struct {
	client  notificationv1.NotificationServiceClient
	timeout time.Duration
}

func NewNotification(target, serviceToken string, timeout time.Duration) (*Notification, error) {
	conn, err := grpcutil.Dial(grpcutil.DialConfig{Service: "authentication", Target: target, ServiceToken: serviceToken})
	if err != nil {
		return nil, err
	}
	return &Notification{client: notificationv1.NewNotificationServiceClient(conn), timeout: timeout}, nil
}

func (n *Notification) NotifyPhone(ctx context.Context, event notificationv1.EventType, phone, subjectID, idempotencyKey string, params map[string]any) {
	p, err := structpb.NewStruct(params)
	if err != nil {
		slog.ErrorContext(ctx, "notification params could not be encoded", "event", event.String(), "error", err)
		p = nil
	}
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), n.timeout)
	defer cancel()
	_, err = n.client.Notify(sendCtx, &notificationv1.NotifyRequest{
		Event:          event,
		Audience:       &notificationv1.Audience{Target: &notificationv1.Audience_Phone{Phone: &notificationv1.PhoneNumber{Number: phone}}},
		SubjectId:      subjectID,
		SubjectType:    "user",
		Params:         p,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		slog.ErrorContext(ctx, "notification delivery failed", "event", event.String(), "subject", subjectID, "error", err)
	}
}

// NoopNotifier is used when the notification service is not configured.
type NoopNotifier struct{}

func (NoopNotifier) NotifyPhone(context.Context, notificationv1.EventType, string, string, string, map[string]any) {
}
