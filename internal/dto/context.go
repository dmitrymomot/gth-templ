package dto

import (
	"context"

	"github.com/google/uuid"
)

// contextKey represents a key for storing values in a context.
// It's used to avoid key collisions in the context.
type contextKey struct{ key string }

// NewContextKey returns a new context key.
func NewContextKey(key string) contextKey {
	return contextKey{key: key}
}

// Predefined context keys.
var (
	// ContextKeyUserID is the key used to store the user ID in the context.
	ContextKeyUserID = NewContextKey("user_id")
)

// GetUserIDFromCtx returns the user entity from the context.
func GetUserIDFromCtx(ctx context.Context) uuid.UUID {
	id, ok := ctx.Value(ContextKeyUserID).(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// SetUserIDInCtx sets the user ID in the context.
func SetUserIDInCtx(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, ContextKeyUserID, userID)
}
