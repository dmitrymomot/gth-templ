package dto

import (
	"time"

	"github.com/google/uuid"
)

// Account represents a user account entity.
type Account struct {
	ID      uuid.UUID
	Name    string
	Slug    string
	LogoURL string
	Members []AccountMember
}

// AccountMember represents a user account member entity.
type AccountMember struct {
	ID        string
	AccountID string
	UserID    string
	Name      string
	Role      string
	AvatarURL string
	CreatedAt time.Time
}
