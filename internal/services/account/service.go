package account

import (
	"context"

	"github.com/dmitrymomot/go-app-template/db/repository"
	"github.com/google/uuid"
)

// Service represents the account service.
type Service struct {
	repo repository.Querier
}

// NewService creates a new instance of the Service struct.
// It takes a repository.Querier as a parameter and returns a pointer to the Service.
func NewService(repo repository.Querier) *Service {
	return &Service{
		repo: repo,
	}
}

// CreateAccount creates a new account with the specified name and title.
// It takes a name and a title as parameters and returns an error.
func (s *Service) CreateAccount(ctx context.Context, ownerID uuid.UUID, name, slug, logoURL string) error {
	return nil
}
