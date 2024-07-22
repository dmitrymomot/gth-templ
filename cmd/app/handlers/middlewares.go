package handlers

import (
	"net/http"

	"github.com/alexedwards/scs/v2"
	"github.com/dmitrymomot/go-app-template/internal/dto"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuthMiddleware is a middleware that checks if the user is authenticated.
// If the user is not authenticated, it redirects them to the login page.
func AuthMiddleware(
	sm *scs.SessionManager,
	log *zap.SugaredLogger,
	mustBeAuthorized bool,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if the user id is in the session.
			uid, ok := sm.Get(r.Context(), userIDSessionKey).(uuid.UUID)
			if (!ok || uid == uuid.Nil) && mustBeAuthorized {
				// Redirect to the login page.
				http.Redirect(w, r, notAuthenticatedURL, http.StatusSeeOther)
				return
			}

			// Redirect to the profile page if the user is already authenticated.
			if ok && uid != uuid.Nil && !mustBeAuthorized {
				http.Redirect(w, r, authenticatedURL, http.StatusSeeOther)
				return
			}

			// Set the user ID in the context.
			ctx := dto.SetUserIDInCtx(r.Context(), uid)

			// Call the next handler.
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
