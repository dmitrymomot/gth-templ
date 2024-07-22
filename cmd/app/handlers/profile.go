package handlers

import (
	"net/http"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/dmitrymomot/go-app-template/internal/dto"
	"github.com/dmitrymomot/go-app-template/internal/services/user"
	"github.com/dmitrymomot/go-app-template/web/templates/views/profile"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// NewProfileHTTPHandler creates a new HTTP handler for the profile endpoints.
func NewProfileHTTPHandler(
	log *zap.SugaredLogger,
	sm *scs.SessionManager,
	us *user.Service,
) http.Handler {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		// Auth middleware
		r.Use(AuthMiddleware(sm, log, true))

		// GET /profile
		r.Get("/", profileHandler(us, log))
	})

	return r
}

// profileHandler is the handler for the GET /profile endpoint.
func profileHandler(us *user.Service, log *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the user ID from the context.
		uid := dto.GetUserIDFromCtx(r.Context())

		user, err := us.GetUserByID(r.Context(), uid)
		if err != nil {
			log.Errorw("Failed to get user by ID", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Write the response.
		templ.Handler(profile.ProfilePage(profile.User{
			ID:    user.ID.String(),
			Email: user.Email,
		})).ServeHTTP(w, r)
	}
}
