package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/a-h/templ"
	"github.com/alexedwards/scs/v2"
	"github.com/dmitrymomot/binder"
	authsvc "github.com/dmitrymomot/go-app-template/internal/services/auth"
	"github.com/dmitrymomot/go-app-template/pkg/validator"
	"github.com/dmitrymomot/go-app-template/web/templates/views/auth"
	"github.com/dmitrymomot/random"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// NewAuthHTTPHandler creates a new HTTP handler for the auth service.
// It takes a pointer to a Service struct as a parameter and returns an http.Handler.
// The returned handler is responsible for handling HTTP requests related to the auth service.
func NewAuthHTTPHandler(
	log *zap.SugaredLogger,
	gAuth *oauth2.Config,
	es *authsvc.EmailService,
	gs *authsvc.GoogleService,
	sm *scs.SessionManager,
) http.Handler {
	r := chi.NewRouter()

	r.Group(func(r chi.Router) {
		// Auth middleware
		r.Use(AuthMiddleware(sm, log, false))

		r.Get("/signup", templ.Handler(auth.SignupPage()).ServeHTTP)
		r.Get("/login", templ.Handler(auth.LoginPage()).ServeHTTP)
		r.Get("/forgot-password", templ.Handler(auth.ForgotPasswordPage()).ServeHTTP)
		r.Get("/reset-password", templ.Handler(auth.ResetPasswordPage()).ServeHTTP)

		r.Post("/signup", signupHandler(es, log))
		r.Post("/login", loginHandler(es, log))
		r.Post("/forgot-password", forgotPasswordHandler(es, log))
		r.Post("/reset-password", resetPasswordHandler(es, log))

		// Google OAuth2
		r.Get("/login/google", googleLoginHandler(gAuth, sm))
		r.Get("/login/google/callback", googleLoginCallbackHandler(gAuth, gs, sm, log))
	})

	// Confirm email endpoint must be accessible without authentication
	// to allow users to confirm their email address after signing up.
	r.Get("/confirm-email", confirmEmailHandler(es, log))

	r.Group(func(r chi.Router) {
		// Auth middleware
		r.Use(AuthMiddleware(sm, log, true))
		r.Post("/logout", logoutHandler(sm))
	})

	return r
}

// render renders the given view to the HTTP response writer.
// It logs any errors that occur during rendering and sends an internal server error response if necessary.
func render(w http.ResponseWriter, r *http.Request, view templ.Component, log *zap.SugaredLogger) {
	if err := view.Render(r.Context(), w); err != nil {
		log.Errorw("Failed to render view", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// signupHandler is an HTTP handler for the signup endpoint.
// It takes a pointer to a Service struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the signup endpoint.
func signupHandler(_ *authsvc.EmailService, log *zap.SugaredLogger) http.HandlerFunc {
	type requestPayload struct {
		Email    string `form:"email" validate:"required|email|realEmail" filter:"sanitizeEmail" label:"Email address"`
		Password string `form:"password" validate:"required|password" label:"Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		req := &requestPayload{}
		if err := binder.BindForm(r, req); err != nil {
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrBindForm, err))
			return
		}

		// Validate the request.
		if verr := validator.ValidateStruct(req); len(verr) > 0 {
			// Respond to the client.
			render(w, r, auth.SignupForm(auth.SignupFormPayload{
				Form:   r.Form,
				Errors: verr,
			}), log)
			return
		}

		// ...

		// Respond to the client.
		render(w, r, auth.SignupForm(auth.SignupFormPayload{
			Form:   r.Form,
			Errors: url.Values{},
		}), log)
	}
}

// loginHandler is an HTTP handler for the login endpoint.
// It takes a pointer to a Service struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the login endpoint.
func loginHandler(_ *authsvc.EmailService, log *zap.SugaredLogger) http.HandlerFunc {
	type requestPayload struct {
		Email    string `form:"email" validate:"required|email" filter:"sanitizeEmail" message:"Email is invalid" label:"Email address"`
		Password string `form:"password" validate:"required" message:"Password is required" label:"Password"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		req := &requestPayload{}
		if err := binder.BindForm(r, req); err != nil {
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrBindForm, err))
			return
		}

		// Validate the request.
		if verr := validator.ValidateStruct(req); len(verr) > 0 {
			// Respond to the client.
			render(w, r, auth.LoginForm(auth.LoginFormPayload{
				Form:   r.Form,
				Errors: verr,
			}), log)
			return
		}

		// Redirect to the home page.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// logoutHandler is an HTTP handler for the logout endpoint.
// It takes a pointer to a Service struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the logout endpoint.
func logoutHandler(sm *scs.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Remove the user ID from the session.
		sm.Remove(r.Context(), userIDSessionKey)
		// Redirect to the home page.
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// forgotPasswordHandler is an HTTP handler for the forgot-password endpoint.
// It takes a pointer to a Service struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the forgot-password endpoint.
func forgotPasswordHandler(_ *authsvc.EmailService, log *zap.SugaredLogger) http.HandlerFunc {
	type requestPayload struct {
		Email string `form:"email" validate:"required|email|realEmail" filter:"sanitizeEmail" message:"Email is invalid" label:"Email address"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		req := &requestPayload{}
		if err := binder.BindForm(r, req); err != nil {
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrBindForm, err))
			return
		}

		// Validate the request.
		if verr := validator.ValidateStruct(req); len(verr) > 0 {
			// Respond to the client.
			render(w, r, auth.ForgotPasswordForm(auth.ForgotPasswordFormPayload{
				Form:   r.Form,
				Errors: verr,
			}), log)
			return
		}

		// Respond to the client.
		render(w, r, auth.PopupNotification(auth.PopupPayload{
			Type:        auth.PopupSuccess,
			Title:       "Success!",
			Message:     "Password reset instructions have been sent to your email address. Please check your email. If you don't receive an email, please try again.",
			ActionURL:   "/auth/forgot-password",
			ActionLabel: "Try again",
		}), log)
	}
}

// resetPasswordHandler is an HTTP handler for the reset-password endpoint.
// It takes a pointer to a Service struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the reset-password endpoint.
func resetPasswordHandler(_ *authsvc.EmailService, log *zap.SugaredLogger) http.HandlerFunc {
	type requestPayload struct {
		Token           string `form:"token" validate:"required" message:"Token is required" label:"Token"`
		Password        string `form:"password" validate:"required|password" label:"Password"`
		PasswordConfirm string `form:"password_confirmation" validate:"required|eqField:Password" message:"Passwords do not match" label:"Password confirmation"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		req := &requestPayload{}
		if err := binder.BindForm(r, req); err != nil {
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrBindForm, err))
			return
		}

		// Validate the request.
		if verr := validator.ValidateStruct(req); len(verr) > 0 {
			// Respond to the client.
			render(w, r, auth.ResetPasswordForm(auth.ResetPasswordFormPayload{
				Form:   r.Form,
				Errors: verr,
			}), log)
			return
		}

		// Respond to the client.
		render(w, r, auth.ResetPasswordForm(auth.ResetPasswordFormPayload{
			Form:   r.Form,
			Errors: url.Values{},
		}), log)
	}
}

// confirmEmailHandler is an HTTP handler for the confirm-email endpoint.
// It takes a pointer to a Service struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the confirm-email endpoint.
func confirmEmailHandler(es *authsvc.EmailService, log *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			sendErrorResponseWithCode(w, r, http.StatusBadRequest, ErrMissingEmailConfirmationToken)
			return
		}

		if _, err := es.VerifyEmail(r.Context(), token); err != nil {
			log.Errorw("Failed to verify email", "error", err)
			sendErrorResponse(w, r, err)
			return
		}
	}
}

// googleLoginHandler is an HTTP handler for the login/google endpoint.
// It takes a pointer to a oauth2.Config struct as a parameter and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the login/google endpoint.
func googleLoginHandler(c *oauth2.Config, sm *scs.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := random.String(32)
		// Store the auth code in the session.
		sm.Put(r.Context(), googleAuthStateKey, state)
		// Redirect to the Google OAuth2 login page.
		http.Redirect(w, r, c.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusTemporaryRedirect)
	}
}

// googleLoginCallbackHandler is an HTTP handler for the login/google/callback endpoint.
// It takes a pointer to a oauth2.Config struct and a pointer to a Service struct as parameters and returns an http.HandlerFunc.
// The returned handler is responsible for handling HTTP requests to the login/google/callback endpoint.
func googleLoginCallbackHandler(c *oauth2.Config, gAuth *authsvc.GoogleService, sm *scs.SessionManager, log *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		code := r.URL.Query().Get("code")
		if code == "" {
			sendErrorResponseWithCode(w, r, http.StatusBadRequest, ErrMissingAuthCode)
			return
		}

		// Check the state.
		state := r.URL.Query().Get("state")
		if state == "" {
			sendErrorResponseWithCode(w, r, http.StatusBadRequest, ErrMissingAuthState)
			return
		}

		// Get the auth code from the session.
		authState := sm.GetString(r.Context(), googleAuthStateKey)
		if authState != state {
			sendErrorResponseWithCode(w, r, http.StatusBadRequest, ErrInvalidAuthState)
			return
		}

		// Delete the auth state from the session.
		sm.Remove(r.Context(), googleAuthStateKey)

		// Exchange the code for a token.
		token, err := c.Exchange(r.Context(), code)
		if err != nil {
			log.Errorw("Failed to exchange code", "error", err)
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrFailedToExchangeCode, err))
			return
		}

		// Authenticate the user.
		u, err := gAuth.Auth(r.Context(), token.AccessToken)
		if err != nil {
			log.Errorw("Failed to authenticate user", "error", err)
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrFailedToAuthenticate, err))
			return
		}

		// Renew the session token.
		if err := sm.RenewToken(r.Context()); err != nil {
			log.Errorw("Failed to renew session token", "error", err)
			sendErrorResponseWithCode(w, r, http.StatusInternalServerError, errors.Join(ErrFailedToAuthenticate, err))
			return
		}

		// Set the user ID in the session.
		sm.Put(r.Context(), userIDSessionKey, u.ID)

		// Redirect to the home page.
		http.Redirect(w, r, authenticatedURL, http.StatusSeeOther)
	}
}
