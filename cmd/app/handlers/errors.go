package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dmitrymomot/go-app-template/internal/services/auth"
	"github.com/dmitrymomot/go-app-template/web/templates/views"
)

// Predefined handlers errors
var (
	ErrMissingAuthCode               = errors.New("missing auth code")
	ErrBindForm                      = errors.New("failed to bind form")
	ErrMissingAuthState              = errors.New("missing auth state")
	ErrInvalidAuthState              = errors.New("invalid auth state")
	ErrFailedToExchangeCode          = errors.New("failed to exchange code")
	ErrFailedToGetUserProfile        = errors.New("failed to get user profile")
	ErrFailedToReadResponseBody      = errors.New("failed to read response body")
	ErrFailedToAuthenticate          = errors.New("failed to authenticate")
	ErrInvalidSession                = errors.New("invalid session")
	ErrMissingEmailConfirmationToken = errors.New("missing email confirmation token")
)

// NotFoundHandler is a handler for 404 Not Found
func NotFoundHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := errors.New("page not found")
		if isJsonRequest(r) {
			err = errors.New("endpoint not found")
		}
		sendErrorResponseWithCode(
			w, r,
			http.StatusNotFound,
			err,
		)
	}
}

// MethodNotAllowedHandler is a handler for 405 Method Not Allowed
func MethodNotAllowedHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sendErrorResponseWithCode(
			w, r,
			http.StatusMethodNotAllowed,
			errors.New(http.StatusText(http.StatusMethodNotAllowed)),
		)
	}
}

// Predefined http encoder content type
const (
	contentTypeHeader  = "Content-Type"
	contextTypeCharset = "charset=utf-8"
	contentTypeJSON    = "application/json"
	contentTypeHTML    = "text/html"
	contentTypeJSONUTF = contentTypeJSON + "; " + contextTypeCharset
	contentTypeHTMLUTF = contentTypeHTML + "; " + contextTypeCharset
)

// Helper function to check if an error code is valid
func isValidErrorCode(errCode int) bool {
	return errCode >= 400 && errCode < 600
}

// Is request a json request?
func isJsonRequest(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get(contentTypeHeader)), contentTypeJSON)
}

// Helper function to send an error response
func sendErrorResponseWithCode(w http.ResponseWriter, r *http.Request, statusCode int, err error) {
	if !isValidErrorCode(statusCode) {
		statusCode = http.StatusInternalServerError
	}

	if isJsonRequest(r) {
		w.Header().Set(contentTypeHeader, contentTypeJSONUTF)
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set(contentTypeHeader, contentTypeHTMLUTF)
	w.WriteHeader(statusCode)
	if err := views.ErrorPage(statusCode, err.Error()).Render(r.Context(), w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Helper function to send an error response
func sendErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	sendErrorResponseWithCode(w, r, defineErrorCode(err), err)
}

// Helper function to define error code by error.
// If error is not found, return 500 Internal Server Error.
// It unwraps the error to find the original error.
func defineErrorCode(err error) int {
	if err == nil {
		return http.StatusOK
	}
	for {
		if code, ok := errorsToCodes[err]; ok {
			return code
		}
		if err = errors.Unwrap(err); err == nil {
			break
		}
	}
	return http.StatusInternalServerError
}

// Errors to codes mapping
var errorsToCodes = map[error]int{
	auth.ErrEmailAlreadyExists:              http.StatusConflict,
	auth.ErrUserNotFound:                    http.StatusNotFound,
	auth.ErrInvalidCredentials:              http.StatusUnauthorized,
	auth.ErrFailedToCreateUser:              http.StatusInternalServerError,
	auth.ErrFailedToSendEmail:               http.StatusInternalServerError,
	auth.ErrFailedToAuthenticate:            http.StatusInternalServerError,
	auth.ErrFailedToRestoreAccess:           http.StatusInternalServerError,
	auth.ErrFailedToResetPassword:           http.StatusInternalServerError,
	auth.ErrInvalidToken:                    http.StatusUnauthorized,
	auth.ErrFailedToSignup:                  http.StatusInternalServerError,
	auth.ErrFailedToVerifyEmail:             http.StatusInternalServerError,
	auth.ErrFailedToGetUserProfile:          http.StatusInternalServerError,
	auth.ErrFailedToReadResponseBody:        http.StatusInternalServerError,
	auth.ErrFailedToAuthenticateUser:        http.StatusInternalServerError,
	auth.ErrFailedToCreateUserSocialProfile: http.StatusInternalServerError,
	auth.ErrEmptyOrNotVerifiedEmail:         http.StatusUnauthorized,
}
