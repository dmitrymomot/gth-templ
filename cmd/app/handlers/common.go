package handlers

const (
	// googleAuthStateKey is the key used to store the Google OAuth2 auth state in the session.
	googleAuthStateKey = "google_auth_state"
	// userIDSessionKey is the key used to store the user ID in the session.
	userIDSessionKey = "user_id"
	// notAuthenticatedURL is the URL to redirect to if the user is not authenticated.
	notAuthenticatedURL = "/auth/login"
	// authenticatedURL is the URL to redirect to if the user is authenticated.
	authenticatedURL = "/profile"
)
