package account

import "errors"

// Predefined errors
var (
	ErrAccountNameInvalid    = errors.New("account name is invalid")
	ErrAccountNameLength     = errors.New("account name must be between 5 and 50 characters long")
	ErrAccountNameCharacters = errors.New("account name must contain only letters, numbers, and spaces")
	ErrAccountNameSpaces     = errors.New("account name must not contain any leading or trailing spaces")
)
