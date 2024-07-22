package framework

import "net/url"

// ErrValidation represents an error type that contains validation errors.
// It is used to store URL values that represent validation errors.
type ErrValidation url.Values

// Error returns the error message.
func (e ErrValidation) Error() string {
	return "validation error: " + url.Values(e).Encode()
}

// NewErrValidation creates a new validation error with the given values.
func NewErrValidation(values url.Values) ErrValidation {
	return ErrValidation(values)
}
