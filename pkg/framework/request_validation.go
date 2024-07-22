package framework

import (
	"context"
	"net/url"

	"github.com/dmitrymomot/go-app-template/pkg/validator"
)

// validationFunc is a function type that takes an interface{} as input and returns url.Values.
// It is used for defining custom validation functions for request validation.
type validationFunc func(interface{}) url.Values

// DefaultValidationFunc is the default validation function used for request validation.
// It is set to `validator.ValidateStruct` by default.
var DefaultValidationFunc = validator.ValidateStruct

// ValidateRequest is an endpoint decorator that validates the incoming request
// before calling the next decorator or the endpoint.
// It takes a request type `Req` and a response type `Resp` as input
// and returns an `EndpointDecorator` function.
func ValidateRequest[Req any, Resp any](vfn validationFunc) EndpointDecorator[Req, Resp] {
	if vfn == nil {
		// Use the default validation function if none is provided
		vfn = DefaultValidationFunc
	}
	// Return the endpoint decorator function
	return func(next Endpoint[Req, Resp]) Endpoint[Req, Resp] {
		return func(ctx context.Context, req Req) (resp Resp, err error) {
			// Validate the request
			if verr := vfn(&req); len(verr) > 0 {
				return resp, NewErrValidation(verr)
			}

			// Call the next decorator or the endpoint
			return next(ctx, req)
		}
	}
}
