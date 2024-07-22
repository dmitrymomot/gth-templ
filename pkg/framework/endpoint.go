package framework

import "context"

// Endpoint represents a function that handles a specific endpoint in a service.
// It takes a context and a request object as input, and returns a response object and an error.
type Endpoint[Req any, Resp any] func(ctx context.Context, req Req) (Resp, error)

// EndpointDecorator is a function type that decorates an endpoint.
// It takes an `Endpoint` as input and returns an `Endpoint` as output.
// The `EndpointDecorator` can be used to add additional functionality or modify the behavior of an endpoint.
// The `Req` and `Resp` type parameters represent the request and response types of the endpoint, respectively.
type EndpointDecorator[Req any, Resp any] func(Endpoint[Req, Resp]) Endpoint[Req, Resp]

// ApplyEndpointDecorators applies a series of decorators to an endpoint and returns the decorated endpoint.
// The decorators are applied in the order they are provided.
// The endpoint function is passed through each decorator, allowing additional functionality to be added.
// The resulting decorated endpoint is returned.
func ApplyEndpointDecorators[Req any, Resp any](
	endpoint Endpoint[Req, Resp],
	decorators ...EndpointDecorator[Req, Resp],
) Endpoint[Req, Resp] {
	for _, decorator := range decorators {
		endpoint = decorator(endpoint)
	}
	return endpoint
}
