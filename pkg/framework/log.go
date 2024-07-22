package framework

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ErrorLog is an endpoint decorator that logs errors using the provided logger.
// It wraps the given endpoint function and adds error logging functionality.
// The logger is used to log the error message, along with the request and stack trace (if available).
func ErrorLog[Req any, Resp any](logger *zap.Logger) EndpointDecorator[Req, Resp] {
	return func(next Endpoint[Req, Resp]) Endpoint[Req, Resp] {
		return func(ctx context.Context, req Req) (Resp, error) {
			resp, err := next(ctx, req)
			if err != nil {
				logger.
					WithOptions(
						zap.WithCaller(true),
						zap.AddCallerSkip(1),
						zap.AddStacktrace(zapcore.ErrorLevel),
					).
					Error(
						"endpoint error",
						zap.Error(err),
						zap.Any("request", req),
					)
			}
			return resp, err
		}
	}
}
