package endpoints

import (
	"context"

	"github.com/dmitrymomot/go-app-template/internal/services/auth"
	"github.com/dmitrymomot/go-app-template/pkg/framework"
)

type (
	AuthWithEmailAndPassword struct {
		Signup         framework.Endpoint[EmailSignupRequest, EmailSignupResponse]
		Login          framework.Endpoint[EmailLoginRequest, EmailLoginResponse]
		ForgotPassword framework.Endpoint[EmailForgotPasswordRequest, bool]
		ResetPassword  framework.Endpoint[EmailResetPasswordRequest, bool]
		Logout         framework.Endpoint[LogoutRequest, bool]
	}

	EmailSignupRequest struct {
		Email    string `json:"email" form:"email" validate:"required|email|realEmail" filter:"sanitizeEmail" label:"Email address"`
		Password string `json:"password" form:"password" validate:"required|password" label:"Password"`
	}

	EmailSignupResponse struct {
		UserID string `json:"user_id"`
	}

	EmailLoginRequest struct {
		Email    string `json:"email" form:"email" validate:"required|email|realEmail" filter:"sanitizeEmail" label:"Email address"`
		Password string `json:"password" form:"password" validate:"required|password" label:"Password"`
	}

	EmailLoginResponse struct {
		UserID string `json:"user_id"`
	}

	EmailForgotPasswordRequest struct {
		Email string `json:"email" form:"email" validate:"required|email|realEmail" filter:"sanitizeEmail" label:"Email address"`
	}

	EmailResetPasswordRequest struct {
		Token           string `json:"token" form:"token" validate:"required" message:"Token is required" label:"Token"`
		Password        string `json:"password" form:"password" validate:"required|password" label:"Password"`
		PasswordConfirm string `json:"password_confirmation" form:"password_confirmation" validate:"required|eqField:Password" message:"Passwords do not match" label:"Password confirmation"`
	}

	LogoutRequest struct {
		UserID string `json:"user_id" form:"user_id" validate:"required" label:"User ID"`
	}
)

func NewAuth(svc *auth.EmailService) AuthWithEmailAndPassword {
	return AuthWithEmailAndPassword{
		Signup: framework.ApplyEndpointDecorators(
			makeSignupEndpoint(svc),
			framework.ValidateRequest[EmailSignupRequest, EmailSignupResponse](nil),
		),
		Login: framework.ApplyEndpointDecorators(
			makeLoginEndpoint(svc),
			framework.ValidateRequest[EmailLoginRequest, EmailLoginResponse](nil),
		),
		ForgotPassword: framework.ApplyEndpointDecorators(
			makeForgotPasswordEndpoint(svc),
			framework.ValidateRequest[EmailForgotPasswordRequest, bool](nil),
		),
		ResetPassword: framework.ApplyEndpointDecorators(
			makeResetPasswordEndpoint(svc),
			framework.ValidateRequest[EmailResetPasswordRequest, bool](nil),
		),
		Logout: framework.ApplyEndpointDecorators(
			makeLogoutEndpoint(svc),
			framework.ValidateRequest[LogoutRequest, bool](nil),
		),
	}
}

func makeSignupEndpoint(_ *auth.EmailService) framework.Endpoint[EmailSignupRequest, EmailSignupResponse] {
	return func(ctx context.Context, req EmailSignupRequest) (EmailSignupResponse, error) {
		return EmailSignupResponse{}, nil
	}
}

func makeLoginEndpoint(_ *auth.EmailService) framework.Endpoint[EmailLoginRequest, EmailLoginResponse] {
	return func(ctx context.Context, req EmailLoginRequest) (EmailLoginResponse, error) {
		return EmailLoginResponse{}, nil
	}
}

func makeForgotPasswordEndpoint(_ *auth.EmailService) framework.Endpoint[EmailForgotPasswordRequest, bool] {
	return func(ctx context.Context, req EmailForgotPasswordRequest) (bool, error) {
		return true, nil
	}
}

func makeResetPasswordEndpoint(_ *auth.EmailService) framework.Endpoint[EmailResetPasswordRequest, bool] {
	return func(ctx context.Context, req EmailResetPasswordRequest) (bool, error) {
		return true, nil
	}
}

func makeLogoutEndpoint(_ *auth.EmailService) framework.Endpoint[LogoutRequest, bool] {
	return func(ctx context.Context, req LogoutRequest) (bool, error) {
		return true, nil
	}
}
