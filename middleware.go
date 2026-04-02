package captcher

import (
	"context"
	"fmt"
)

// MiddlewareConfig holds configuration for CAPTCHA middleware.
type MiddlewareConfig struct {
	// Verifier is the CAPTCHA verifier to use.
	Verifier Verifier

	// TokenHeader is the HTTP header name containing the CAPTCHA token.
	// Defaults to "X-Captcha-Token".
	TokenHeader string

	// TokenFormField is the form field name containing the CAPTCHA token.
	// Checked if the header is empty. Note: in net/http and Echo, this also
	// checks query parameters (via FormValue). Defaults to "captcha_token".
	TokenFormField string

	// TokenQueryParam is the query parameter name containing the CAPTCHA token.
	// Checked if header and form field are empty. Defaults to "" (disabled).
	TokenQueryParam string

	// IPHeader is an optional header to read the client IP from (e.g., "X-Forwarded-For").
	// If empty, the request's RemoteAddr is used.
	IPHeader string

	// SkipPaths is a list of exact paths to skip CAPTCHA verification for.
	// Only exact string matches are checked (no prefix or glob matching).
	SkipPaths []string

	// Optional when true, CAPTCHA failure won't block the request.
	// The verification result will still be available in the request context.
	Optional bool
}

// DefaultMiddlewareConfig returns middleware config with sensible defaults.
func DefaultMiddlewareConfig(v Verifier) *MiddlewareConfig {
	return &MiddlewareConfig{
		Verifier:       v,
		TokenHeader:    "X-Captcha-Token",
		TokenFormField: "captcha_token",
	}
}

// Validate checks the middleware config for required fields.
func (c *MiddlewareConfig) Validate() error {
	if c.Verifier == nil {
		return fmt.Errorf("captcha: middleware requires a verifier")
	}
	return nil
}

// contextKey is an unexported type used for storing verification results
// in request context, preventing key collisions.
type contextKey struct{}

// ctxKey is the singleton context key for CAPTCHA verification results.
var ctxKey = contextKey{}

// NewContext returns a new context with the VerifyResponse stored in it.
func NewContext(ctx context.Context, resp *VerifyResponse) context.Context {
	return context.WithValue(ctx, ctxKey, resp)
}

// FromContext retrieves the VerifyResponse from the context.
// Returns nil if no response is stored.
func FromContext(ctx context.Context) *VerifyResponse {
	resp, _ := ctx.Value(ctxKey).(*VerifyResponse)
	return resp
}
