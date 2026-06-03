package captcher

import (
	"context"
	"fmt"
)

// MiddlewareConfig holds configuration for CAPTCHA middleware.
type MiddlewareConfig struct {
	Verifier        Verifier
	TokenHeader     string
	TokenFormField  string
	TokenQueryParam string
	IPHeader        string
	SkipPaths       []string
	Optional        bool
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

// contextKey is an unexported context-key type that prevents collisions.
type contextKey struct{}

// ctxKey is the singleton context key for CAPTCHA verification results.
var ctxKey = contextKey{}

// NewContext returns a new context with the VerifyResponse stored in it.
func NewContext(ctx context.Context, resp *VerifyResponse) context.Context {
	return context.WithValue(ctx, ctxKey, resp)
}

// FromContext returns the VerifyResponse stored in ctx, or nil if none.
func FromContext(ctx context.Context) *VerifyResponse {
	resp, _ := ctx.Value(ctxKey).(*VerifyResponse)
	return resp
}
