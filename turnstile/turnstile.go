// Package turnstile provides Cloudflare Turnstile verification.
package turnstile

import (
	"context"

	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/internal/verify"
)

const defaultVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// verifier implements captcher.Verifier for Turnstile.
type verifier struct {
	cfg verify.Config
}

// New creates a Cloudflare Turnstile verifier; it panics if secret is empty.
func New(secret string, options ...captcher.Option) captcher.Verifier {
	if secret == "" {
		panic("captcha: turnstile secret is required")
	}
	opts := captcher.DefaultOptions()
	captcher.ApplyOptions(opts, options)
	return &verifier{
		cfg: verify.Config{
			Secret:    secret,
			VerifyURL: defaultVerifyURL,
			Client:    opts.GetHTTPClient(),
			Provider:  captcher.ProviderTurnstile,
			Opts:      opts,
		},
	}
}

func (v *verifier) Provider() captcher.Provider {
	return captcher.ProviderTurnstile
}

func (v *verifier) Verify(ctx context.Context, req captcher.VerifyRequest) (*captcher.VerifyResponse, error) {
	_, result, err := verify.Do(ctx, &v.cfg, req)
	return result, err
}

// setVerifyURL is used by tests to override the verification endpoint.
func (v *verifier) setVerifyURL(url string) {
	v.cfg.VerifyURL = url
}
