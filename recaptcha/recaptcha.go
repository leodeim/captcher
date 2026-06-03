// Package recaptcha provides Google reCAPTCHA v2 and v3 verification.
package recaptcha

import (
	"context"
	"fmt"

	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/internal/verify"
)

const defaultVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

// verifier implements captcher.Verifier for reCAPTCHA.
type verifier struct {
	cfg verify.Config
}

// NewV2 creates a reCAPTCHA v2 verifier; it panics if secret is empty.
func NewV2(secret string, options ...captcher.Option) captcher.Verifier {
	if secret == "" {
		panic("captcha: recaptcha secret is required")
	}
	opts := captcher.DefaultOptions()
	captcher.ApplyOptions(opts, options)
	return &verifier{
		cfg: verify.Config{
			Secret:    secret,
			VerifyURL: defaultVerifyURL,
			Client:    opts.GetHTTPClient(),
			Provider:  captcher.ProviderRecaptchaV2,
			Opts:      opts,
		},
	}
}

// NewV3 creates a reCAPTCHA v3 verifier; it panics if secret is empty.
func NewV3(secret string, options ...captcher.Option) captcher.Verifier {
	if secret == "" {
		panic("captcha: recaptcha secret is required")
	}
	opts := captcher.DefaultOptions()
	captcher.ApplyOptions(opts, options)
	return &verifier{
		cfg: verify.Config{
			Secret:    secret,
			VerifyURL: defaultVerifyURL,
			Client:    opts.GetHTTPClient(),
			Provider:  captcher.ProviderRecaptchaV3,
			Opts:      opts,
		},
	}
}

func (v *verifier) Provider() captcher.Provider {
	return v.cfg.Provider
}

func (v *verifier) Verify(ctx context.Context, req captcher.VerifyRequest) (*captcher.VerifyResponse, error) {
	raw, result, err := verify.Do(ctx, &v.cfg, req)
	if err != nil {
		return result, err
	}

	// v3-specific: score threshold check
	if v.cfg.Provider == captcher.ProviderRecaptchaV3 {
		if raw.Score < v.cfg.Opts.ScoreThreshold {
			result.Success = false
			return result, fmt.Errorf("%w: score %.2f < threshold %.2f",
				captcher.ErrScoreTooLow, raw.Score, v.cfg.Opts.ScoreThreshold)
		}
	}

	return result, nil
}

// setVerifyURL is used by tests to override the verification endpoint.
func (v *verifier) setVerifyURL(url string) {
	v.cfg.VerifyURL = url
}
