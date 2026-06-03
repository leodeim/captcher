// Package captcher provides a unified CAPTCHA verification interface for reCAPTCHA v2/v3 and Cloudflare Turnstile.
package captcher

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Provider identifies the CAPTCHA service.
type Provider string

const (
	ProviderRecaptchaV2 Provider = "recaptcha_v2"
	ProviderRecaptchaV3 Provider = "recaptcha_v3"
	ProviderTurnstile   Provider = "turnstile"
)

// Common errors returned by verifiers.
var (
	ErrMissingToken    = errors.New("captcha: token is empty")
	ErrVerifyFailed    = errors.New("captcha: verification failed")
	ErrScoreTooLow     = errors.New("captcha: score below threshold")
	ErrHTTPRequest     = errors.New("captcha: http request failed")
	ErrInvalidResponse = errors.New("captcha: invalid response from provider")
	ErrTimeout         = errors.New("captcha: verification timed out")
)

// VerifyRequest contains the parameters for a CAPTCHA verification.
type VerifyRequest struct {
	// Token is the CAPTCHA response token from the client.
	Token string

	// RemoteIP is the optional IP address of the user (improves verification accuracy).
	RemoteIP string
}

// VerifyResponse contains the result of a CAPTCHA verification.
type VerifyResponse struct {
	Success     bool
	Score       float64
	Action      string
	Hostname    string
	ChallengeTS time.Time
	ErrorCodes  []string
	CData       string
	Provider    Provider
}

// Verifier is the core interface for CAPTCHA verification.
type Verifier interface {
	// Verify checks a CAPTCHA token and returns the result.
	Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error)

	// Provider returns the provider type.
	Provider() Provider
}

// Option is a functional option for configuring verifiers.
type Option func(*Options)

// Options holds common configuration for verifiers.
type Options struct {
	HTTPClient       *http.Client
	Timeout          time.Duration
	ScoreThreshold   float64
	ExpectedAction   string
	ExpectedHostname string
}

// DefaultOptions returns options with sensible defaults.
func DefaultOptions() *Options {
	return &Options{
		Timeout:        10 * time.Second,
		ScoreThreshold: 0.5,
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(o *Options) {
		o.HTTPClient = client
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.Timeout = d
	}
}

// WithScoreThreshold sets the minimum score for reCAPTCHA v3.
func WithScoreThreshold(threshold float64) Option {
	return func(o *Options) {
		o.ScoreThreshold = threshold
	}
}

// WithExpectedAction sets the expected action (reCAPTCHA v3 and Turnstile).
func WithExpectedAction(action string) Option {
	return func(o *Options) {
		o.ExpectedAction = action
	}
}

// WithExpectedHostname sets the expected hostname for verification.
func WithExpectedHostname(hostname string) Option {
	return func(o *Options) {
		o.ExpectedHostname = hostname
	}
}

// ApplyOptions applies functional options to an Options struct.
func ApplyOptions(opts *Options, options []Option) {
	for _, opt := range options {
		opt(opts)
	}
}

// GetHTTPClient returns the configured HTTP client or a default one.
func (o *Options) GetHTTPClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{
		Timeout: o.Timeout,
	}
}
