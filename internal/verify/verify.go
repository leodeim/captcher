// Package verify holds the shared site-verify HTTP logic for the reCAPTCHA and Turnstile providers.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/leodeim/captcher"
)

// maxResponseBytes is the maximum size of a verification response body (1 MB).
const maxResponseBytes = 1 << 20

// ProviderResponse is the raw JSON shared by the reCAPTCHA and Turnstile site-verify endpoints.
type ProviderResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	CData       string   `json:"cdata"`
}

// Config holds the parameters needed to perform a site-verify call.
type Config struct {
	Secret    string
	VerifyURL string
	Client    *http.Client
	Provider  captcher.Provider
	Opts      *captcher.Options
}

// Do runs the site-verify POST and applies common hostname/action checks; provider checks are left to callers.
func Do(ctx context.Context, cfg *Config, req captcher.VerifyRequest) (*ProviderResponse, *captcher.VerifyResponse, error) {
	if req.Token == "" {
		return nil, nil, captcher.ErrMissingToken
	}

	form := url.Values{
		"secret":   {cfg.Secret},
		"response": {req.Token},
	}
	if req.RemoteIP != "" {
		form.Set("remoteip", req.RemoteIP)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.VerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", captcher.ErrHTTPRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cfg.Client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("%w: %v", captcher.ErrTimeout, err)
		}
		return nil, nil, fmt.Errorf("%w: %v", captcher.ErrHTTPRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failed to read response body: %v", captcher.ErrHTTPRequest, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: status %d: %s", captcher.ErrHTTPRequest, resp.StatusCode, string(body))
	}

	var siteResp ProviderResponse
	if err := json.Unmarshal(body, &siteResp); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", captcher.ErrInvalidResponse, err)
	}

	result := &captcher.VerifyResponse{
		Success:    siteResp.Success,
		Score:      siteResp.Score,
		Action:     siteResp.Action,
		Hostname:   siteResp.Hostname,
		ErrorCodes: siteResp.ErrorCodes,
		Provider:   cfg.Provider,
		CData:      siteResp.CData,
	}

	if siteResp.ChallengeTS != "" {
		if ts, err := time.Parse(time.RFC3339, siteResp.ChallengeTS); err == nil {
			result.ChallengeTS = ts
		}
	}

	if !siteResp.Success {
		return &siteResp, result, captcher.ErrVerifyFailed
	}

	// Hostname check
	if cfg.Opts.ExpectedHostname != "" && siteResp.Hostname != cfg.Opts.ExpectedHostname {
		result.Success = false
		return &siteResp, result, fmt.Errorf("%w: hostname mismatch: got %q, want %q",
			captcher.ErrVerifyFailed, siteResp.Hostname, cfg.Opts.ExpectedHostname)
	}

	// Action check
	if cfg.Opts.ExpectedAction != "" && siteResp.Action != cfg.Opts.ExpectedAction {
		result.Success = false
		return &siteResp, result, fmt.Errorf("%w: action mismatch: got %q, want %q",
			captcher.ErrVerifyFailed, siteResp.Action, cfg.Opts.ExpectedAction)
	}

	return &siteResp, result, nil
}
