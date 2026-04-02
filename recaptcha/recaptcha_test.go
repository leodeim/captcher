package recaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/internal/verify"
)

func mockServer(t *testing.T, response verify.ProviderResponse, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(response)
	}))
}

func newTestV2(secret string, serverURL string, opts ...captcher.Option) captcher.Verifier {
	v := NewV2(secret, opts...).(*verifier)
	v.setVerifyURL(serverURL)
	return v
}

func newTestV3(secret string, serverURL string, opts ...captcher.Option) captcher.Verifier {
	v := NewV3(secret, opts...).(*verifier)
	v.setVerifyURL(serverURL)
	return v
}

// --- Provider Tests ---

func TestV2_Provider(t *testing.T) {
	v := NewV2("secret")
	if v.Provider() != captcher.ProviderRecaptchaV2 {
		t.Errorf("got %v, want %v", v.Provider(), captcher.ProviderRecaptchaV2)
	}
}

func TestV3_Provider(t *testing.T) {
	v := NewV3("secret")
	if v.Provider() != captcher.ProviderRecaptchaV3 {
		t.Errorf("got %v, want %v", v.Provider(), captcher.ProviderRecaptchaV3)
	}
}

// --- Empty Token Tests ---

func TestV2_EmptyToken(t *testing.T) {
	v := NewV2("secret")
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{})
	if !errors.Is(err, captcher.ErrMissingToken) {
		t.Errorf("got %v, want %v", err, captcher.ErrMissingToken)
	}
}

func TestV3_EmptyToken(t *testing.T) {
	v := NewV3("secret")
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{})
	if !errors.Is(err, captcher.ErrMissingToken) {
		t.Errorf("got %v, want %v", err, captcher.ErrMissingToken)
	}
}

// --- V2 Verification Tests ---

func TestV2_Success(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:     true,
		ChallengeTS: "2024-01-15T10:30:00Z",
		Hostname:    "example.com",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestV2("secret", srv.URL)
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token:    "valid-token",
		RemoteIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
	if resp.Hostname != "example.com" {
		t.Errorf("hostname = %q, want %q", resp.Hostname, "example.com")
	}
	if resp.Provider != captcher.ProviderRecaptchaV2 {
		t.Errorf("provider = %v, want %v", resp.Provider, captcher.ProviderRecaptchaV2)
	}
	expectedTS := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	if !resp.ChallengeTS.Equal(expectedTS) {
		t.Errorf("ChallengeTS = %v, want %v", resp.ChallengeTS, expectedTS)
	}
}

func TestV2_Failure(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:    false,
		ErrorCodes: []string{"invalid-input-response"},
	}, http.StatusOK)
	defer srv.Close()

	v := newTestV2("secret", srv.URL)
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "bad-token"})
	if !errors.Is(err, captcher.ErrVerifyFailed) {
		t.Errorf("got %v, want %v", err, captcher.ErrVerifyFailed)
	}
	if resp == nil {
		t.Fatal("expected response even on failure")
	}
	if resp.Success {
		t.Error("expected failure")
	}
	if len(resp.ErrorCodes) == 0 || resp.ErrorCodes[0] != "invalid-input-response" {
		t.Errorf("error codes = %v, want [invalid-input-response]", resp.ErrorCodes)
	}
}

func TestV2_HostnameMismatch(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:  true,
		Hostname: "evil.com",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestV2("secret", srv.URL, captcher.WithExpectedHostname("example.com"))
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrVerifyFailed) {
		t.Errorf("got %v, want %v", err, captcher.ErrVerifyFailed)
	}
	if resp.Success {
		t.Error("expected failure on hostname mismatch")
	}
}

// --- V3 Verification Tests ---

func TestV3_SuccessAboveThreshold(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:  true,
		Score:    0.9,
		Action:   "login",
		Hostname: "example.com",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestV3("secret", srv.URL,
		captcher.WithScoreThreshold(0.5),
		captcher.WithExpectedAction("login"),
	)
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
	if resp.Score != 0.9 {
		t.Errorf("score = %v, want 0.9", resp.Score)
	}
	if resp.Action != "login" {
		t.Errorf("action = %q, want %q", resp.Action, "login")
	}
}

func TestV3_ScoreBelowThreshold(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success: true,
		Score:   0.3,
		Action:  "login",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestV3("secret", srv.URL, captcher.WithScoreThreshold(0.5))
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrScoreTooLow) {
		t.Errorf("got %v, want %v", err, captcher.ErrScoreTooLow)
	}
	if resp.Success {
		t.Error("expected failure for low score")
	}
}

func TestV3_ActionMismatch(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success: true,
		Score:   0.9,
		Action:  "signup",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestV3("secret", srv.URL,
		captcher.WithScoreThreshold(0.5),
		captcher.WithExpectedAction("login"),
	)
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrVerifyFailed) {
		t.Errorf("got %v, want %v", err, captcher.ErrVerifyFailed)
	}
	if resp.Success {
		t.Error("expected failure on action mismatch")
	}
}

// --- Error Handling Tests ---

func TestV2_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	v := newTestV2("secret", srv.URL)
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrHTTPRequest) {
		t.Errorf("got %v, want %v", err, captcher.ErrHTTPRequest)
	}
}

func TestV2_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	v := newTestV2("secret", srv.URL)
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrInvalidResponse) {
		t.Errorf("got %v, want %v", err, captcher.ErrInvalidResponse)
	}
}

func TestV2_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	v := newTestV2("secret", srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := v.Verify(ctx, captcher.VerifyRequest{Token: "token"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}
