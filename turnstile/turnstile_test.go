package turnstile

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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(response)
	}))
}

func newTestVerifier(secret string, serverURL string, opts ...captcher.Option) captcher.Verifier {
	v := New(secret, opts...).(*verifier)
	v.setVerifyURL(serverURL)
	return v
}

// --- Provider Test ---

func TestProvider(t *testing.T) {
	v := New("secret")
	if v.Provider() != captcher.ProviderTurnstile {
		t.Errorf("got %v, want %v", v.Provider(), captcher.ProviderTurnstile)
	}
}

// --- Empty Token ---

func TestEmptyToken(t *testing.T) {
	v := New("secret")
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{})
	if !errors.Is(err, captcher.ErrMissingToken) {
		t.Errorf("got %v, want %v", err, captcher.ErrMissingToken)
	}
}

// --- Verification Tests ---

func TestSuccess(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:     true,
		ChallengeTS: "2024-01-15T10:30:00Z",
		Hostname:    "example.com",
		Action:      "login",
		CData:       "customer-data-123",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL)
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
	if resp.Action != "login" {
		t.Errorf("action = %q, want %q", resp.Action, "login")
	}
	if resp.CData != "customer-data-123" {
		t.Errorf("cdata = %q, want %q", resp.CData, "customer-data-123")
	}
	if resp.Provider != captcher.ProviderTurnstile {
		t.Errorf("provider = %v, want %v", resp.Provider, captcher.ProviderTurnstile)
	}
	expectedTS := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	if !resp.ChallengeTS.Equal(expectedTS) {
		t.Errorf("ChallengeTS = %v, want %v", resp.ChallengeTS, expectedTS)
	}
}

func TestFailure(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:    false,
		ErrorCodes: []string{"invalid-input-response"},
	}, http.StatusOK)
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL)
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
}

func TestHostnameMismatch(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success:  true,
		Hostname: "evil.com",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL, captcher.WithExpectedHostname("example.com"))
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrVerifyFailed) {
		t.Errorf("got %v, want %v", err, captcher.ErrVerifyFailed)
	}
	if resp.Success {
		t.Error("expected failure on hostname mismatch")
	}
}

func TestActionMismatch(t *testing.T) {
	srv := mockServer(t, verify.ProviderResponse{
		Success: true,
		Action:  "signup",
	}, http.StatusOK)
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL, captcher.WithExpectedAction("login"))
	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrVerifyFailed) {
		t.Errorf("got %v, want %v", err, captcher.ErrVerifyFailed)
	}
	if resp.Success {
		t.Error("expected failure on action mismatch")
	}
}

// --- Error Handling ---

func TestEmptySecret_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty secret")
		}
	}()
	New("")
}

func TestServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL)
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrHTTPRequest) {
		t.Errorf("got %v, want %v", err, captcher.ErrHTTPRequest)
	}
}

func TestInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL)
	_, err := v.Verify(context.Background(), captcher.VerifyRequest{Token: "token"})
	if !errors.Is(err, captcher.ErrInvalidResponse) {
		t.Errorf("got %v, want %v", err, captcher.ErrInvalidResponse)
	}
}

func TestCancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	v := newTestVerifier("secret", srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := v.Verify(ctx, captcher.VerifyRequest{Token: "token"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}
