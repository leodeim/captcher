package captcher

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", opts.Timeout)
	}
	if opts.ScoreThreshold != 0.5 {
		t.Errorf("threshold = %v, want 0.5", opts.ScoreThreshold)
	}
}

func TestApplyOptions(t *testing.T) {
	opts := DefaultOptions()
	ApplyOptions(opts, []Option{
		WithScoreThreshold(0.9),
		WithExpectedAction("test"),
		WithExpectedHostname("example.com"),
		WithTimeout(30 * time.Second),
	})

	if opts.ScoreThreshold != 0.9 {
		t.Errorf("threshold = %v, want 0.9", opts.ScoreThreshold)
	}
	if opts.ExpectedAction != "test" {
		t.Errorf("action = %q, want %q", opts.ExpectedAction, "test")
	}
	if opts.ExpectedHostname != "example.com" {
		t.Errorf("hostname = %q, want %q", opts.ExpectedHostname, "example.com")
	}
	if opts.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", opts.Timeout)
	}
}

func TestWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}
	opts := DefaultOptions()
	ApplyOptions(opts, []Option{WithHTTPClient(custom)})

	got := opts.GetHTTPClient()
	if got != custom {
		t.Error("expected custom client to be returned")
	}
}

func TestGetHTTPClient_Default(t *testing.T) {
	opts := DefaultOptions()
	client := opts.GetHTTPClient()
	if client == nil {
		t.Fatal("expected non-nil default client")
	}
	if client.Timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", client.Timeout)
	}
}

func TestMiddlewareConfig_Validate(t *testing.T) {
	cfg := &MiddlewareConfig{}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for nil verifier")
	}
}

func TestNewContext_FromContext(t *testing.T) {
	resp := &VerifyResponse{Success: true, Provider: ProviderTurnstile}
	ctx := NewContext(context.Background(), resp)

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil response from context")
	}
	if !got.Success {
		t.Error("expected success")
	}
	if got.Provider != ProviderTurnstile {
		t.Errorf("provider = %v, want %v", got.Provider, ProviderTurnstile)
	}
}

func TestFromContext_Missing(t *testing.T) {
	got := FromContext(context.Background())
	if got != nil {
		t.Error("expected nil from empty context")
	}
}
