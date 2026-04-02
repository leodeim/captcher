package stdhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodeim/captcher"
)

// mockVerifier implements captcher.Verifier for testing.
type mockVerifier struct {
	resp *captcher.VerifyResponse
	err  error
}

func (m *mockVerifier) Verify(_ context.Context, _ captcher.VerifyRequest) (*captcher.VerifyResponse, error) {
	return m.resp, m.err
}

func (m *mockVerifier) Provider() captcher.Provider {
	return captcher.ProviderRecaptchaV2
}

func TestMiddleware_Success(t *testing.T) {
	v := &mockVerifier{
		resp: &captcher.VerifyResponse{Success: true},
	}
	cfg := captcher.DefaultMiddlewareConfig(v)

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := VerifyResponseFromContext(r.Context())
		if resp == nil {
			t.Error("expected response in context")
		}
		if !resp.Success {
			t.Error("expected success")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Captcha-Token", "valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_Failure(t *testing.T) {
	v := &mockVerifier{
		resp: &captcher.VerifyResponse{Success: false},
		err:  captcher.ErrVerifyFailed,
	}
	cfg := captcher.DefaultMiddlewareConfig(v)

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Captcha-Token", "bad-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected error in response body")
	}
}

func TestMiddleware_Optional(t *testing.T) {
	v := &mockVerifier{
		resp: &captcher.VerifyResponse{Success: false},
		err:  captcher.ErrVerifyFailed,
	}
	cfg := captcher.DefaultMiddlewareConfig(v)
	cfg.Optional = true

	called := false
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Captcha-Token", "bad-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("handler should be called when optional")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// panicVerifier panics if Verify is called, used to assert skip paths work.
type panicVerifier struct{}

func (p *panicVerifier) Verify(_ context.Context, _ captcher.VerifyRequest) (*captcher.VerifyResponse, error) {
	panic("Verify should not be called for skipped paths")
}

func (p *panicVerifier) Provider() captcher.Provider {
	return captcher.ProviderRecaptchaV2
}

func TestMiddleware_SkipPaths(t *testing.T) {
	cfg := captcher.DefaultMiddlewareConfig(&panicVerifier{})
	cfg.SkipPaths = []string{"/health", "/ready"}

	called := false
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("handler should be called for skipped paths")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_MissingToken(t *testing.T) {
	v := &mockVerifier{
		err: captcher.ErrMissingToken,
	}
	cfg := captcher.DefaultMiddlewareConfig(v)

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddleware_TokenFromFormField(t *testing.T) {
	v := &mockVerifier{
		resp: &captcher.VerifyResponse{Success: true},
	}
	cfg := captcher.DefaultMiddlewareConfig(v)

	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/?captcha_token=form-token", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_NilConfig_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil config")
		}
	}()
	Middleware(nil)
}

func TestMiddleware_NilVerifier_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil verifier")
		}
	}()
	Middleware(&captcher.MiddlewareConfig{})
}

func TestVerifyResponseFromContext_Missing(t *testing.T) {
	resp := VerifyResponseFromContext(context.Background())
	if resp != nil {
		t.Error("expected nil for missing context value")
	}
}
