package echomw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
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

// panicVerifier panics if Verify is called, used to assert skip paths work.
type panicVerifier struct{}

func (p *panicVerifier) Verify(_ context.Context, _ captcher.VerifyRequest) (*captcher.VerifyResponse, error) {
	panic("Verify should not be called for skipped paths")
}

func (p *panicVerifier) Provider() captcher.Provider {
	return captcher.ProviderRecaptchaV2
}

// newEcho creates an echo.Echo with the captcha middleware and a test handler.
func newEcho(cfg *captcher.MiddlewareConfig, method, path string, handler echo.HandlerFunc) *echo.Echo {
	e := echo.New()
	e.Use(Middleware(cfg))
	switch method {
	case http.MethodGet:
		e.GET(path, handler)
	default:
		e.POST(path, handler)
	}
	return e
}

func TestMiddleware_Success(t *testing.T) {
	v := &mockVerifier{
		resp: &captcher.VerifyResponse{Success: true, Provider: captcher.ProviderRecaptchaV2},
	}
	cfg := captcher.DefaultMiddlewareConfig(v)

	e := newEcho(cfg, http.MethodPost, "/submit", func(c echo.Context) error {
		resp := VerifyResponseFromContext(c)
		if resp == nil {
			t.Error("expected response in context")
			return nil
		}
		if !resp.Success {
			t.Error("expected success")
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", "valid-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
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

	handlerCalled := false
	e := newEcho(cfg, http.MethodPost, "/submit", func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", "bad-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
	if handlerCalled {
		t.Error("handler should not be called on failure")
	}
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
	e := newEcho(cfg, http.MethodPost, "/submit", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", "bad-token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
	if !called {
		t.Error("handler should be called when optional")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_SkipPaths(t *testing.T) {
	cfg := captcher.DefaultMiddlewareConfig(&panicVerifier{})
	cfg.SkipPaths = []string{"/health", "/ready"}

	called := false
	e := newEcho(cfg, http.MethodGet, "/health", func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
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

	handlerCalled := false
	e := newEcho(cfg, http.MethodPost, "/submit", func(c echo.Context) error {
		handlerCalled = true
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
	if handlerCalled {
		t.Error("handler should not be called")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddleware_TokenFromQuery(t *testing.T) {
	v := &mockVerifier{
		resp: &captcher.VerifyResponse{Success: true},
	}
	cfg := captcher.DefaultMiddlewareConfig(v)

	e := newEcho(cfg, http.MethodPost, "/submit", func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit?captcha_token=query-token", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
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
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	resp := VerifyResponseFromContext(c)
	if resp != nil {
		t.Error("expected nil for missing context value")
	}
}

func TestMiddleware_ContextPropagation(t *testing.T) {
	expected := &captcher.VerifyResponse{
		Success:  true,
		Provider: captcher.ProviderTurnstile,
	}
	v := &mockVerifier{resp: expected}
	cfg := captcher.DefaultMiddlewareConfig(v)

	e := newEcho(cfg, http.MethodPost, "/submit", func(c echo.Context) error {
		// Verify response is accessible via the helper
		resp := VerifyResponseFromContext(c)
		if resp == nil {
			t.Fatal("expected response from VerifyResponseFromContext")
		}
		if resp.Provider != captcher.ProviderTurnstile {
			t.Errorf("provider = %v, want %v", resp.Provider, captcher.ProviderTurnstile)
		}

		// Also accessible via captcher.FromContext on raw request context
		resp2 := captcher.FromContext(c.Request().Context())
		if resp2 == nil {
			t.Fatal("expected response from captcher.FromContext")
		}
		if resp2 != resp {
			t.Error("expected same response from both context accessors")
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", "token")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
