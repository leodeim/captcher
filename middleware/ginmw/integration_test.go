//go:build integration

package ginmw_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/middleware/ginmw"
	"github.com/leodeim/captcher/turnstile"
)

const (
	turnstilePassSecret = "1x0000000000000000000000000000000AA"
	turnstileFailSecret = "2x0000000000000000000000000000000AA"
	dummyToken          = "XXXX.DUMMY.TOKEN.XXXX"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestIntegration_Gin_Success(t *testing.T) {
	v := turnstile.New(turnstilePassSecret)
	cfg := captcher.DefaultMiddlewareConfig(v)

	var ctxResp *captcher.VerifyResponse
	r := gin.New()
	r.Use(ginmw.Middleware(cfg))
	r.POST("/submit", func(c *gin.Context) {
		ctxResp = ginmw.VerifyResponseFromContext(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", dummyToken)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ctxResp == nil {
		t.Fatal("expected VerifyResponse in context")
	}
	if !ctxResp.Success {
		t.Errorf("expected Success=true; error codes: %v", ctxResp.ErrorCodes)
	}
	if ctxResp.Provider != captcher.ProviderTurnstile {
		t.Errorf("provider = %v, want %v", ctxResp.Provider, captcher.ProviderTurnstile)
	}
}

func TestIntegration_Gin_Failure(t *testing.T) {
	v := turnstile.New(turnstileFailSecret)
	cfg := captcher.DefaultMiddlewareConfig(v)

	handlerCalled := false
	r := gin.New()
	r.Use(ginmw.Middleware(cfg))
	r.POST("/submit", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", dummyToken)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if handlerCalled {
		t.Error("handler should not be called on verification failure")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected error message in response body")
	}
}

func TestIntegration_Gin_Optional(t *testing.T) {
	v := turnstile.New(turnstileFailSecret)
	cfg := captcher.DefaultMiddlewareConfig(v)
	cfg.Optional = true

	var ctxResp *captcher.VerifyResponse
	handlerCalled := false
	r := gin.New()
	r.Use(ginmw.Middleware(cfg))
	r.POST("/submit", func(c *gin.Context) {
		handlerCalled = true
		ctxResp = ginmw.VerifyResponseFromContext(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("X-Captcha-Token", dummyToken)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called in optional mode")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ctxResp == nil {
		t.Fatal("expected VerifyResponse in context even on failure")
	}
	if ctxResp.Success {
		t.Error("expected Success=false (fail secret)")
	}
}

func TestIntegration_Gin_SkipPath(t *testing.T) {
	v := turnstile.New(turnstileFailSecret)
	cfg := captcher.DefaultMiddlewareConfig(v)
	cfg.SkipPaths = []string{"/health"}

	handlerCalled := false
	r := gin.New()
	r.Use(ginmw.Middleware(cfg))
	r.GET("/health", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("handler should be called for skipped path")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestIntegration_Gin_MissingToken(t *testing.T) {
	v := turnstile.New(turnstilePassSecret)
	cfg := captcher.DefaultMiddlewareConfig(v)

	handlerCalled := false
	r := gin.New()
	r.Use(ginmw.Middleware(cfg))
	r.POST("/submit", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if handlerCalled {
		t.Error("handler should not be called when token is missing")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestIntegration_Gin_TokenFromQuery(t *testing.T) {
	v := turnstile.New(turnstilePassSecret)
	cfg := captcher.DefaultMiddlewareConfig(v)

	r := gin.New()
	r.Use(ginmw.Middleware(cfg))
	r.POST("/submit", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/submit?captcha_token="+dummyToken, nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
