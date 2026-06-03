// Command example demonstrates the captcher library: direct verification with
// the core module, and the three HTTP middleware adapters (net/http, Gin, Echo).
//
// The core module (github.com/leodeim/captcher) has zero third-party
// dependencies. The Gin and Echo adapters live in their own modules, so this
// example — which exercises all of them — is itself a separate module (see
// example/go.mod). A real application would only depend on the adapter it uses.
//
// Run it and pick a framework with the FRAMEWORK env var:
//
//	go run .                 # net/http (default)
//	FRAMEWORK=gin  go run .
//	FRAMEWORK=echo go run .
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"

	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/middleware/echomw"
	"github.com/leodeim/captcher/middleware/ginmw"
	"github.com/leodeim/captcher/middleware/stdhttp"
	"github.com/leodeim/captcher/recaptcha"
	"github.com/leodeim/captcher/turnstile"
)

func main() {
	// Always show direct (no-middleware) verification first.
	directVerification()

	// Then start an HTTP server using the chosen framework's middleware.
	switch os.Getenv("FRAMEWORK") {
	case "gin":
		ginServer()
	case "echo":
		echoServer()
	default:
		stdHTTPServer()
	}
}

// -------------------------------------------------------------------------
// Core module: direct verification, no middleware.
// -------------------------------------------------------------------------

func directVerification() {
	// reCAPTCHA v2.
	v2 := recaptcha.NewV2("your-recaptcha-v2-secret")
	resp, err := v2.Verify(context.Background(), captcher.VerifyRequest{
		Token:    "token-from-client",
		RemoteIP: "1.2.3.4",
	})
	fmt.Printf("reCAPTCHA v2: success=%v, err=%v\n", resp != nil && resp.Success, err)

	// reCAPTCHA v3 with a score threshold and expected action.
	v3 := recaptcha.NewV3("your-recaptcha-v3-secret",
		captcher.WithScoreThreshold(0.7),
		captcher.WithExpectedAction("login"),
	)
	resp, err = v3.Verify(context.Background(), captcher.VerifyRequest{
		Token: "token-from-client",
	})
	fmt.Printf("reCAPTCHA v3: success=%v, score=%v, err=%v\n",
		resp != nil && resp.Success, resp != nil && resp.Score > 0, err)

	// Cloudflare Turnstile.
	ts := turnstile.New("your-turnstile-secret",
		captcher.WithExpectedHostname("example.com"),
	)
	resp, err = ts.Verify(context.Background(), captcher.VerifyRequest{
		Token: "token-from-client",
	})
	fmt.Printf("Turnstile: success=%v, err=%v\n", resp != nil && resp.Success, err)
}

// newVerifier builds a verifier from config. Swapping providers is a one-line
// change — the rest of the application (and middleware) is provider-agnostic.
func newVerifier(provider, secret string) captcher.Verifier {
	switch provider {
	case "recaptcha_v2":
		return recaptcha.NewV2(secret)
	case "recaptcha_v3":
		return recaptcha.NewV3(secret, captcher.WithScoreThreshold(0.5))
	case "turnstile":
		return turnstile.New(secret)
	default:
		panic("unknown provider: " + provider)
	}
}

// sharedConfig is the middleware configuration reused by every framework below,
// proving the config type is identical across adapters.
func sharedConfig() *captcher.MiddlewareConfig {
	// In a real app the provider and secret come from env/config.
	verifier := newVerifier("turnstile", "your-turnstile-secret")

	cfg := captcher.DefaultMiddlewareConfig(verifier)
	cfg.SkipPaths = []string{"/health", "/ready"} // not captcha-protected
	cfg.IPHeader = "X-Forwarded-For"
	return cfg
}

// -------------------------------------------------------------------------
// net/http middleware (lives in the core module — zero extra dependencies).
// -------------------------------------------------------------------------

func stdHTTPServer() {
	cfg := sharedConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		resp := stdhttp.VerifyResponseFromContext(r.Context())
		fmt.Fprintf(w, "Login OK via net/http. Provider: %s\n", resp.Provider)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	handler := stdhttp.Middleware(cfg)(mux)

	log.Println("net/http server on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// -------------------------------------------------------------------------
// Gin middleware (separate module: github.com/leodeim/captcher/middleware/ginmw).
// -------------------------------------------------------------------------

func ginServer() {
	cfg := sharedConfig()

	r := gin.New()
	r.Use(ginmw.Middleware(cfg))

	r.POST("/login", func(c *gin.Context) {
		resp := ginmw.VerifyResponseFromContext(c)
		c.String(http.StatusOK, "Login OK via Gin. Provider: %s\n", resp.Provider)
	})
	r.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	log.Println("Gin server on :8080")
	log.Fatal(r.Run(":8080"))
}

// -------------------------------------------------------------------------
// Echo middleware (separate module: github.com/leodeim/captcher/middleware/echomw).
// -------------------------------------------------------------------------

func echoServer() {
	cfg := sharedConfig()

	e := echo.New()
	e.Use(echomw.Middleware(cfg))

	e.POST("/login", func(c echo.Context) error {
		resp := echomw.VerifyResponseFromContext(c)
		return c.String(http.StatusOK, fmt.Sprintf("Login OK via Echo. Provider: %s\n", resp.Provider))
	})
	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	log.Println("Echo server on :8080")
	log.Fatal(e.Start(":8080"))
}
