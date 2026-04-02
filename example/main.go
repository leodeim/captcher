package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/middleware/stdhttp"
	"github.com/leodeim/captcher/recaptcha"
	"github.com/leodeim/captcher/turnstile"
)

func main() {
	// -------------------------------------------------------
	// Example 1: Direct verification (no middleware)
	// -------------------------------------------------------
	directVerification()

	// -------------------------------------------------------
	// Example 2: net/http middleware
	// -------------------------------------------------------
	stdHTTPServer()
}

func directVerification() {
	// --- reCAPTCHA v2 ---
	v2 := recaptcha.NewV2("your-recaptcha-v2-secret")
	resp, err := v2.Verify(context.Background(), captcher.VerifyRequest{
		Token:    "token-from-client",
		RemoteIP: "1.2.3.4",
	})
	fmt.Printf("reCAPTCHA v2: success=%v, err=%v\n", resp != nil && resp.Success, err)

	// --- reCAPTCHA v3 with score threshold ---
	v3 := recaptcha.NewV3("your-recaptcha-v3-secret",
		captcher.WithScoreThreshold(0.7),
		captcher.WithExpectedAction("login"),
	)
	resp, err = v3.Verify(context.Background(), captcher.VerifyRequest{
		Token: "token-from-client",
	})
	fmt.Printf("reCAPTCHA v3: success=%v, score=%v, err=%v\n",
		resp != nil && resp.Success, resp != nil && resp.Score > 0, err)

	// --- Cloudflare Turnstile ---
	ts := turnstile.New("your-turnstile-secret",
		captcher.WithExpectedHostname("example.com"),
	)
	resp, err = ts.Verify(context.Background(), captcher.VerifyRequest{
		Token: "token-from-client",
	})
	fmt.Printf("Turnstile: success=%v, err=%v\n", resp != nil && resp.Success, err)
}

func stdHTTPServer() {
	// Pick your provider — swap providers without changing application code.
	// In a real app, these would come from environment variables or config.
	verifier := providerFromConfig("turnstile", "your-turnstile-secret")

	// Configure middleware
	cfg := captcher.DefaultMiddlewareConfig(verifier)
	cfg.SkipPaths = []string{"/health", "/ready"}
	cfg.IPHeader = "X-Forwarded-For"

	mux := http.NewServeMux()

	// Public endpoints (captcha protected)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Access verification result from context (works with any middleware)
		resp := captcher.FromContext(r.Context())
		fmt.Fprintf(w, "Login successful! Provider: %s\n", resp.Provider)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Wrap with captcha middleware
	handler := stdhttp.Middleware(cfg)(mux)

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// Example: Swapping providers at runtime based on config
func providerFromConfig(provider, secret string) captcher.Verifier {
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
