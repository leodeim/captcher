// Package stdhttp provides net/http middleware for CAPTCHA verification.
package stdhttp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/leodeim/captcher"
)

// Middleware returns an http.Handler middleware that verifies CAPTCHA tokens.
func Middleware(cfg *captcher.MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		panic("captcha: middleware config is nil")
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check skip paths
			for _, path := range cfg.SkipPaths {
				if r.URL.Path == path {
					next.ServeHTTP(w, r)
					return
				}
			}

			token := extractToken(r, cfg)
			remoteIP := extractIP(r, cfg)

			resp, err := cfg.Verifier.Verify(r.Context(), captcher.VerifyRequest{
				Token:    token,
				RemoteIP: remoteIP,
			})

			// Store result in context regardless of outcome
			ctx := captcher.NewContext(r.Context(), resp)
			r = r.WithContext(ctx)

			if err != nil {
				if cfg.Optional {
					next.ServeHTTP(w, r)
					return
				}
				writeError(w, http.StatusForbidden, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// VerifyResponseFromContext retrieves the CAPTCHA verification response from the request context.
func VerifyResponseFromContext(ctx context.Context) *captcher.VerifyResponse {
	return captcher.FromContext(ctx)
}

func extractToken(r *http.Request, cfg *captcher.MiddlewareConfig) string {
	// 1. Try header
	if cfg.TokenHeader != "" {
		if token := r.Header.Get(cfg.TokenHeader); token != "" {
			return token
		}
	}

	// 2. Try form field
	if cfg.TokenFormField != "" {
		if token := r.FormValue(cfg.TokenFormField); token != "" {
			return token
		}
	}

	// 3. Try query param
	if cfg.TokenQueryParam != "" {
		if token := r.URL.Query().Get(cfg.TokenQueryParam); token != "" {
			return token
		}
	}

	return ""
}

func extractIP(r *http.Request, cfg *captcher.MiddlewareConfig) string {
	if cfg.IPHeader != "" {
		if ip := r.Header.Get(cfg.IPHeader); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}
