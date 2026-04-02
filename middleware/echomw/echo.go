// Package echomw provides Echo middleware for CAPTCHA verification.
package echomw

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/leodeim/captcher"
)

// Middleware returns an Echo middleware handler that verifies CAPTCHA tokens.
func Middleware(cfg *captcher.MiddlewareConfig) echo.MiddlewareFunc {
	if cfg == nil {
		panic("captcha: middleware config is nil")
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check skip paths
			for _, path := range cfg.SkipPaths {
				if c.Path() == path || c.Request().URL.Path == path {
					return next(c)
				}
			}

			token := extractToken(c, cfg)
			remoteIP := extractIP(c, cfg)

			resp, err := cfg.Verifier.Verify(c.Request().Context(), captcher.VerifyRequest{
				Token:    token,
				RemoteIP: remoteIP,
			})

			// Store in request context for consistency across all middleware
			ctx := captcher.NewContext(c.Request().Context(), resp)
			c.SetRequest(c.Request().WithContext(ctx))

			if err != nil {
				if cfg.Optional {
					return next(c)
				}
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": err.Error(),
				})
			}

			return next(c)
		}
	}
}

// VerifyResponseFromContext retrieves the CAPTCHA verification response from the Echo context.
func VerifyResponseFromContext(c echo.Context) *captcher.VerifyResponse {
	return captcher.FromContext(c.Request().Context())
}

func extractToken(c echo.Context, cfg *captcher.MiddlewareConfig) string {
	// 1. Try header
	if cfg.TokenHeader != "" {
		if token := c.Request().Header.Get(cfg.TokenHeader); token != "" {
			return token
		}
	}

	// 2. Try form field
	if cfg.TokenFormField != "" {
		if token := c.FormValue(cfg.TokenFormField); token != "" {
			return token
		}
	}

	// 3. Try query param
	if cfg.TokenQueryParam != "" {
		if token := c.QueryParam(cfg.TokenQueryParam); token != "" {
			return token
		}
	}

	return ""
}

func extractIP(c echo.Context, cfg *captcher.MiddlewareConfig) string {
	if cfg.IPHeader != "" {
		if ip := c.Request().Header.Get(cfg.IPHeader); ip != "" {
			return ip
		}
	}
	// Echo's RealIP handles X-Forwarded-For, X-Real-IP, and falls back to RemoteAddr.
	return c.RealIP()
}
