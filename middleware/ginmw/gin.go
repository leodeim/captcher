// Package ginmw provides Gin middleware for CAPTCHA verification.
package ginmw

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/leodeim/captcher"
)

// Middleware returns a Gin middleware handler that verifies CAPTCHA tokens.
func Middleware(cfg *captcher.MiddlewareConfig) gin.HandlerFunc {
	if cfg == nil {
		panic("captcha: middleware config is nil")
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}

	return func(c *gin.Context) {
		// Check skip paths
		for _, path := range cfg.SkipPaths {
			if c.Request.URL.Path == path {
				c.Next()
				return
			}
		}

		token := extractToken(c, cfg)
		remoteIP := extractIP(c, cfg)

		resp, err := cfg.Verifier.Verify(c.Request.Context(), captcher.VerifyRequest{
			Token:    token,
			RemoteIP: remoteIP,
		})

		// Store result in request context regardless of outcome
		ctx := captcher.NewContext(c.Request.Context(), resp)
		c.Request = c.Request.WithContext(ctx)

		if err != nil {
			if cfg.Optional {
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.Next()
	}
}

// VerifyResponseFromContext retrieves the CAPTCHA verification response from the Gin context.
func VerifyResponseFromContext(c *gin.Context) *captcher.VerifyResponse {
	return captcher.FromContext(c.Request.Context())
}

func extractToken(c *gin.Context, cfg *captcher.MiddlewareConfig) string {
	// 1. Try header
	if cfg.TokenHeader != "" {
		if token := c.GetHeader(cfg.TokenHeader); token != "" {
			return token
		}
	}

	// 2. Try form field (Gin's PostForm is POST-only, so also check query to match net/http's FormValue).
	if cfg.TokenFormField != "" {
		if token := c.PostForm(cfg.TokenFormField); token != "" {
			return token
		}
		if token := c.Query(cfg.TokenFormField); token != "" {
			return token
		}
	}

	// 3. Try query param
	if cfg.TokenQueryParam != "" {
		if token := c.Query(cfg.TokenQueryParam); token != "" {
			return token
		}
	}

	return ""
}

func extractIP(c *gin.Context, cfg *captcher.MiddlewareConfig) string {
	if cfg.IPHeader != "" {
		if ip := c.GetHeader(cfg.IPHeader); ip != "" {
			return ip
		}
	}
	// Gin's ClientIP handles X-Forwarded-For, X-Real-IP, and falls back to RemoteAddr.
	return c.ClientIP()
}
