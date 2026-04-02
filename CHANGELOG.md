# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-02

### Added

- Core `captcher.Verifier` interface for unified CAPTCHA verification
- Google reCAPTCHA v2 provider (`recaptcha.NewV2`)
- Google reCAPTCHA v3 provider (`recaptcha.NewV3`) with score threshold and action validation
- Cloudflare Turnstile provider (`turnstile.New`) with CData support
- HTTP middleware for net/http (`middleware/stdhttp`)
- HTTP middleware for Gin (`middleware/ginmw`)
- HTTP middleware for Echo (`middleware/echomw`)
- Functional options: `WithHTTPClient`, `WithTimeout`, `WithScoreThreshold`, `WithExpectedAction`, `WithExpectedHostname`
- Context propagation via `captcher.NewContext()` / `captcher.FromContext()`
- Sentinel errors compatible with `errors.Is()`: `ErrMissingToken`, `ErrVerifyFailed`, `ErrScoreTooLow`, `ErrHTTPRequest`, `ErrInvalidResponse`, `ErrTimeout`
- Fail-fast validation: constructors panic on empty secret, middleware panics on nil config/verifier
- 61 unit tests and 39 integration tests against real provider APIs
- Makefile with build, test, lint, coverage, and CI targets
- GitHub Actions CI workflow

[0.1.0]: https://github.com/leodeim/captcher/releases/tag/v0.1.0
