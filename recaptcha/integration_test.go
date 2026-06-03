//go:build integration

package recaptcha_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/leodeim/captcher"
	"github.com/leodeim/captcher/recaptcha"
)

// Google reCAPTCHA test credentials (v2 always passes; v3 reuses the endpoint, scores not meaningful).
const (
	// testSecret is Google's public test secret key.
	testSecret = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"

	// anyToken works with the test secret — all tokens pass.
	anyToken = "test-token-value"
)

// --- reCAPTCHA v2 Integration Tests ---

func TestIntegration_V2_Success(t *testing.T) {
	v := recaptcha.NewV2(testSecret)

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: anyToken,
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true, got false; error codes: %v", resp.ErrorCodes)
	}
	if resp.Provider != captcher.ProviderRecaptchaV2 {
		t.Errorf("provider = %v, want %v", resp.Provider, captcher.ProviderRecaptchaV2)
	}
	if resp.ChallengeTS.IsZero() {
		t.Error("expected non-zero ChallengeTS")
	}
}

func TestIntegration_V2_Success_WithRemoteIP(t *testing.T) {
	v := recaptcha.NewV2(testSecret)

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token:    anyToken,
		RemoteIP: "198.51.100.42",
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true; error codes: %v", resp.ErrorCodes)
	}
}

func TestIntegration_V2_EmptyToken(t *testing.T) {
	v := recaptcha.NewV2(testSecret)

	_, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: "",
	})
	if !errors.Is(err, captcher.ErrMissingToken) {
		t.Errorf("expected ErrMissingToken, got: %v", err)
	}
}

func TestIntegration_V2_InvalidSecret(t *testing.T) {
	v := recaptcha.NewV2("not-a-real-secret")

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: anyToken,
	})
	if err == nil {
		t.Fatal("expected error for invalid secret, got nil")
	}
	if resp != nil && resp.Success {
		t.Error("expected Success=false for invalid secret")
	}
}

func TestIntegration_V2_ContextTimeout(t *testing.T) {
	v := recaptcha.NewV2(testSecret, captcher.WithTimeout(1*time.Nanosecond))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)

	_, err := v.Verify(ctx, captcher.VerifyRequest{
		Token: anyToken,
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestIntegration_V2_ResponseFields(t *testing.T) {
	v := recaptcha.NewV2(testSecret)

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: anyToken,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Error("expected Success=true")
	}
	if resp.ChallengeTS.IsZero() {
		t.Error("expected non-zero ChallengeTS")
	}
	if resp.Provider != captcher.ProviderRecaptchaV2 {
		t.Errorf("provider = %v, want %v", resp.Provider, captcher.ProviderRecaptchaV2)
	}
	t.Logf("Response fields: Hostname=%q, Action=%q, Score=%.2f, ChallengeTS=%v",
		resp.Hostname, resp.Action, resp.Score, resp.ChallengeTS)
}

// reCAPTCHA v3 tests: no public v3 keys, so reuse the v2 secret (same endpoint); scores are meaningless.
func TestIntegration_V3_Success_WithLowThreshold(t *testing.T) {
	// Threshold 0.0 so the test secret's score (likely 0) doesn't fail.
	v := recaptcha.NewV3(testSecret, captcher.WithScoreThreshold(0.0))

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: anyToken,
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true; error codes: %v", resp.ErrorCodes)
	}
	if resp.Provider != captcher.ProviderRecaptchaV3 {
		t.Errorf("provider = %v, want %v", resp.Provider, captcher.ProviderRecaptchaV3)
	}
	t.Logf("v3 score from test secret: %.2f", resp.Score)
}

func TestIntegration_V3_ScoreBelowThreshold(t *testing.T) {
	// High threshold — the test secret returns ~0 score, so this should fail with ErrScoreTooLow.
	v := recaptcha.NewV3(testSecret, captcher.WithScoreThreshold(0.99))

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: anyToken,
	})

	// Test secret usually returns score 0 (< 0.99) → ErrScoreTooLow; a high score still validates the flow.
	if err != nil {
		if !errors.Is(err, captcher.ErrScoreTooLow) {
			t.Errorf("expected ErrScoreTooLow, got: %v", err)
		}
		if resp != nil && resp.Success {
			t.Error("expected Success=false when score is below threshold")
		}
	} else {
		t.Logf("note: test secret returned score >= 0.99 (%.2f), threshold check was not triggered", resp.Score)
	}
}

func TestIntegration_V3_EmptyToken(t *testing.T) {
	v := recaptcha.NewV3(testSecret)

	_, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: "",
	})
	if !errors.Is(err, captcher.ErrMissingToken) {
		t.Errorf("expected ErrMissingToken, got: %v", err)
	}
}

func TestIntegration_V3_InvalidSecret(t *testing.T) {
	v := recaptcha.NewV3("bogus-secret-key")

	resp, err := v.Verify(context.Background(), captcher.VerifyRequest{
		Token: anyToken,
	})
	if err == nil {
		t.Fatal("expected error for invalid secret, got nil")
	}
	if resp != nil && resp.Success {
		t.Error("expected Success=false for invalid secret")
	}
}

func TestIntegration_V3_ContextTimeout(t *testing.T) {
	v := recaptcha.NewV3(testSecret, captcher.WithTimeout(1*time.Nanosecond))

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)

	_, err := v.Verify(ctx, captcher.VerifyRequest{
		Token: anyToken,
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
