package api

import (
	"testing"
	"time"
)

func TestAgentRateLimiter_AllowsUpToRate(t *testing.T) {
	rl := NewAgentRateLimiter(3, time.Second)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if !rl.Allow("agent://test") {
			t.Fatalf("expected allow on request %d", i+1)
		}
	}
}

func TestAgentRateLimiter_BlocksWhenExceeded(t *testing.T) {
	rl := NewAgentRateLimiter(3, time.Second)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		rl.Allow("agent://test")
	}
	if rl.Allow("agent://test") {
		t.Fatal("expected block after rate exhausted")
	}
}

func TestAgentRateLimiter_IndependentKeys(t *testing.T) {
	rl := NewAgentRateLimiter(1, time.Second)
	defer rl.Stop()

	// First request for each agent should pass.
	if !rl.Allow("agent://a") {
		t.Fatal("expected allow for agent a")
	}
	if !rl.Allow("agent://b") {
		t.Fatal("expected allow for agent b — independent bucket")
	}
	// Second request for agent a should be blocked.
	if rl.Allow("agent://a") {
		t.Fatal("expected block for agent a on second request")
	}
}

func TestAgentRateLimiter_RefillsOverTime(t *testing.T) {
	rl := NewAgentRateLimiter(2, 50*time.Millisecond)
	defer rl.Stop()

	rl.Allow("agent://refill")
	rl.Allow("agent://refill")
	if rl.Allow("agent://refill") {
		t.Fatal("expected block after exhausting tokens")
	}

	// Wait for refill.
	time.Sleep(60 * time.Millisecond)

	if !rl.Allow("agent://refill") {
		t.Fatal("expected allow after refill interval")
	}
}

func TestAgentRateLimiter_NewKeyStartsFullBucket(t *testing.T) {
	rl := NewAgentRateLimiter(5, time.Second)
	defer rl.Stop()

	// Exhaust one key.
	for i := 0; i < 5; i++ {
		rl.Allow("agent://exhausted")
	}
	if rl.Allow("agent://exhausted") {
		t.Fatal("expected exhausted to be blocked")
	}

	// A brand new key should still have full tokens.
	if !rl.Allow("agent://fresh") {
		t.Fatal("expected fresh agent to be allowed")
	}
}

func TestAgentRateLimiter_ZeroRateBlocksAll(t *testing.T) {
	rl := NewAgentRateLimiter(0, time.Second)
	defer rl.Stop()
	// Rate of 0 means no tokens ever available.
	if rl.Allow("agent://zero") {
		t.Fatal("expected block for zero-rate limiter")
	}
}
