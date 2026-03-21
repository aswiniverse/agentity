package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// TokensIssued counts the number of root tokens issued.
	TokensIssued = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "tokens_issued_total",
		Help:      "Total number of root ACT tokens issued.",
	})

	// TokensVerified counts successful token verifications.
	TokensVerified = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "tokens_verified_total",
		Help:      "Total number of ACT tokens successfully verified.",
	})

	// TokensRejected counts failed token verifications.
	TokensRejected = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "tokens_rejected_total",
		Help:      "Total number of ACT token verification failures.",
	})

	// TokensDelegated counts delegation submissions.
	TokensDelegated = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "tokens_delegated_total",
		Help:      "Total number of delegated ACT tokens submitted.",
	})

	// TokensRevoked counts explicit token revocations.
	TokensRevoked = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "tokens_revoked_total",
		Help:      "Total number of ACT tokens revoked.",
	})

	// AgentsRegistered counts agent registrations.
	AgentsRegistered = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "agents_registered_total",
		Help:      "Total number of agents registered.",
	})

	// PolicyDenials counts policy-denied requests.
	PolicyDenials = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "agentity",
		Name:      "policy_denials_total",
		Help:      "Total number of requests denied by the policy engine.",
	})

	// VerificationDuration measures token verification latency.
	VerificationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "agentity",
		Name:      "token_verification_duration_seconds",
		Help:      "Latency of ACT token verification.",
		Buckets:   prometheus.DefBuckets,
	})

	// IssuanceDuration measures token issuance latency.
	IssuanceDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "agentity",
		Name:      "token_issuance_duration_seconds",
		Help:      "Latency of ACT token issuance.",
		Buckets:   prometheus.DefBuckets,
	})
)
