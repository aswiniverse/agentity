package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// maxRequestBodyBytes limits request bodies to 1 MB to prevent DoS.
const maxRequestBodyBytes = 1 << 20 // 1 MB

type contextKey string

const (
	requestIDKey contextKey = "request_id"
)

// RequestIDMiddleware adds a unique request ID to each request.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// MaxBytesMiddleware limits request body size to prevent DoS via large payloads.
func MaxBytesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs request details using zerolog.
func LoggingMiddleware(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(sw, r)

			logger.Info().
				Str("request_id", GetRequestID(r.Context())).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", sw.status).
				Dur("duration", time.Since(start)).
				Str("remote_addr", r.RemoteAddr).
				Msg("request completed")
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusWriter) WriteHeader(status int) {
	if !w.written {
		w.status = status
		w.written = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.status = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// AdminAuthMiddleware validates the admin API key using a constant-time comparison
// to prevent timing-based side-channel attacks.
// C1 fix: use crypto/subtle.ConstantTimeCompare instead of string equality.
// C2 fix: refuse all requests when adminKey is empty (misconfiguration guard).
func AdminAuthMiddleware(adminKey string) func(http.Handler) http.Handler {
	keyBytes := []byte(adminKey)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// C2: never allow through if no key is configured — misconfiguration
			// in production (forgotten env var) must not silently disable auth.
			if adminKey == "" {
				writeProblem(w, http.StatusServiceUnavailable,
					"https://agentity.dev/errors/misconfigured",
					"Server Misconfigured",
					"Admin API key is not set. Configure AGENTITY_AUTH_ADMIN_API_KEY.")
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeProblem(w, http.StatusUnauthorized,
					"https://agentity.dev/errors/unauthorized",
					"Unauthorized",
					"Missing Authorization header")
				return
			}

			key := auth
			if strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}

			// C1: constant-time comparison to prevent timing attacks.
			if subtle.ConstantTimeCompare([]byte(key), keyBytes) != 1 {
				writeProblem(w, http.StatusForbidden,
					"https://agentity.dev/errors/forbidden",
					"Forbidden",
					"Invalid API key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware adds CORS headers. In production, set AllowedOrigins explicitly.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]struct{}, len(allowedOrigins))
	wildcard := false
	for _, o := range allowedOrigins {
		if o == "*" {
			wildcard = true
		}
		originSet[o] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := wildcard
			if !allowed {
				_, allowed = originSet[origin]
			}

			if allowed && origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			} else if wildcard {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-Request-ID")
			w.Header().Set("Access-Control-Max-Age", "3600")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter implements a token bucket rate limiter per IP with bounded memory.
// M2 fix: a background goroutine periodically evicts stale buckets to prevent OOM.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int
	interval time.Duration
	done     chan struct{}
}

type bucket struct {
	tokens     int
	lastRefill time.Time
	lastSeen   time.Time
}

// NewRateLimiter creates a rate limiter allowing `rate` requests per `interval`.
// A cleanup goroutine evicts IPs that haven't been seen for 5× the interval.
func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		interval: interval,
		done:     make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.done)
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.interval * 5)
	defer ticker.Stop()
	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			threshold := time.Now().Add(-5 * rl.interval)
			rl.mu.Lock()
			for ip, b := range rl.buckets {
				if b.lastSeen.Before(threshold) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Middleware returns an HTTP middleware that enforces rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		now := time.Now()
		rl.mu.Lock()
		b, exists := rl.buckets[ip]
		if !exists {
			b = &bucket{tokens: rl.rate, lastRefill: now, lastSeen: now}
			rl.buckets[ip] = b
		}

		b.lastSeen = now

		elapsed := now.Sub(b.lastRefill)
		if elapsed >= rl.interval {
			periods := int(elapsed / rl.interval)
			b.tokens += periods * rl.rate
			if b.tokens > rl.rate {
				b.tokens = rl.rate
			}
			b.lastRefill = b.lastRefill.Add(time.Duration(periods) * rl.interval)
		}

		if b.tokens <= 0 {
			rl.mu.Unlock()
			writeProblem(w, http.StatusTooManyRequests,
				"https://agentity.dev/errors/rate-limited",
				"Rate Limited",
				"Too many requests. Please try again later.")
			return
		}

		b.tokens--
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
