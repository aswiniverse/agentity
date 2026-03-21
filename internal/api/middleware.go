package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

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
	status int
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
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// AdminAuthMiddleware validates the admin API key from the Authorization header.
func AdminAuthMiddleware(adminKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if adminKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeProblem(w, http.StatusUnauthorized, "https://agentity.dev/errors/unauthorized", "Unauthorized", "Missing Authorization header")
				return
			}

			// Support "Bearer <key>" format.
			key := auth
			if strings.HasPrefix(auth, "Bearer ") {
				key = strings.TrimPrefix(auth, "Bearer ")
			}

			if key != adminKey {
				writeProblem(w, http.StatusForbidden, "https://agentity.dev/errors/forbidden", "Forbidden", "Invalid API key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware adds CORS headers.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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

// RateLimiter implements a simple token bucket rate limiter per IP.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // tokens per interval
	interval time.Duration
}

type bucket struct {
	tokens    int
	lastRefill time.Time
}

// NewRateLimiter creates a rate limiter allowing `rate` requests per `interval`.
func NewRateLimiter(rate int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		interval: interval,
	}
}

// Middleware returns an HTTP middleware that enforces rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		rl.mu.Lock()
		b, exists := rl.buckets[ip]
		if !exists {
			b = &bucket{tokens: rl.rate, lastRefill: time.Now()}
			rl.buckets[ip] = b
		}

		// Refill tokens.
		elapsed := time.Since(b.lastRefill)
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
			writeProblem(w, http.StatusTooManyRequests, "https://agentity.dev/errors/rate-limited", "Rate Limited", "Too many requests. Please try again later.")
			return
		}

		b.tokens--
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
