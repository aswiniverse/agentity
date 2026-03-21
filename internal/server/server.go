package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentity/agentity/internal/config"
	"github.com/rs/zerolog"
)

// Server wraps http.Server with graceful shutdown.
type Server struct {
	httpServer *http.Server
	logger     zerolog.Logger
	cfg        config.ServerConfig
}

// New creates a new Server.
func New(handler http.Handler, cfg config.ServerConfig, logger zerolog.Logger) *Server {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  120 * time.Second,
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return &Server{
		httpServer: httpServer,
		logger:     logger,
		cfg:        cfg,
	}
}

// Start begins listening and blocks until shutdown signal is received.
func (s *Server) Start() error {
	// Channel for shutdown signals.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Channel for server errors.
	errCh := make(chan error, 1)

	go func() {
		s.logger.Info().
			Str("addr", s.httpServer.Addr).
			Msg("server starting")

		var err error
		if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
			err = s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or error.
	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-stop:
		s.logger.Info().
			Str("signal", sig.String()).
			Msg("shutdown signal received")
	}

	// Graceful shutdown.
	shutdownTimeout := s.cfg.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = 15 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	s.logger.Info().
		Dur("timeout", shutdownTimeout).
		Msg("shutting down gracefully")

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	s.logger.Info().Msg("server stopped")
	return nil
}
