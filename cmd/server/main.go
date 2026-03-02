package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cdpg/dx/apd-go/internal/config"
	"github.com/cdpg/dx/apd-go/internal/handler"
	"github.com/cdpg/dx/apd-go/internal/middleware"
	"github.com/cdpg/dx/apd-go/internal/repository"
	"github.com/cdpg/dx/apd-go/internal/router"
	"github.com/cdpg/dx/apd-go/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// ---------------------------------------------------------------------------
	// Database
	// ---------------------------------------------------------------------------
	pool, err := repository.NewPool(ctx, cfg.DB)
	if err != nil {
		log.Fatalf("connect to postgres: %v", err)
	}
	defer pool.Close()
	log.Println("connected to postgres")

	// ---------------------------------------------------------------------------
	// Repositories
	// ---------------------------------------------------------------------------
	accessRequestRepo := repository.NewAccessRequestRepo(pool)
	consentTokenRepo := repository.NewConsentTokenRepo(pool)

	// ---------------------------------------------------------------------------
	// Services
	// ---------------------------------------------------------------------------
	emailSvc := service.NewEmailService(cfg.Email)

	consentSvc := service.NewConsentService(consentTokenRepo, emailSvc)

	attestSvc, err := service.NewAttestationService(cfg.AMD)
	if err != nil {
		log.Fatalf("init attestation service: %v", err)
	}

	teeSvc, err := service.NewTEEService(cfg.TEE, cfg.APD)
	if err != nil {
		log.Fatalf("init TEE service: %v", err)
	}

	accessReqSvc := service.NewAccessRequestService(
		accessRequestRepo,
		teeSvc,
		attestSvc,
		consentSvc,
		emailSvc,
	)

	// ---------------------------------------------------------------------------
	// Handlers & Router
	// ---------------------------------------------------------------------------
	h := handler.New(accessReqSvc)

	jwtMW, err := middleware.NewJWTMiddleware(cfg.JWT.PublicKeyPath)
	if err != nil {
		log.Fatalf("init JWT middleware: %v", err)
	}

	mux := router.New(h, jwtMW)

	// ---------------------------------------------------------------------------
	// HTTP Server with graceful shutdown
	// ---------------------------------------------------------------------------
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("APD server listening on :%s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for OS signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("server forced shutdown: %v", err)
	}
	log.Println("server exited cleanly")
}
