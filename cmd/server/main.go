package main

import (
	"context"
	"encoding/json"
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

// ---------------------------------------------------------------------------
// Contract endpoint (TOP receives contract from ConMan)
// ---------------------------------------------------------------------------
func contractHandler(w http.ResponseWriter, r *http.Request) {

	var contract map[string]interface{}

	err := json.NewDecoder(r.Body).Decode(&contract)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println("Contract received from ConMan:", contract)

	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
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
	// Wrap router to add /contract endpoint without modifying router.go
	// ---------------------------------------------------------------------------
	handlerWithContract := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodPost && r.URL.Path == "/contract" {
			contractHandler(w, r)
			return
		}

		mux.ServeHTTP(w, r)
	})

	// ---------------------------------------------------------------------------
	// HTTP Server with graceful shutdown
	// ---------------------------------------------------------------------------
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:      handlerWithContract,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("APD server listening on :%s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

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
