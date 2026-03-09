package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/cdpg/dx/apd-go/internal/handler"
	"github.com/cdpg/dx/apd-go/internal/middleware"
)

func New(h *handler.Handler, jwtMW *middleware.JWTMiddleware) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.RequestID)
	r.Use(jsonContentType)

	// ---------------------------------------------------------------------------
	// Contract endpoint (ConMan → APD)
	// ---------------------------------------------------------------------------

	// ---------------------------------------------------------------------------
	// Public routes
	// ---------------------------------------------------------------------------
	r.Get("/health", h.HealthCheck)

	// Consent links — accessed by provider via email, no JWT needed.
	// They carry a one-time token in the URL path.
	r.Route("/api/v1/consent/{token}", func(r chi.Router) {
		r.Get("/approve", h.ApproveConsent)
		r.Get("/deny", h.DenyConsent)
	})

	// ---------------------------------------------------------------------------
	// Policy endpoints — Phase 0
	// ---------------------------------------------------------------------------

	// Original routes (kept unchanged)
	r.Route("/api/v1/policy", func(r chi.Router) {
		r.Post("/", h.ReceivePolicy)
		r.Get("/{policyId}", h.GetPolicy)
	})

	// Additional endpoints from provided snippet (kept identical)
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/policy", h.ReceivePolicy)
		r.Get("/policy/{policyId}", h.GetPolicy)
	})

	// ---------------------------------------------------------------------------
	// TEE callbacks — called by the TEE Orchestrator
	// ---------------------------------------------------------------------------
	r.Route("/api/v1/tee", func(r chi.Router) {
		r.Post("/attestation", h.SubmitAttestation)
		r.Post("/result", h.TEEResult)
	})

	// ---------------------------------------------------------------------------
	// Authenticated routes
	// ---------------------------------------------------------------------------
	r.Group(func(r chi.Router) {
		r.Use(jwtMW.Authenticate)

		// Consumer endpoints
		r.Route("/api/v1/access-requests", func(r chi.Router) {
			r.With(middleware.RequireRole("consumer")).
				Post("/", h.CreateAccessRequest)

			r.With(middleware.RequireRole("consumer")).
				Get("/", h.ListAccessRequestsConsumer)

			r.Route("/{requestId}", func(r chi.Router) {
				r.Get("/", h.GetAccessRequest)

				r.With(middleware.RequireRole("consumer")).
					Post("/compute", h.TriggerComputation)

				r.With(middleware.RequireRole("consumer")).
					Get("/result", h.GetResult)

				r.With(middleware.RequireRole("provider", "org_admin")).
					Post("/key-bundle", h.SubmitKeyBundle)
			})
		})

		// Provider endpoints
		r.Route("/api/v1/provider/access-requests", func(r chi.Router) {
			r.With(middleware.RequireRole("provider", "org_admin")).
				Get("/", h.ListAccessRequestsProvider)
		})
	})

	return r
}

func jsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
