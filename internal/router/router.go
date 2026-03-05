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
	// Public routes
	// ---------------------------------------------------------------------------
	r.Get("/health", h.HealthCheck)

	// Consent links — accessed by provider via email, no JWT needed.
	// They carry a one-time token in the URL path.
	r.Route("/api/v1/consent/{token}", func(r chi.Router) {
		r.Get("/approve", h.ApproveConsent)
		r.Get("/deny", h.DenyConsent)
	})

	// Policy endpoints — Phase 0.
	// ConMan pushes a policy; TOP fetches it. Internal network only (no user JWT).
	r.Route("/api/v1/policy", func(r chi.Router) {
		r.Post("/", h.ReceivePolicy)                  // ConMan → APD: store policy
		r.Get("/{policyId}", h.GetPolicy)             // TOP   → APD: fetch by policyId
		r.Get("/item/{itemId}", h.GetPolicyByItemID)  // TOP   → APD: fetch by itemId (fallback)
	})

	// TEE callbacks — called by the TEE Orchestrator (internal network only).
	// In production, restrict these to the orchestrator's IP range at the
	// network/ingress level; no user JWT is expected here.
	r.Route("/api/v1/tee", func(r chi.Router) {
		r.Post("/attestation", h.SubmitAttestation) // Phase 3
		r.Post("/result", h.TEEResult)              // Phase 5
	})

	// ---------------------------------------------------------------------------
	// Authenticated routes
	// ---------------------------------------------------------------------------
	r.Group(func(r chi.Router) {
		r.Use(jwtMW.Authenticate)

		// Consumer endpoints
		r.Route("/api/v1/access-requests", func(r chi.Router) {
			r.With(middleware.RequireRole("consumer")).
				Post("/", h.CreateAccessRequest) // Phase 1

			r.With(middleware.RequireRole("consumer")).
				Get("/", h.ListAccessRequestsConsumer) // List own requests

			r.Route("/{requestId}", func(r chi.Router) {
				r.Get("/", h.GetAccessRequest) // Any authenticated user

				r.With(middleware.RequireRole("consumer")).
					Post("/compute", h.TriggerComputation) // Phase 2

				r.With(middleware.RequireRole("consumer")).
					Get("/result", h.GetResult) // Phase 5 — poll for result

				// Provider submits encrypted key bundle (Cases 2 & 3)
				r.With(middleware.RequireRole("provider", "org_admin")).
					Post("/key-bundle", h.SubmitKeyBundle) // Phase 4
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
