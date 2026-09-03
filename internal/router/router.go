package router

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/handler"
	"github.com/cdpg/dx/apd-go/internal/middleware"
)

func New(h *handler.Handler, fh *handler.FormsHandler, jwtMW *middleware.JWTMiddleware, formsToken string) http.Handler {
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
		r.Post("/", h.ReceivePolicy)               // ConMan → APD: store policy
		r.Get("/datasets", h.ListPolicyDatasets) // dataset catalogue: {item_id, name} with a policy set
		r.Get("/infrastructure", h.ListInfraProviders) // InfraCat: registered infra-provider policies
		// "My Infrastructure" dashboard (aaa derives provider_id from the
		// caller's JWT and passes it as a query param — same trust model as
		// the rest of this route block). Static "/mine" resolves before the
		// "/{policyId}" wildcard below, so this doesn't collide with it.
		r.Get("/mine", h.ListMyInfrastructure)
		r.Delete("/by-item/{itemId}", h.DeleteMyInfrastructure)
		// "My Datasets" dashboard — same trust model, mirrors the infra pair
		// above exactly. Registered before the "/{policyId}" wildcard for
		// the same reason.
		r.Get("/mine-datasets", h.ListMyDatasets)
		r.Delete("/by-item-dataset/{itemId}", h.DeleteMyDataset)
		r.Get("/{policyId}", h.GetPolicy)          // TOP   → APD: fetch policy
		r.Get("/by-item/{itemId}", h.GetPolicyByItemID)
	})

	// FL form submissions and data-provider forms — pushed here by aaa
	// (the FL form UI's backend) right after it accepts a submission.
	// APD is the store of record; aaa no longer writes to immudb for
	// these. Internal network only, guarded by a shared secret rather
	// than user JWT since the caller is aaa itself, not an end user.
	r.Route("/api/v1/forms", func(r chi.Router) {
		r.Use(requireFormsToken(formsToken))
		r.Post("/submissions", fh.CreateSubmission)
		r.Get("/submissions", fh.ListSubmissions)
		r.Get("/submissions/{id}", fh.GetSubmission)
		r.Delete("/submissions/{id}", fh.DeleteSubmission)
		r.Post("/provider-forms", fh.CreateProviderForm)
		r.Get("/provider-forms", fh.ListProviderForms)
		r.Get("/dataset-names", fh.ListDatasetNames)
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

// requireFormsToken guards the forms routes with an optional shared secret
// (FORMS_PUSH_TOKEN). Left unset, the check is skipped — matching the same
// convention the governance layer uses for aaa's other forms push.
func requireFormsToken(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token != "" && r.Header.Get("X-Forms-Push-Token") != token {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(domain.APIResponse{Status: "error", Message: "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
