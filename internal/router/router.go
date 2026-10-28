package router

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/handler"
	"github.com/cdpg/dx/apd-go/internal/middleware"
)

func New(h *handler.Handler, fh *handler.FormsHandler, uh *handler.UserHandler, jwtMW *middleware.JWTMiddleware, formsToken string, corsOrigins []string) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.RequestID)
	r.Use(cors(corsOrigins))
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
		// Consumer grants gov_layer posts on data-provider approval. Before
		// the "/{policyId}" wildcard for the same reason as "/mine".
		r.Get("/grants", h.ListGrants)
		r.Get("/{policyId}", h.GetPolicy)          // TOP   → APD: fetch policy
		r.Get("/by-item/{itemId}", h.GetPolicyByItemID)
	})

	// FL form submissions and data-provider forms. APD is the store of
	// record. Called by the UI with the user's JWT, and by services
	// (gov_layer) with the X-Forms-Push-Token shared secret.
	r.Route("/api/v1/forms", func(r chi.Router) {
		r.Use(requireFormsTokenOrUser(formsToken, jwtMW))
		r.Post("/submissions", fh.CreateSubmission)
		r.Get("/submissions", fh.ListSubmissions)
		r.Get("/submissions/{id}", fh.GetSubmission)
		r.Delete("/submissions/{id}", fh.DeleteSubmission)
		r.With(requireRoleIfUser("provider")).Post("/provider-forms", fh.CreateProviderForm)
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

		// User-facing policy routes (the P3DX UI). provider_id always comes
		// from the caller's token; the internal /api/v1/policy routes above
		// stay for service callers.
		r.Route("/api/v1/me/policies", func(r chi.Router) {
			r.Post("/", uh.SubmitMyPolicy) // role checked per policy_type
			r.With(middleware.RequireRole("infra_provider")).
				Get("/infrastructure", uh.ListMyInfrastructure)
			r.With(middleware.RequireRole("infra_provider")).
				Delete("/infrastructure/{itemId}", uh.DeleteMyInfrastructure)
			r.With(middleware.RequireRole("provider")).
				Get("/datasets", uh.ListMyDatasets)
			r.With(middleware.RequireRole("provider")).
				Get("/datasets/{itemId}", uh.GetMyDataset)
			r.With(middleware.RequireRole("provider")).
				Delete("/datasets/{itemId}", uh.DeleteMyDataset)
		})

		// Catalogue browsing — any signed-in user.
		r.Route("/api/v1/catalogue", func(r chi.Router) {
			r.Get("/datasets", uh.ListCatalogueDatasets)
			r.Get("/infrastructure", uh.ListCatalogueInfrastructure)
			r.Get("/infrastructure/{itemId}", uh.GetCatalogueInfrastructure)
		})

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

// requireFormsTokenOrUser lets a request through when it carries a valid user
// JWT (Authorization: Bearer ...) or the forms shared secret. With no secret
// configured, requests without a JWT pass as before.
func requireFormsTokenOrUser(token string, jwtMW *middleware.JWTMiddleware) func(http.Handler) http.Handler {
	tokenCheck := requireFormsToken(token)
	return func(next http.Handler) http.Handler {
		viaJWT := jwtMW.Authenticate(next)
		viaToken := tokenCheck(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				viaJWT.ServeHTTP(w, r)
				return
			}
			viaToken.ServeHTTP(w, r)
		})
	}
}

// requireRoleIfUser enforces role on user (JWT) callers only; service callers
// that came in on the shared secret carry no user and pass through.
func requireRoleIfUser(role string) func(http.Handler) http.Handler {
	roleCheck := middleware.RequireRole(role)
	return func(next http.Handler) http.Handler {
		checked := roleCheck(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if middleware.UserIDFromCtx(r.Context()) == "" {
				next.ServeHTTP(w, r)
				return
			}
			checked.ServeHTTP(w, r)
		})
	}
}

// cors allows the listed browser origins (the P3DX UI) to call APD. Requests
// from other origins get no CORS headers, so browsers block them; non-browser
// callers are unaffected.
func cors(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && slices.Contains(origins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Max-Age", "600")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
