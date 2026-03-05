package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/middleware"
	"github.com/cdpg/dx/apd-go/internal/service"
)

// Handler holds all HTTP handlers. It is registered on the router.
type Handler struct {
	accessReq *service.AccessRequestService
}

func New(accessReq *service.AccessRequestService) *Handler {
	return &Handler{accessReq: accessReq}
}

// ---------------------------------------------------------------------------
// Phase 0 — ConMan pushes policy to APD
// POST /api/v1/policy
// ---------------------------------------------------------------------------

func (h *Handler) ReceivePolicy(w http.ResponseWriter, r *http.Request) {
	var body domain.ReceivePolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	policy, err := h.accessReq.ReceivePolicy(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, domain.APIResponse{
		Status:  "success",
		Message: "policy stored",
		Data:    policy,
	})
}

// ---------------------------------------------------------------------------
// Phase 0 — TOP fetches policy from APD
// GET /api/v1/policy/{policyId}
// ---------------------------------------------------------------------------

func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "policyId")

	policy, err := h.accessReq.GetPolicy(r.Context(), policyID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: policy})
}

// ---------------------------------------------------------------------------
// Phase 0 — TOP fetches policy by itemId (fallback)
// GET /api/v1/policy/item/{itemId}
// ---------------------------------------------------------------------------

func (h *Handler) GetPolicyByItemID(w http.ResponseWriter, r *http.Request) {
	itemID := chi.URLParam(r, "itemId")

	policy, err := h.accessReq.GetPolicyByItemID(r.Context(), itemID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: policy})
}

// ---------------------------------------------------------------------------
// Phase 1 — Consumer creates access request
// POST /api/v1/access-requests
// ---------------------------------------------------------------------------

func (h *Handler) CreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	consumerID := middleware.UserIDFromCtx(r.Context())

	// In production, providerID / assetName / assetType are resolved from the DX Catalogue
	// using itemId. We accept them inline here so the APD can be tested standalone.
	var body struct {
		domain.CreateAccessRequestBody
		ProviderID string `json:"providerId"`
		AssetName  string `json:"assetName"`
		AssetType  string `json:"assetType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if body.ItemID == "" || string(body.AccessType) == "" {
		writeError(w, http.StatusBadRequest, "itemId and accessType are required")
		return
	}

	req, err := h.accessReq.Create(
		r.Context(),
		consumerID,
		body.CreateAccessRequestBody,
		body.ProviderID,
		body.AssetName,
		body.AssetType,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, domain.APIResponse{Status: "success", Data: req})
}

// ---------------------------------------------------------------------------
// Phase 2 — Consumer triggers computation
// POST /api/v1/access-requests/{requestId}/compute
// ---------------------------------------------------------------------------

func (h *Handler) TriggerComputation(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	consumerID := middleware.UserIDFromCtx(r.Context())

	req, err := h.accessReq.TriggerComputation(r.Context(), requestID, consumerID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, domain.APIResponse{
		Status:  "success",
		Message: "TEE provisioning started — awaiting attestation",
		Data:    req,
	})
}

// ---------------------------------------------------------------------------
// Phase 3 — TEE submits attestation report (TEE → APD callback)
// POST /api/v1/tee/attestation
// ---------------------------------------------------------------------------

func (h *Handler) SubmitAttestation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		domain.SubmitAttestationBody
		ProviderEmail string `json:"providerEmail"`
		ConsumerName  string `json:"consumerName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.RequestID == "" {
		writeError(w, http.StatusBadRequest, "requestId is required")
		return
	}

	if err := h.accessReq.SubmitAttestation(
		r.Context(),
		body.RequestID,
		body.AttestationReport,
		body.ProviderEmail,
		body.ConsumerName,
	); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{
		Status:  "success",
		Message: "attestation verified — runtime consent request sent to provider",
	})
}

// ---------------------------------------------------------------------------
// Phase 4 — Provider approves runtime consent (via email link)
// GET /api/v1/consent/{token}/approve
// ---------------------------------------------------------------------------

func (h *Handler) ApproveConsent(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	var body struct {
		ConsumerEmail string `json:"consumerEmail"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	req, err := h.accessReq.ApproveRuntimeConsent(r.Context(), token, body.ConsumerEmail)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	msg := "runtime consent granted"
	if req.AccessType == domain.AccessTypeOpen {
		msg = "runtime consent granted — TEE is fetching data (open access)"
	} else {
		msg = "runtime consent granted — awaiting key bundle from provider"
	}

	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: msg, Data: req})
}

// ---------------------------------------------------------------------------
// Phase 4 — Provider denies runtime consent
// GET /api/v1/consent/{token}/deny
// ---------------------------------------------------------------------------

func (h *Handler) DenyConsent(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	var body struct {
		ConsumerEmail string `json:"consumerEmail"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	if err := h.accessReq.DenyRuntimeConsent(r.Context(), token, body.ConsumerEmail); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "consent denied — TEE terminated"})
}

// ---------------------------------------------------------------------------
// Phase 4 (Cases 2 & 3) — Provider submits encrypted key bundle
// POST /api/v1/access-requests/{requestId}/key-bundle
// ---------------------------------------------------------------------------

func (h *Handler) SubmitKeyBundle(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	providerID := middleware.UserIDFromCtx(r.Context())

	var body domain.SubmitKeyBundleBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.EncryptedBundle == "" {
		writeError(w, http.StatusBadRequest, "encryptedBundle is required")
		return
	}

	bundle := domain.KeyBundle{
		RequestID:       requestID,
		EncryptedBundle: body.EncryptedBundle,
		SSHHost:         body.SSHHost,
		SSHUser:         body.SSHUser,
	}

	if err := h.accessReq.ReceiveKeyBundle(r.Context(), requestID, providerID, bundle); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{
		Status:  "success",
		Message: "key bundle forwarded to TEE — data fetching in progress",
	})
}

// ---------------------------------------------------------------------------
// Phase 5 — TEE reports result (TEE → APD callback)
// POST /api/v1/tee/result
// ---------------------------------------------------------------------------

func (h *Handler) TEEResult(w http.ResponseWriter, r *http.Request) {
	var body struct {
		domain.TEEDataFetchedBody
		ConsumerEmail string `json:"consumerEmail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.accessReq.TEEDataFetched(r.Context(), body.TEEDataFetchedBody, body.ConsumerEmail); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "result stored"})
}

// ---------------------------------------------------------------------------
// Status / result retrieval
// ---------------------------------------------------------------------------

// GET /api/v1/access-requests/{requestId}
func (h *Handler) GetAccessRequest(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	req, err := h.accessReq.GetByID(r.Context(), requestID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: req})
}

// GET /api/v1/access-requests (consumer view)
func (h *Handler) ListAccessRequestsConsumer(w http.ResponseWriter, r *http.Request) {
	consumerID := middleware.UserIDFromCtx(r.Context())
	reqs, err := h.accessReq.ListByConsumer(r.Context(), consumerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: reqs})
}

// GET /api/v1/provider/access-requests (provider view)
func (h *Handler) ListAccessRequestsProvider(w http.ResponseWriter, r *http.Request) {
	providerID := middleware.UserIDFromCtx(r.Context())
	reqs, err := h.accessReq.ListByProvider(r.Context(), providerID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: reqs})
}

// GET /api/v1/access-requests/{requestId}/result
func (h *Handler) GetResult(w http.ResponseWriter, r *http.Request) {
	requestID := chi.URLParam(r, "requestId")
	consumerID := middleware.UserIDFromCtx(r.Context())

	req, err := h.accessReq.GetByID(r.Context(), requestID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if req.ConsumerID != consumerID {
		writeError(w, http.StatusForbidden, "not your request")
		return
	}
	if req.Status != domain.StatusResultDelivered {
		writeJSON(w, http.StatusAccepted, domain.APIResponse{
			Status:  "pending",
			Message: "result not yet available, current status: " + string(req.Status),
		})
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{
		Status: "success",
		Data: map[string]string{
			"encryptedResult": *req.EncryptedResult,
			"note":            "result is encrypted with your public key — decrypt locally",
		},
	})
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, domain.APIResponse{Status: "error", Message: msg})
}
