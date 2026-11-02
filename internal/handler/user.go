package handler

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/middleware"
	"github.com/cdpg/dx/apd-go/internal/service"
)

// DX realm roles allowed to register each policy type.
const (
	roleDataProvider  = "provider"
	roleInfraProvider = "infra_provider"
)

// UserHandler serves the user-facing (browser) policy and catalogue routes.
// Unlike the internal /api/v1/policy routes, every route here sits behind the
// JWT middleware and takes the caller's provider_id from their token, never
// from the request.
type UserHandler struct {
	accessReq *service.AccessRequestService
	forms     *service.FormsService
}

func NewUser(accessReq *service.AccessRequestService, forms *service.FormsService) *UserHandler {
	return &UserHandler{accessReq: accessReq, forms: forms}
}

// POST /api/v1/me/policies — a provider registers (or edits, by resubmitting
// the same itemId) a dataset or infrastructure policy. rules.policy_type
// "infra-provider" needs the infra_provider role; anything else is a dataset
// policy and needs provider. Consumer grants are gov_layer's alone.
func (h *UserHandler) SubmitMyPolicy(w http.ResponseWriter, r *http.Request) {
	var body domain.ReceivePolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	policyType, _ := body.Rules["policy_type"].(string)
	requiredRole := roleDataProvider
	switch policyType {
	case "infra-provider":
		requiredRole = roleInfraProvider
	case domain.PolicyTypeConsumerGrant:
		writeError(w, http.StatusForbidden, "consumer grants cannot be submitted by users")
		return
	}
	if !middleware.HasRole(r.Context(), requiredRole) {
		writeError(w, http.StatusForbidden, "requires role "+requiredRole)
		return
	}

	body.ProviderID = middleware.ProviderIDFromCtx(r.Context())
	if email := middleware.EmailFromCtx(r.Context()); email != "" {
		body.ProviderEmail = email
	}
	if body.IssuedBy == "" {
		body.IssuedBy = body.ProviderID
	}
	(&Handler{accessReq: h.accessReq}).storePolicy(w, r, body)
}

// GET /api/v1/me/policies/infrastructure — the "My Infrastructure" dashboard.
func (h *UserHandler) ListMyInfrastructure(w http.ResponseWriter, r *http.Request) {
	infra, err := h.accessReq.ListMyInfrastructure(r.Context(), middleware.ProviderIDFromCtx(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: infra})
}

// DELETE /api/v1/me/policies/infrastructure/{itemId} — 404 also when the item
// belongs to someone else.
func (h *UserHandler) DeleteMyInfrastructure(w http.ResponseWriter, r *http.Request) {
	deleted, err := h.accessReq.DeleteMyInfrastructure(r.Context(), chi.URLParam(r, "itemId"), middleware.ProviderIDFromCtx(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "infrastructure not found")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "infrastructure deleted"})
}

// GET /api/v1/me/policies/datasets — the "My Datasets" dashboard.
func (h *UserHandler) ListMyDatasets(w http.ResponseWriter, r *http.Request) {
	datasets, err := h.accessReq.ListMyDatasets(r.Context(), middleware.ProviderIDFromCtx(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: datasets})
}

// myDatasetPolicy is what the dataset edit form needs; it leaves out the
// provider's identity fields.
type myDatasetPolicy struct {
	ItemID    string                 `json:"item_id"`
	Rules     map[string]interface{} `json:"rules"`
	IsPrivate bool                   `json:"is_private"`
	DataURL   string                 `json:"data_url"`
	ExpiresAt interface{}            `json:"expiresAt,omitempty"`
}

// GET /api/v1/me/policies/datasets/{itemId} — one of the caller's own dataset
// policies, for editing. 403 if it belongs to another provider.
func (h *UserHandler) GetMyDataset(w http.ResponseWriter, r *http.Request) {
	policy, err := h.accessReq.GetPolicyByItemID(r.Context(), chi.URLParam(r, "itemId"))
	if err != nil || policy == nil {
		writeError(w, http.StatusNotFound, "dataset not found")
		return
	}
	if policy.ProviderID != middleware.ProviderIDFromCtx(r.Context()) {
		writeError(w, http.StatusForbidden, "dataset belongs to another provider")
		return
	}
	out := myDatasetPolicy{ItemID: policy.ItemID, Rules: policy.Rules, IsPrivate: policy.IsPrivate, DataURL: policy.DataURL}
	if policy.ExpiresAt != nil {
		out.ExpiresAt = policy.ExpiresAt
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: out})
}

// DELETE /api/v1/me/policies/datasets/{itemId} — 404 also when the item
// belongs to someone else.
func (h *UserHandler) DeleteMyDataset(w http.ResponseWriter, r *http.Request) {
	deleted, err := h.accessReq.DeleteMyDataset(r.Context(), chi.URLParam(r, "itemId"), middleware.ProviderIDFromCtx(r.Context()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "dataset not found")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "dataset deleted"})
}

// catalogueDataset is one entry of the dataset catalogue.
type catalogueDataset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GET /api/v1/catalogue/datasets — every dataset a consumer can pick, from
// both sources: policies (Set Policy page, keyed by a real item_id) and FL
// data-provider forms (name only). For a form-only dataset the id falls back
// to its name; when a name exists in both, the policy's item_id wins, since
// a later by-item policy lookup needs the real id.
func (h *UserHandler) ListCatalogueDatasets(w http.ResponseWriter, r *http.Request) {
	formNames, err := h.forms.ListDatasetNames(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policyDatasets, err := h.accessReq.ListPolicyDatasets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	byName := make(map[string]catalogueDataset)
	for _, name := range formNames {
		if name != "" {
			byName[name] = catalogueDataset{ID: name, Name: name}
		}
	}
	for _, d := range policyDatasets {
		if d.Name != "" {
			byName[d.Name] = catalogueDataset{ID: d.ItemID, Name: d.Name}
		}
	}
	out := make([]catalogueDataset, 0, len(byName))
	for _, d := range byName {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: out})
}

// GET /api/v1/catalogue/infrastructure — the Infrastructure Catalogue (InfraCat).
func (h *UserHandler) ListCatalogueInfrastructure(w http.ResponseWriter, r *http.Request) {
	infra, err := h.accessReq.ListInfraProviders(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: infra})
}

// GET /api/v1/catalogue/infrastructure/{itemId} — one infra's registered
// detail (rules.infrastructure only, not the provider's identity fields).
func (h *UserHandler) GetCatalogueInfrastructure(w http.ResponseWriter, r *http.Request) {
	policy, err := h.accessReq.GetPolicyByItemID(r.Context(), chi.URLParam(r, "itemId"))
	if err != nil || policy == nil {
		writeError(w, http.StatusNotFound, "infrastructure not found")
		return
	}
	infra, ok := policy.Rules["infrastructure"]
	if !ok || infra == nil {
		writeError(w, http.StatusNotFound, "infrastructure not found")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: infra})
}
