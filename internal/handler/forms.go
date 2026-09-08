package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/service"
)

// FormsHandler serves aaa's forwarded FL form writes/reads. aaa is the sole
// caller — these are internal, network-trust routes (see requireFormsToken
// in router.go), not part of the user-facing JWT-guarded API.
type FormsHandler struct {
	forms *service.FormsService
}

func NewForms(forms *service.FormsService) *FormsHandler {
	return &FormsHandler{forms: forms}
}

// POST /api/v1/forms/submissions
func (h *FormsHandler) CreateSubmission(w http.ResponseWriter, r *http.Request) {
	var body domain.CreateFormSubmissionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	sub, err := h.forms.CreateSubmission(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, domain.APIResponse{Status: "success", Data: sub})
}

// GET /api/v1/forms/submissions
func (h *FormsHandler) ListSubmissions(w http.ResponseWriter, r *http.Request) {
	subs, err := h.forms.ListSubmissions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: subs})
}

// GET /api/v1/forms/submissions/{id}
func (h *FormsHandler) GetSubmission(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	sub, err := h.forms.GetSubmission(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sub == nil {
		writeError(w, http.StatusNotFound, "form submission not found")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: sub})
}

// DELETE /api/v1/forms/submissions/{id}
func (h *FormsHandler) DeleteSubmission(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	deleted, err := h.forms.DeleteSubmission(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "form submission not found")
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Message: "form submission deleted"})
}

// POST /api/v1/forms/provider-forms
func (h *FormsHandler) CreateProviderForm(w http.ResponseWriter, r *http.Request) {
	var body domain.CreateProviderFormBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	form, err := h.forms.CreateProviderForm(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, domain.APIResponse{Status: "success", Data: form})
}

// GET /api/v1/forms/provider-forms?dataset_name=...
func (h *FormsHandler) ListProviderForms(w http.ResponseWriter, r *http.Request) {
	datasetName := r.URL.Query().Get("dataset_name")

	forms, err := h.forms.ListProviderForms(r.Context(), datasetName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: forms})
}

// GET /api/v1/forms/dataset-names
func (h *FormsHandler) ListDatasetNames(w http.ResponseWriter, r *http.Request) {
	names, err := h.forms.ListDatasetNames(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, domain.APIResponse{Status: "success", Data: names})
}
