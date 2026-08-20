package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/repository"
)

// FormsService is the store-of-record for FL form submissions and
// data-provider forms. aaa used to own this shaping logic (id minting,
// numeric/string coercion) against immudb; it moved here with the storage
// itself so APD is the single source of truth.
type FormsService struct {
	subs     *repository.FormSubmissionRepo
	provider *repository.ProviderFormRepo
}

func NewFormsService(subs *repository.FormSubmissionRepo, provider *repository.ProviderFormRepo) *FormsService {
	return &FormsService{subs: subs, provider: provider}
}

func (s *FormsService) CreateSubmission(ctx context.Context, body domain.CreateFormSubmissionBody) (*domain.FormSubmission, error) {
	if body.FormID == "" || body.RequestedBy == "" || body.OutputOwnerID == "" {
		return nil, errors.New("form_id, requested_by, and output_owner_id are required")
	}

	now := time.Now()
	requestedAt := now
	if body.RequestedAt != "" {
		if t, err := time.Parse(time.RFC3339, body.RequestedAt); err == nil {
			requestedAt = t
		}
	}

	components := body.Components
	if components == nil {
		components = map[string]interface{}{}
	}
	selected := body.SelectedProviders
	if selected == nil {
		selected = []string{}
	}

	sub := &domain.FormSubmission{
		ID:                "gov-" + uuid.NewString(),
		FormID:            body.FormID,
		RequestedBy:       body.RequestedBy,
		OutputOwnerID:     body.OutputOwnerID,
		NumServerRounds:   numOrNull(body.NumServerRounds),
		FractionEvaluate:  numOrNull(body.FractionEvaluate),
		LocalEpochs:       numOrNull(body.LocalEpochs),
		LearningRate:      numOrNull(body.LearningRate),
		BatchSize:         numOrNull(body.BatchSize),
		Model:             strOrNull(body.Model),
		Framework:         strOrNull(body.Framework),
		Components:        components,
		Filled:            true,
		RequestedAt:       requestedAt,
		FilledAt:          now,
		SelectedProviders: selected,
		IPAddress:         strOrNull(body.IPAddress),
		Port:              numOrNull(body.Port),
		RAMUsage:          numOrNull(body.RAMUsage),
	}

	if err := s.subs.Upsert(ctx, sub); err != nil {
		return nil, err
	}
	return sub, nil
}

func (s *FormsService) ListSubmissions(ctx context.Context) ([]*domain.FormSubmission, error) {
	return s.subs.List(ctx)
}

func (s *FormsService) GetSubmission(ctx context.Context, id string) (*domain.FormSubmission, error) {
	return s.subs.GetByID(ctx, id)
}

func (s *FormsService) DeleteSubmission(ctx context.Context, id string) (bool, error) {
	return s.subs.SoftDelete(ctx, id)
}

func (s *FormsService) CreateProviderForm(ctx context.Context, body domain.CreateProviderFormBody) (*domain.ProviderForm, error) {
	now := time.Now()
	filledAt := now
	if body.FilledAt != "" {
		if t, err := time.Parse(time.RFC3339, body.FilledAt); err == nil {
			filledAt = t
		}
	}

	form := &domain.ProviderForm{
		ID:             "dpf-" + uuid.NewString(),
		FormID:         strOrNull(body.FormID),
		DataOwnerID:    strOrNull(body.DataOwnerID),
		DatasetName:    strOrNull(body.DatasetName),
		RAM:            numOrNull(body.RAM),
		MemoryMB:       numOrNull(body.MemoryMB),
		DataSizeBytes:  numOrNull(body.DataSizeBytes),
		DataResourceID: strOrNull(body.DataResourceID),
		IPAddress:      strOrNull(body.IPAddress),
		Port:           numOrNull(body.Port),
		RAMUsage:       numOrNull(body.RAMUsage),
		Filled:         true,
		FilledAt:       filledAt,
		SubmittedBy:    strOrNull(body.SubmittedBy),
	}

	if err := s.provider.Insert(ctx, form); err != nil {
		return nil, err
	}
	return form, nil
}

func (s *FormsService) ListDatasetNames(ctx context.Context) ([]string, error) {
	return s.provider.ListDatasetNames(ctx)
}

func (s *FormsService) ListProviderForms(ctx context.Context, datasetName string) ([]*domain.ProviderForm, error) {
	return s.provider.ListByDatasetName(ctx, datasetName)
}

// numOrNull mirrors the aaa "value || null" coercion: undefined, null, "",
// non-numeric strings, and 0 all become nil.
func numOrNull(v interface{}) *float64 {
	var n float64
	switch t := v.(type) {
	case nil:
		return nil
	case float64:
		n = t
	case string:
		if t == "" {
			return nil
		}
		parsed, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return nil
		}
		n = parsed
	default:
		return nil
	}
	if n == 0 {
		return nil
	}
	return &n
}

// strOrNull mirrors the aaa coercion: only a non-empty string survives.
func strOrNull(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
