package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/repository"
)

// AccessRequestService orchestrates the full TEE-based data access lifecycle.
type AccessRequestService struct {
	repo        *repository.AccessRequestRepo
	tee         *TEEService
	attest      *AttestationService
	consent     *ConsentService
	email       *EmailService

	// Phase 0: policies received from ConMan, keyed by policyId
	policyMu sync.RWMutex
	policies map[string]*domain.Policy
}

func NewAccessRequestService(
	repo *repository.AccessRequestRepo,
	tee *TEEService,
	attest *AttestationService,
	consent *ConsentService,
	email *EmailService,
) *AccessRequestService {
	return &AccessRequestService{
		repo:     repo,
		tee:      tee,
		attest:   attest,
		consent:  consent,
		email:    email,
		policies: make(map[string]*domain.Policy),
	}
}

// ---------------------------------------------------------------------------
// Phase 0 — ConMan pushes policy; TOP fetches it
// ---------------------------------------------------------------------------

// ReceivePolicy stores a policy received from the Contract Manager (ConMan).
func (s *AccessRequestService) ReceivePolicy(ctx context.Context, body domain.ReceivePolicyBody) (*domain.Policy, error) {
	if body.PolicyID == "" {
		return nil, errors.New("policyId is required")
	}
	if body.ItemID == "" {
		return nil, errors.New("itemId is required")
	}
	if body.IssuedBy == "" {
		return nil, errors.New("issuedBy is required")
	}

	policy := &domain.Policy{
		PolicyID:  body.PolicyID,
		ItemID:    body.ItemID,
		IssuedBy:  body.IssuedBy,
		Rules:     body.Rules,
		IssuedAt:  time.Now(),
		ExpiresAt: body.ExpiresAt,
	}

	s.policyMu.Lock()
	s.policies[policy.PolicyID] = policy
	s.policyMu.Unlock()

	return policy, nil
}

// GetPolicy returns the policy for the given policyId, called by the TOP.
func (s *AccessRequestService) GetPolicy(ctx context.Context, policyID string) (*domain.Policy, error) {
	s.policyMu.RLock()
	policy, ok := s.policies[policyID]
	s.policyMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("policy %q not found", policyID)
	}
	if policy.ExpiresAt != nil && policy.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("policy %q has expired", policyID)
	}
	return policy, nil
}

// ---------------------------------------------------------------------------
// Phase 1 — Consumer creates request
// ---------------------------------------------------------------------------

func (s *AccessRequestService) Create(
	ctx context.Context,
	consumerID string,
	body domain.CreateAccessRequestBody,
	providerID string, // resolved from catalogue
	assetName, assetType string,
) (*domain.AccessRequest, error) {

	if consumerID == providerID {
		return nil, errors.New("consumer and provider cannot be the same user")
	}
	if body.AppImageHash == "" {
		return nil, errors.New("appImageHash (expected TEE measurement) is required")
	}
	if body.ConsumerPublicKey == "" {
		return nil, errors.New("consumerPublicKey is required to encrypt the result")
	}

	req := &domain.AccessRequest{
		ID:                  uuid.NewString(),
		ConsumerID:          consumerID,
		ProviderID:          providerID,
		ItemID:              body.ItemID,
		Status:              domain.StatusPending,
		AccessType:          body.AccessType,
		AssetName:           assetName,
		AssetType:           assetType,
		ResourceURL:         body.ResourceURL,
		AppImageID:          body.AppImageID,
		AppImageHash:        body.AppImageHash,
		ExpectedMeasurement: body.AppImageHash, // measurement IS the image hash for SEV-SNP
		ConsumerPublicKey:   body.ConsumerPublicKey,
		AdditionalInfo:      body.AdditionalInfo,
	}

	if err := s.repo.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create access request: %w", err)
	}

	// Temporary behavior: auto-approve all new requests.
	if err := s.approveEveryRequest(ctx, req.ID); err != nil {
		return nil, fmt.Errorf("auto-approve request: %w", err)
	}

	return s.repo.GetByID(ctx, req.ID)
}

// approveEveryRequest marks newly created requests as pre-approved.
func (s *AccessRequestService) approveEveryRequest(ctx context.Context, requestID string) error {
	return s.repo.AutoApprove(ctx, requestID)
}

// ---------------------------------------------------------------------------
// Phase 2 — Consumer triggers computation (starts TEE provisioning)
// ---------------------------------------------------------------------------

func (s *AccessRequestService) TriggerComputation(
	ctx context.Context,
	requestID, consumerID string,
) (*domain.AccessRequest, error) {

	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("get request: %w", err)
	}
	if req.ConsumerID != consumerID {
		return nil, errors.New("only the requesting consumer may trigger this computation")
	}
	if req.Status != domain.StatusPreApproved {
		return nil, fmt.Errorf("computation can only be triggered for PRE_APPROVED requests, current status: %s", req.Status)
	}
	if req.PreApprovalExpiry != nil && req.PreApprovalExpiry.Before(time.Now()) {
		return nil, errors.New("pre-approval has expired")
	}

	// Mark as provisioning before calling orchestrator (idempotency guard)
	if err := s.repo.UpdateStatus(ctx, requestID, domain.StatusTEEProvisioning); err != nil {
		return nil, err
	}

	// Submit contract to TEE Orchestrator — orchestrator spins up AMD SEV-SNP VM
	teeID, err := s.tee.ProvisionTEE(ctx, req)
	if err != nil {
		// Roll back to pre-approved so consumer can retry
		_ = s.repo.UpdateStatus(ctx, requestID, domain.StatusPreApproved)
		return nil, fmt.Errorf("TEE provisioning failed: %w", err)
	}

	if err := s.repo.SetTEEProvisioning(ctx, requestID, teeID); err != nil {
		return nil, err
	}

	// Transition to awaiting attestation — TEE will callback with its report
	if err := s.repo.UpdateStatus(ctx, requestID, domain.StatusAwaitingAttestation); err != nil {
		return nil, err
	}

	return s.repo.GetByID(ctx, requestID)
}

// ---------------------------------------------------------------------------
// Phase 3 — TEE submits attestation report (callback from TEE)
// ---------------------------------------------------------------------------

func (s *AccessRequestService) SubmitAttestation(
	ctx context.Context,
	requestID string,
	report domain.AttestationReport,
	providerEmail, consumerName string,
) error {
	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return err
	}
	if req.Status != domain.StatusAwaitingAttestation {
		return fmt.Errorf("unexpected status %s for attestation submission", req.Status)
	}

	// Verify AMD SEV-SNP attestation report
	teePublicKey, _, err := s.attest.Verify(report, req.ExpectedMeasurement, requestID)
	if err != nil {
		_ = s.repo.UpdateStatus(ctx, requestID, domain.StatusAttestationFailed)
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	// Persist TEE public key (extracted from report_data) — used to encrypt key bundle
	if err := s.repo.SetAttestationVerified(ctx, requestID, teePublicKey, report.RawReport); err != nil {
		return err
	}

	// Move to awaiting runtime consent and notify provider
	if err := s.repo.SetAwaitingRuntimeConsent(ctx, requestID); err != nil {
		return err
	}

	return s.consent.Issue(ctx, req, providerEmail, consumerName)
}

// ---------------------------------------------------------------------------
// Phase 4 — Provider approves at runtime (via consent token in email link)
// ---------------------------------------------------------------------------

func (s *AccessRequestService) ApproveRuntimeConsent(
	ctx context.Context,
	consentToken string,
	consumerEmail string,
) (*domain.AccessRequest, error) {

	requestID, err := s.consent.Consume(ctx, consentToken)
	if err != nil {
		return nil, err // invalid / expired token
	}

	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != domain.StatusAwaitingRuntimeConsent {
		return nil, fmt.Errorf("request is not awaiting runtime consent (status: %s)", req.Status)
	}

	if err := s.repo.SetRuntimeConsentGranted(ctx, requestID); err != nil {
		return nil, err
	}

	// For Case 1 (OPEN): no key needed — notify TEE to proceed directly
	if req.AccessType == domain.AccessTypeOpen {
		if err := s.signalTEEToFetch(ctx, req); err != nil {
			return nil, fmt.Errorf("signal TEE: %w", err)
		}
		_ = s.repo.UpdateStatus(ctx, requestID, domain.StatusDataFetching)
	}
	// For Cases 2 & 3: APD now awaits provider to submit the encrypted key bundle
	// (provider sees KEY_RELEASED status via GET on their dashboard)
	if req.AccessType == domain.AccessTypeSSHEncrypted || req.AccessType == domain.AccessTypeEncrypted {
		_ = s.repo.UpdateStatus(ctx, requestID, domain.StatusRuntimeConsentGranted)
	}

	_ = s.email.SendConsentGrantedToConsumer(consumerEmail, requestID, req.AssetName)

	return s.repo.GetByID(ctx, requestID)
}

// ---------------------------------------------------------------------------
// Phase 4 — Provider denies runtime consent
// ---------------------------------------------------------------------------

func (s *AccessRequestService) DenyRuntimeConsent(
	ctx context.Context,
	consentToken string,
	consumerEmail string,
) error {
	requestID, err := s.consent.Consume(ctx, consentToken)
	if err != nil {
		return err
	}

	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return err
	}

	if err := s.repo.UpdateStatus(ctx, requestID, domain.StatusConsentDenied); err != nil {
		return err
	}
	_ = s.consent.InvalidateAll(ctx, requestID)

	// Terminate the TEE that was spun up
	if req.TEEID != nil {
		_ = s.tee.TerminateTEE(ctx, *req.TEEID)
	}

	_ = s.email.SendConsentDenied(consumerEmail, requestID, req.AssetName)
	return nil
}

// ---------------------------------------------------------------------------
// Phase 4 (Cases 2 & 3) — Provider submits encrypted key bundle to APD
// ---------------------------------------------------------------------------

// ReceiveKeyBundle accepts the provider's encrypted key bundle,
// forwards it to the TEE, and never persists it.
func (s *AccessRequestService) ReceiveKeyBundle(
	ctx context.Context,
	requestID, providerID string,
	bundle domain.KeyBundle,
) error {
	req, err := s.repo.GetByID(ctx, requestID)
	if err != nil {
		return err
	}
	if req.ProviderID != providerID {
		return errors.New("only the owning provider may submit a key bundle")
	}
	if req.Status != domain.StatusRuntimeConsentGranted {
		return fmt.Errorf("key bundle can only be submitted after runtime consent (status: %s)", req.Status)
	}
	if req.AccessType == domain.AccessTypeOpen {
		return errors.New("open-access datasets do not require a key bundle")
	}
	if req.TEEID == nil {
		return errors.New("no active TEE instance for this request")
	}

	bundle.RequestID = requestID

	// Forward to TEE — APD is a transparent relay; key never stored
	if err := s.tee.ForwardKeyBundle(ctx, *req.TEEID, bundle); err != nil {
		return fmt.Errorf("forward key bundle to TEE: %w", err)
	}

	if err := s.repo.UpdateStatus(ctx, requestID, domain.StatusKeyReleased); err != nil {
		return err
	}
	if err := s.repo.UpdateStatus(ctx, requestID, domain.StatusDataFetching); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Phase 5 — TEE reports computation complete (callback from TEE)
// ---------------------------------------------------------------------------

func (s *AccessRequestService) TEEDataFetched(
	ctx context.Context,
	body domain.TEEDataFetchedBody,
	consumerEmail string,
) error {
	req, err := s.repo.GetByID(ctx, body.RequestID)
	if err != nil {
		return err
	}

	if err := s.repo.UpdateStatus(ctx, body.RequestID, domain.StatusComputationComplete); err != nil {
		return err
	}
	if err := s.repo.SetResultDelivered(ctx, body.RequestID, body.EncryptedResult); err != nil {
		return err
	}

	// Terminate TEE — computation is done
	if req.TEEID != nil {
		_ = s.tee.TerminateTEE(ctx, *req.TEEID)
	}

	_ = s.email.SendResultReady(consumerEmail, body.RequestID, req.AssetName)
	return nil
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------

func (s *AccessRequestService) GetByID(ctx context.Context, id string) (*domain.AccessRequest, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *AccessRequestService) ListByConsumer(ctx context.Context, consumerID string) ([]*domain.AccessRequest, error) {
	return s.repo.ListByConsumer(ctx, consumerID)
}

func (s *AccessRequestService) ListByProvider(ctx context.Context, providerID string) ([]*domain.AccessRequest, error) {
	return s.repo.ListByProvider(ctx, providerID)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// signalTEEToFetch notifies the TEE Orchestrator that consent was granted and
// the TEE may proceed to fetch data (used for Case 1 - open access).
func (s *AccessRequestService) signalTEEToFetch(ctx context.Context, req *domain.AccessRequest) error {
	if req.TEEID == nil {
		return errors.New("no TEE ID on request")
	}
	return s.tee.ForwardKeyBundle(ctx, *req.TEEID, domain.KeyBundle{
		RequestID:       req.ID,
		EncryptedBundle: "", // no keys needed for open access
	})
}
