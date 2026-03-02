package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cdpg/dx/apd-go/internal/domain"
)

type AccessRequestRepo struct {
	db *pgxpool.Pool
}

func NewAccessRequestRepo(db *pgxpool.Pool) *AccessRequestRepo {
	return &AccessRequestRepo{db: db}
}

func (r *AccessRequestRepo) Create(ctx context.Context, req *domain.AccessRequest) error {
	info, _ := json.Marshal(req.AdditionalInfo)
	_, err := r.db.Exec(ctx, `
		INSERT INTO access_requests (
			id, consumer_id, provider_id, item_id, status, access_type,
			asset_name, asset_type, resource_url,
			app_image_id, app_image_hash, expected_measurement,
			consumer_public_key, additional_info, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15
		)`,
		req.ID, req.ConsumerID, req.ProviderID, req.ItemID,
		string(req.Status), string(req.AccessType),
		req.AssetName, req.AssetType, req.ResourceURL,
		req.AppImageID, req.AppImageHash, req.ExpectedMeasurement,
		req.ConsumerPublicKey, info, time.Now(),
	)
	return err
}

func (r *AccessRequestRepo) GetByID(ctx context.Context, id string) (*domain.AccessRequest, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, consumer_id, provider_id, item_id, status, access_type,
		       asset_name, asset_type, resource_url,
		       app_image_id, app_image_hash, expected_measurement,
		       consumer_public_key,
		       tee_id, tee_public_key,
		       attestation_report, attestation_verified_at,
		       pre_approved_at, pre_approval_expiry,
		       consent_requested_at, consent_granted_at,
		       encrypted_result, additional_info,
		       created_at, updated_at
		FROM access_requests WHERE id = $1`, id)

	return scanRequest(row)
}

func (r *AccessRequestRepo) ListByConsumer(ctx context.Context, consumerID string) ([]*domain.AccessRequest, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, consumer_id, provider_id, item_id, status, access_type,
		       asset_name, asset_type, resource_url,
		       app_image_id, app_image_hash, expected_measurement,
		       consumer_public_key,
		       tee_id, tee_public_key,
		       attestation_report, attestation_verified_at,
		       pre_approved_at, pre_approval_expiry,
		       consent_requested_at, consent_granted_at,
		       encrypted_result, additional_info,
		       created_at, updated_at
		FROM access_requests WHERE consumer_id = $1 ORDER BY created_at DESC`, consumerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequests(rows)
}

func (r *AccessRequestRepo) ListByProvider(ctx context.Context, providerID string) ([]*domain.AccessRequest, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, consumer_id, provider_id, item_id, status, access_type,
		       asset_name, asset_type, resource_url,
		       app_image_id, app_image_hash, expected_measurement,
		       consumer_public_key,
		       tee_id, tee_public_key,
		       attestation_report, attestation_verified_at,
		       pre_approved_at, pre_approval_expiry,
		       consent_requested_at, consent_granted_at,
		       encrypted_result, additional_info,
		       created_at, updated_at
		FROM access_requests WHERE provider_id = $1 ORDER BY created_at DESC`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRequests(rows)
}

// UpdateStatus is used for simple single-field status transitions.
func (r *AccessRequestRepo) UpdateStatus(ctx context.Context, id string, status domain.Status) error {
	_, err := r.db.Exec(ctx,
		`UPDATE access_requests SET status=$1, updated_at=$2 WHERE id=$3`,
		string(status), time.Now(), id)
	return err
}

func (r *AccessRequestRepo) SetPreApproved(ctx context.Context, id string, expiry time.Time) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, pre_approved_at=$2, pre_approval_expiry=$3, updated_at=$2
		WHERE id=$4`,
		string(domain.StatusPreApproved), now, expiry, id)
	return err
}

// AutoApprove marks a request as pre-approved without an expiry window.
func (r *AccessRequestRepo) AutoApprove(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, pre_approved_at=$2, pre_approval_expiry=NULL, updated_at=$2
		WHERE id=$3`,
		string(domain.StatusPreApproved), now, id)
	return err
}

func (r *AccessRequestRepo) SetTEEProvisioning(ctx context.Context, id, teeID string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, tee_id=$2, updated_at=$3
		WHERE id=$4`,
		string(domain.StatusTEEProvisioning), teeID, time.Now(), id)
	return err
}

func (r *AccessRequestRepo) SetAttestationVerified(ctx context.Context, id, teePublicKey, rawReport string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, tee_public_key=$2, attestation_report=$3,
		    attestation_verified_at=$4, updated_at=$4
		WHERE id=$5`,
		string(domain.StatusAttestationVerified), teePublicKey, rawReport, now, id)
	return err
}

func (r *AccessRequestRepo) SetAwaitingRuntimeConsent(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, consent_requested_at=$2, updated_at=$2
		WHERE id=$3`,
		string(domain.StatusAwaitingRuntimeConsent), now, id)
	return err
}

func (r *AccessRequestRepo) SetRuntimeConsentGranted(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, consent_granted_at=$2, updated_at=$2
		WHERE id=$3`,
		string(domain.StatusRuntimeConsentGranted), now, id)
	return err
}

func (r *AccessRequestRepo) SetResultDelivered(ctx context.Context, id, encryptedResult string) error {
	now := time.Now()
	_, err := r.db.Exec(ctx, `
		UPDATE access_requests
		SET status=$1, encrypted_result=$2, updated_at=$3
		WHERE id=$4`,
		string(domain.StatusResultDelivered), encryptedResult, now, id)
	return err
}

// ---------------------------------------------------------------------------
// Scanning helpers
// ---------------------------------------------------------------------------

type scannable interface {
	Scan(dest ...any) error
}

func scanRequest(row scannable) (*domain.AccessRequest, error) {
	var req domain.AccessRequest
	var status, accessType string
	var additionalInfoRaw []byte

	err := row.Scan(
		&req.ID, &req.ConsumerID, &req.ProviderID, &req.ItemID,
		&status, &accessType,
		&req.AssetName, &req.AssetType, &req.ResourceURL,
		&req.AppImageID, &req.AppImageHash, &req.ExpectedMeasurement,
		&req.ConsumerPublicKey,
		&req.TEEID, &req.TEEPublicKey,
		&req.AttestationReport, &req.AttestationVerifiedAt,
		&req.PreApprovedAt, &req.PreApprovalExpiry,
		&req.ConsentRequestedAt, &req.ConsentGrantedAt,
		&req.EncryptedResult, &additionalInfoRaw,
		&req.CreatedAt, &req.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan access request: %w", err)
	}

	req.Status = domain.Status(status)
	req.AccessType = domain.AccessType(accessType)

	if additionalInfoRaw != nil {
		_ = json.Unmarshal(additionalInfoRaw, &req.AdditionalInfo)
	}
	return &req, nil
}

func scanRequests(rows interface{ Next() bool; Err() error; Scan(...any) error }) ([]*domain.AccessRequest, error) {
	var reqs []*domain.AccessRequest
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, req)
	}
	return reqs, rows.Err()
}
