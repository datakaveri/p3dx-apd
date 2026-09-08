package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cdpg/dx/apd-go/internal/domain"
)

type PolicyRepo struct {
	db *pgxpool.Pool
}

func NewPolicyRepo(db *pgxpool.Pool) *PolicyRepo {
	return &PolicyRepo{db: db}
}

const policyCols = `policy_id, item_id, issued_by, dataset_id, provider_id, provider_email, is_private, data_url, rules, issued_at, expires_at`

func (r *PolicyRepo) Upsert(ctx context.Context, p *domain.Policy) error {
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO policies (policy_id, item_id, issued_by, dataset_id, provider_id, provider_email, is_private, data_url, rules, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (policy_id) DO UPDATE SET
			item_id=$2, issued_by=$3, dataset_id=$4, provider_id=$5, provider_email=$6, is_private=$7, data_url=$8, rules=$9, issued_at=$10, expires_at=$11`,
		p.PolicyID, p.ItemID, p.IssuedBy, p.DatasetID, p.ProviderID, p.ProviderEmail, p.IsPrivate, p.DataURL, rules, p.IssuedAt, p.ExpiresAt,
	)
	return err
}

func (r *PolicyRepo) GetByID(ctx context.Context, policyID string) (*domain.Policy, error) {
	row := r.db.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE policy_id=$1`, policyID)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// GetLatestByItemID returns the most recently issued, non-expired, non-deleted
// policy for itemID.
func (r *PolicyRepo) GetLatestByItemID(ctx context.Context, itemID string, now time.Time) (*domain.Policy, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+policyCols+` FROM policies
		WHERE item_id=$1 AND NOT deleted AND (expires_at IS NULL OR expires_at > $2)
		ORDER BY issued_at DESC LIMIT 1`, itemID, now)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// ListDatasetSummaries returns the dataset catalogue: one {item_id, name} row
// per distinct dataset item_id that has an access policy set (via the "Set
// Policy" page), using each item_id's most recently issued policy for the
// name. DISTINCT ON (item_id) (not name) so the id a caller gets back is
// always a real item_id a by-item lookup (GetLatestByItemID) can find —
// grouping by name instead would return the display label as the only key,
// which doesn't match anything in the policies table's item_id column.
func (r *PolicyRepo) ListDatasetSummaries(ctx context.Context) ([]domain.DatasetSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (item_id) item_id, rules->'dataset'->>'name' AS name
		FROM policies
		WHERE NOT deleted AND rules->'dataset'->>'name' IS NOT NULL AND rules->'dataset'->>'name' <> ''
		ORDER BY item_id, issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	datasets := []domain.DatasetSummary{}
	for rows.Next() {
		var d domain.DatasetSummary
		if err := rows.Scan(&d.ItemID, &d.Name); err != nil {
			return nil, err
		}
		datasets = append(datasets, d)
	}
	return datasets, rows.Err()
}

// ListInfraProviders returns the Infrastructure Catalogue: one row per
// distinct infra id (item_id) that has an infra-provider policy set (via the
// "Set Infrastructure Policy" page), using each id's most recently issued
// policy. DISTINCT ON item_id (not a plain DISTINCT like ListDatasetNames)
// because InfraPolicyForm.jsx mints a fresh policyId on every submit, so
// re-registering the same infra creates a new row rather than updating the
// old one — without this, a re-registered infra would show up twice.
func (r *PolicyRepo) ListInfraProviders(ctx context.Context) ([]domain.InfraSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (item_id)
			item_id,
			COALESCE(rules->'infrastructure'->>'name', '') AS name,
			COALESCE(rules->'infrastructure'->>'region', '') AS region,
			COALESCE(rules->'infrastructure'->'platform'->>'provider', '') AS provider
		FROM policies
		WHERE NOT deleted AND rules->>'policy_type' = 'infra-provider'
		ORDER BY item_id, issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	infra := []domain.InfraSummary{}
	for rows.Next() {
		var s domain.InfraSummary
		if err := rows.Scan(&s.ItemID, &s.Name, &s.Region, &s.Provider); err != nil {
			return nil, err
		}
		infra = append(infra, s)
	}
	return infra, rows.Err()
}

// ListByProvider returns the "My Infrastructure" list for one provider: one
// row per distinct infra item_id owned by providerID, using each id's most
// recently issued, non-deleted policy. Same DISTINCT ON (item_id) dedup as
// ListInfraProviders, additionally scoped by provider_id and including
// issued_at for the dashboard's "Issued" column.
func (r *PolicyRepo) ListByProvider(ctx context.Context, providerID string) ([]domain.InfraSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (item_id)
			item_id,
			COALESCE(rules->'infrastructure'->>'name', '') AS name,
			COALESCE(rules->'infrastructure'->>'region', '') AS region,
			COALESCE(rules->'infrastructure'->'platform'->>'provider', '') AS provider,
			issued_at
		FROM policies
		WHERE NOT deleted AND provider_id=$1 AND rules->>'policy_type' = 'infra-provider'
		ORDER BY item_id, issued_at DESC`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	infra := []domain.InfraSummary{}
	for rows.Next() {
		var s domain.InfraSummary
		if err := rows.Scan(&s.ItemID, &s.Name, &s.Region, &s.Provider, &s.IssuedAt); err != nil {
			return nil, err
		}
		infra = append(infra, s)
	}
	return infra, rows.Err()
}

// ListDatasetsByProvider returns the "My Datasets" list for one provider: one
// row per distinct dataset item_id owned by providerID, using each id's most
// recently issued, non-deleted policy. Mirrors ListByProvider exactly (same
// DISTINCT ON (item_id) dedup, same provider_id scoping), filtered on
// rules.policy_type = 'data-provider' instead of 'infra-provider'.
func (r *PolicyRepo) ListDatasetsByProvider(ctx context.Context, providerID string) ([]domain.MyDatasetSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (item_id)
			item_id,
			COALESCE(rules->'dataset'->>'name', '') AS name,
			COALESCE(rules->'application'->>'name', '') AS application,
			COALESCE(rules->>'accessLevel', '') AS access_level,
			issued_at
		FROM policies
		WHERE NOT deleted AND provider_id=$1 AND rules->>'policy_type' = 'data-provider'
		ORDER BY item_id, issued_at DESC`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	datasets := []domain.MyDatasetSummary{}
	for rows.Next() {
		var s domain.MyDatasetSummary
		if err := rows.Scan(&s.ItemID, &s.Name, &s.Application, &s.AccessLevel, &s.IssuedAt); err != nil {
			return nil, err
		}
		datasets = append(datasets, s)
	}
	return datasets, rows.Err()
}

// SoftDeleteByItemAndProvider tombstones every row sharing itemID, scoped to
// providerID in the same statement — this is both the ownership check and the
// delete itself, atomically (no separate read-then-write). Tombstoning every
// row for the item_id (not just the latest) prevents an older, non-deleted
// revision from "resurfacing" as the new latest row in any DISTINCT ON
// (item_id) query above. Returns false if nothing matched — the item doesn't
// exist, is already deleted, or belongs to a different provider (the caller
// can't distinguish which, by design).
func (r *PolicyRepo) SoftDeleteByItemAndProvider(ctx context.Context, itemID, providerID string) (bool, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE policies SET deleted=TRUE, deleted_at=$1 WHERE item_id=$2 AND provider_id=$3 AND NOT deleted`,
		time.Now(), itemID, providerID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func scanPolicy(row pgx.Row) (*domain.Policy, error) {
	var p domain.Policy
	var rulesRaw []byte
	err := row.Scan(&p.PolicyID, &p.ItemID, &p.IssuedBy, &p.DatasetID, &p.ProviderID, &p.ProviderEmail, &p.IsPrivate, &p.DataURL, &rulesRaw, &p.IssuedAt, &p.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if len(rulesRaw) > 0 {
		_ = json.Unmarshal(rulesRaw, &p.Rules)
	}
	return &p, nil
}
