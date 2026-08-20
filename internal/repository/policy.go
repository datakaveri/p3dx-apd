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

const policyCols = `policy_id, item_id, issued_by, provider_id, provider_email, is_private, rules, issued_at, expires_at`

func (r *PolicyRepo) Upsert(ctx context.Context, p *domain.Policy) error {
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO policies (policy_id, item_id, issued_by, provider_id, provider_email, is_private, rules, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (policy_id) DO UPDATE SET
			item_id=$2, issued_by=$3, provider_id=$4, provider_email=$5, is_private=$6, rules=$7, issued_at=$8, expires_at=$9`,
		p.PolicyID, p.ItemID, p.IssuedBy, p.ProviderID, p.ProviderEmail, p.IsPrivate, rules, p.IssuedAt, p.ExpiresAt,
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

// GetLatestByItemID returns the most recently issued, non-expired policy for itemID.
func (r *PolicyRepo) GetLatestByItemID(ctx context.Context, itemID string, now time.Time) (*domain.Policy, error) {
	row := r.db.QueryRow(ctx, `
		SELECT `+policyCols+` FROM policies
		WHERE item_id=$1 AND (expires_at IS NULL OR expires_at > $2)
		ORDER BY issued_at DESC LIMIT 1`, itemID, now)
	p, err := scanPolicy(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// ListDatasetNames returns the distinct dataset names carried in
// rules.dataset.name across all policies (set via the "Set Policy" page).
func (r *PolicyRepo) ListDatasetNames(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT rules->'dataset'->>'name' AS name
		FROM policies
		WHERE rules->'dataset'->>'name' IS NOT NULL AND rules->'dataset'->>'name' <> ''
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func scanPolicy(row pgx.Row) (*domain.Policy, error) {
	var p domain.Policy
	var rulesRaw []byte
	var providerID, providerEmail *string
	err := row.Scan(&p.PolicyID, &p.ItemID, &p.IssuedBy, &providerID, &providerEmail, &p.IsPrivate, &rulesRaw, &p.IssuedAt, &p.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if providerID != nil {
		p.ProviderID = *providerID
	}
	if providerEmail != nil {
		p.ProviderEmail = *providerEmail
	}
	if len(rulesRaw) > 0 {
		_ = json.Unmarshal(rulesRaw, &p.Rules)
	}
	return &p, nil
}
