package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cdpg/dx/apd-go/internal/domain"
)

type ProviderFormRepo struct {
	db *pgxpool.Pool
}

func NewProviderFormRepo(db *pgxpool.Pool) *ProviderFormRepo {
	return &ProviderFormRepo{db: db}
}

// Insert always creates a new row — unlike form_submissions, provider forms
// have no upsert-by-formId behavior to preserve.
func (r *ProviderFormRepo) Insert(ctx context.Context, f *domain.ProviderForm) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO provider_forms (
			id, form_id, data_owner_id, dataset_name, dataset_location_url, ram, memory_mb, data_size_bytes,
			data_resource_id, ip_address, port, ram_usage, filled, filled_at, submitted_by
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
		)`,
		f.ID, f.FormID, f.DataOwnerID, f.DatasetName, f.DatasetLocationURL, f.RAM, f.MemoryMB, f.DataSizeBytes,
		f.DataResourceID, f.IPAddress, f.Port, f.RAMUsage, f.Filled, f.FilledAt, f.SubmittedBy,
	)
	return err
}

const providerFormCols = `id, form_id, data_owner_id, dataset_name, ram, memory_mb, data_size_bytes,
	data_resource_id, ip_address, port, ram_usage, filled, filled_at, submitted_by, created_at`

// ListByDatasetName returns provider forms, most-recently-submitted first.
// An empty datasetName returns every provider form; otherwise it matches
// dataset_name case-insensitively.
func (r *ProviderFormRepo) ListByDatasetName(ctx context.Context, datasetName string) ([]*domain.ProviderForm, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+providerFormCols+`
		FROM provider_forms
		WHERE $1 = '' OR LOWER(dataset_name) = LOWER($1)
		ORDER BY created_at DESC`, datasetName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	forms := []*domain.ProviderForm{}
	for rows.Next() {
		var f domain.ProviderForm
		if err := rows.Scan(
			&f.ID, &f.FormID, &f.DataOwnerID, &f.DatasetName, &f.RAM, &f.MemoryMB, &f.DataSizeBytes,
			&f.DataResourceID, &f.IPAddress, &f.Port, &f.RAMUsage, &f.Filled, &f.FilledAt, &f.SubmittedBy, &f.CreatedAt,
		); err != nil {
			return nil, err
		}
		forms = append(forms, &f)
	}
	return forms, rows.Err()
}

// ListDatasetNames returns the distinct, non-empty dataset names submitted by
// data providers, most-recently-submitted first.
func (r *ProviderFormRepo) ListDatasetNames(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (dataset_name) dataset_name
		FROM provider_forms
		WHERE dataset_name IS NOT NULL AND dataset_name <> ''
		ORDER BY dataset_name, created_at DESC`)
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
