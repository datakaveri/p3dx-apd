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

type FormSubmissionRepo struct {
	db *pgxpool.Pool
}

func NewFormSubmissionRepo(db *pgxpool.Pool) *FormSubmissionRepo {
	return &FormSubmissionRepo{db: db}
}

const formSubmissionCols = `
	id, form_id, requested_by, output_owner_id,
	num_server_rounds, fraction_evaluate, local_epochs, learning_rate, batch_size,
	model, framework, components, filled, requested_at, filled_at,
	selected_providers, ip_address, port, ram_usage, created_at, updated_at`

// Upsert resolves the live row for sub.FormID (if any) and reuses its id, so
// a re-submit for the same form overwrites in place instead of creating a
// second row — mirroring the upsert-by-formId behavior the old immudb store
// implemented.
func (r *FormSubmissionRepo) Upsert(ctx context.Context, sub *domain.FormSubmission) error {
	var existingID string
	err := r.db.QueryRow(ctx,
		`SELECT id FROM form_submissions WHERE form_id=$1 AND NOT deleted`, sub.FormID,
	).Scan(&existingID)
	if err == nil {
		sub.ID = existingID
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	components, err := json.Marshal(sub.Components)
	if err != nil {
		return err
	}
	selected, err := json.Marshal(sub.SelectedProviders)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(ctx, `
		INSERT INTO form_submissions (
			id, form_id, requested_by, output_owner_id,
			num_server_rounds, fraction_evaluate, local_epochs, learning_rate, batch_size,
			model, framework, components, filled, requested_at, filled_at,
			selected_providers, ip_address, port, ram_usage
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
		)
		ON CONFLICT (id) DO UPDATE SET
			form_id=$2, requested_by=$3, output_owner_id=$4,
			num_server_rounds=$5, fraction_evaluate=$6, local_epochs=$7, learning_rate=$8, batch_size=$9,
			model=$10, framework=$11, components=$12, filled=$13, requested_at=$14, filled_at=$15,
			selected_providers=$16, ip_address=$17, port=$18, ram_usage=$19`,
		sub.ID, sub.FormID, sub.RequestedBy, sub.OutputOwnerID,
		sub.NumServerRounds, sub.FractionEvaluate, sub.LocalEpochs, sub.LearningRate, sub.BatchSize,
		sub.Model, sub.Framework, components, sub.Filled, sub.RequestedAt, sub.FilledAt,
		selected, sub.IPAddress, sub.Port, sub.RAMUsage,
	)
	return err
}

func (r *FormSubmissionRepo) GetByID(ctx context.Context, id string) (*domain.FormSubmission, error) {
	row := r.db.QueryRow(ctx,
		`SELECT `+formSubmissionCols+` FROM form_submissions WHERE id=$1 AND NOT deleted`, id)

	sub, err := scanFormSubmission(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return sub, err
}

func (r *FormSubmissionRepo) List(ctx context.Context) ([]*domain.FormSubmission, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+formSubmissionCols+` FROM form_submissions WHERE NOT deleted ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []*domain.FormSubmission
	for rows.Next() {
		sub, err := scanFormSubmission(rows)
		if err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

// SoftDelete tombstones a row instead of removing it, matching the old
// immudb store's delete semantics (append-only, no real delete).
func (r *FormSubmissionRepo) SoftDelete(ctx context.Context, id string) (bool, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE form_submissions SET deleted=TRUE, deleted_at=$1 WHERE id=$2 AND NOT deleted`,
		time.Now(), id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func scanFormSubmission(row pgx.Row) (*domain.FormSubmission, error) {
	var sub domain.FormSubmission
	var componentsRaw, selectedRaw []byte

	err := row.Scan(
		&sub.ID, &sub.FormID, &sub.RequestedBy, &sub.OutputOwnerID,
		&sub.NumServerRounds, &sub.FractionEvaluate, &sub.LocalEpochs, &sub.LearningRate, &sub.BatchSize,
		&sub.Model, &sub.Framework, &componentsRaw, &sub.Filled, &sub.RequestedAt, &sub.FilledAt,
		&selectedRaw, &sub.IPAddress, &sub.Port, &sub.RAMUsage, &sub.CreatedAt, &sub.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if len(componentsRaw) > 0 {
		_ = json.Unmarshal(componentsRaw, &sub.Components)
	}
	if len(selectedRaw) > 0 {
		_ = json.Unmarshal(selectedRaw, &sub.SelectedProviders)
	}
	return &sub, nil
}
