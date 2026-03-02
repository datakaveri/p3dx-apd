package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cdpg/dx/apd-go/internal/domain"
)

type ConsentTokenRepo struct {
	db *pgxpool.Pool
}

func NewConsentTokenRepo(db *pgxpool.Pool) *ConsentTokenRepo {
	return &ConsentTokenRepo{db: db}
}

func (r *ConsentTokenRepo) Create(ctx context.Context, ct *domain.ConsentToken) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO consent_tokens (token, request_id, expires_at, used, created_at)
		VALUES ($1, $2, $3, false, $4)`,
		ct.Token, ct.RequestID, ct.ExpiresAt, time.Now(),
	)
	return err
}

// Consume atomically marks the token as used and returns it.
// Returns an error if the token is not found, already used, or expired.
func (r *ConsentTokenRepo) Consume(ctx context.Context, token string) (*domain.ConsentToken, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE consent_tokens
		SET used = true
		WHERE token = $1
		  AND used = false
		  AND expires_at > NOW()
		RETURNING token, request_id, expires_at, used, created_at`, token)

	var ct domain.ConsentToken
	err := row.Scan(&ct.Token, &ct.RequestID, &ct.ExpiresAt, &ct.Used, &ct.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("consume consent token: %w", err)
	}
	return &ct, nil
}

// InvalidateByRequest marks all tokens for a request as used (e.g. on denial).
func (r *ConsentTokenRepo) InvalidateByRequest(ctx context.Context, requestID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE consent_tokens SET used = true WHERE request_id = $1`, requestID)
	return err
}
