package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cdpg/dx/apd-go/internal/domain"
	"github.com/cdpg/dx/apd-go/internal/repository"
)

const consentTokenTTL = 30 * time.Minute

type ConsentService struct {
	consentRepo *repository.ConsentTokenRepo
	email       *EmailService
}

func NewConsentService(repo *repository.ConsentTokenRepo, email *EmailService) *ConsentService {
	return &ConsentService{consentRepo: repo, email: email}
}

// Issue generates a one-time consent token and emails the provider.
func (s *ConsentService) Issue(
	ctx context.Context,
	req *domain.AccessRequest,
	providerEmail, consumerName string,
) error {
	token, err := generateToken(32)
	if err != nil {
		return fmt.Errorf("generate consent token: %w", err)
	}

	ct := &domain.ConsentToken{
		Token:     token,
		RequestID: req.ID,
		ExpiresAt: time.Now().Add(consentTokenTTL),
		Used:      false,
		CreatedAt: time.Now(),
	}
	if err := s.consentRepo.Create(ctx, ct); err != nil {
		return fmt.Errorf("store consent token: %w", err)
	}

	// measurement is stored in ExpectedMeasurement — include in email so
	// the provider can verify the TEE binary themselves if they choose.
	return s.email.SendRuntimeConsentRequest(
		providerEmail,
		req.ID,
		consumerName,
		req.AssetName,
		req.ExpectedMeasurement,
		token,
	)
}

// Consume validates and marks the token as used. Returns the associated requestID.
func (s *ConsentService) Consume(ctx context.Context, token string) (requestID string, err error) {
	ct, err := s.consentRepo.Consume(ctx, token)
	if err != nil {
		return "", fmt.Errorf("invalid or expired consent token: %w", err)
	}
	return ct.RequestID, nil
}

// InvalidateAll marks all consent tokens for a request as used
// (called when provider explicitly denies, or when result is delivered).
func (s *ConsentService) InvalidateAll(ctx context.Context, requestID string) error {
	return s.consentRepo.InvalidateByRequest(ctx, requestID)
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
