package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/cdpg/dx/apd-go/internal/config"
	"github.com/cdpg/dx/apd-go/internal/domain"
)

// TEEService builds and submits contracts to the TEE Orchestrator.
type TEEService struct {
	cfg        config.TEEConfig
	signingKey *ecdsa.PrivateKey
	httpClient *http.Client
}

func NewTEEService(cfg config.TEEConfig, apdCfg config.APDConfig) (*TEEService, error) {
	key, err := loadECPrivateKey(apdCfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load APD signing key: %w", err)
	}
	return &TEEService{
		cfg:        cfg,
		signingKey: key,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// ProvisionTEE builds a Contract from the access request and sends it to the
// TEE Orchestrator. Returns the TEE instance ID assigned by the orchestrator.
func (s *TEEService) ProvisionTEE(ctx context.Context, req *domain.AccessRequest) (teeID string, err error) {
	contract, err := s.buildContract(req)
	if err != nil {
		return "", fmt.Errorf("build contract: %w", err)
	}

	// Sign the contract so the TEE Orchestrator and TEE itself can verify it
	// came from a legitimate APD.
	sig, err := s.signContract(contract)
	if err != nil {
		return "", fmt.Errorf("sign contract: %w", err)
	}
	contract.Signature = sig

	body, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/v1/tee/provision", s.cfg.OrchestratorURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("call TEE orchestrator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("TEE orchestrator returned status %d", resp.StatusCode)
	}

	var result struct {
		TEEID string `json:"teeId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode orchestrator response: %w", err)
	}
	if result.TEEID == "" {
		return "", fmt.Errorf("orchestrator returned empty teeId")
	}
	return result.TEEID, nil
}

// ForwardKeyBundle sends the provider's encrypted key bundle to the TEE.
// APD does NOT inspect or store the ciphertext — it is opaque.
func (s *TEEService) ForwardKeyBundle(ctx context.Context, teeID string, bundle domain.KeyBundle) error {
	body, err := json.Marshal(bundle)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/tee/%s/key-bundle", s.cfg.OrchestratorURL, teeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("forward key bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("key bundle delivery failed: status %d", resp.StatusCode)
	}
	return nil
}

// TerminateTEE instructs the orchestrator to tear down the TEE instance.
func (s *TEEService) TerminateTEE(ctx context.Context, teeID string) error {
	url := fmt.Sprintf("%s/v1/tee/%s/terminate", s.cfg.OrchestratorURL, teeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Contract construction
// ---------------------------------------------------------------------------

func (s *TEEService) buildContract(req *domain.AccessRequest) (*domain.Contract, error) {
	now := time.Now()

	contract := &domain.Contract{
		ContractID: uuid.NewString(),
		RequestID:  req.ID,
		ConsumerID: req.ConsumerID,
		ProviderID: req.ProviderID,

		AppDetails: domain.AppDetails{
			ImageID:   req.AppImageID,
			ImageHash: req.AppImageHash, // TEE must match this measurement
			Version:   "1.0",
		},

		DatasetDetails: domain.DatasetDetails{
			ItemID:      req.ItemID,
			AssetName:   req.AssetName,
			AssetType:   req.AssetType,
			ResourceURL: req.ResourceURL,
		},

		AccessConfig: domain.AccessConfig{
			Type: req.AccessType,
		},

		ConsumerPublicKey: req.ConsumerPublicKey,

		// TEE calls this URL with its attestation report
		APDCallbackURL: fmt.Sprintf("%s/api/v1/tee/attestation", s.cfg.APDBaseURL),

		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(s.cfg.MaxRuntimeMinutes) * time.Minute),
	}

	return contract, nil
}

// signContract signs a SHA-256 digest of the JSON-serialised contract (without
// the Signature field) using the APD's ECDSA private key.
func (s *TEEService) signContract(c *domain.Contract) (string, error) {
	// Temporarily clear signature field before hashing
	c.Signature = ""
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(data)
	r, sig, err := ecdsa.Sign(rand.Reader, s.signingKey, digest[:])
	if err != nil {
		return "", err
	}

	// Encode as r || s (each padded to 32 bytes for P-256)
	rb := r.Bytes()
	sb := sig.Bytes()
	rawSig := make([]byte, 64)
	copy(rawSig[32-len(rb):32], rb)
	copy(rawSig[64-len(sb):], sb)

	return base64.StdEncoding.EncodeToString(rawSig), nil
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		ki, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EC key (%v / %v)", err, err2)
		}
		var ok bool
		key, ok = ki.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in %s is not ECDSA", path)
		}
	}
	return key, nil
}

// signContract uses math/big for ECDSA signature encoding
var _ *big.Int
