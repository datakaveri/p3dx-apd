package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/cdpg/dx/apd-go/internal/config"
	"github.com/cdpg/dx/apd-go/internal/domain"
)

// AMD SEV-SNP attestation report layout (1184 bytes total).
// Ref: AMD SEV-SNP API Specification, Section 8.17 (ATTESTATION_REPORT).
const (
	snpReportSize       = 1184
	snpMeasurementOff  = 0x90 // offset 144, 48 bytes  (SHA-384)
	snpHostDataOff     = 0xC0 // offset 192, 32 bytes
	snpReportDataOff   = 0x50 // offset  80, 64 bytes  (guest-provided, TEE puts EC pub key here)
	snpPolicyOff       = 0x08 // offset   8, 8 bytes   (uint64)
	snpVersionOff      = 0x00 // offset   0, 4 bytes
	snpGuestSVNOff     = 0x04 // offset   4, 4 bytes
	snpSignatureOff    = 0x2A0 // offset 672, 512 bytes
)

// Policy bit: if bit 19 is set, debug mode is enabled — NOT allowed in production.
const snpDebugPolicyBit = uint64(1 << 19)

type AttestationService struct {
	cfg    config.AMDConfig
	arkCert *x509.Certificate // AMD Root Key
}

func NewAttestationService(cfg config.AMDConfig) (*AttestationService, error) {
	svc := &AttestationService{cfg: cfg}

	if !cfg.SkipChainVerification && cfg.ARKCertPath != "" {
		cert, err := loadCert(cfg.ARKCertPath)
		if err != nil {
			return nil, fmt.Errorf("load AMD ARK cert: %w", err)
		}
		svc.arkCert = cert
	}
	return svc, nil
}

// Verify validates an AMD SEV-SNP attestation report and returns the parsed fields.
//
// Steps performed:
//  1. Decode the raw report from base64.
//  2. Parse the binary report structure (measurement, host_data, report_data, policy).
//  3. Verify the AMD VCEK certificate chain (ARK → ASK → VCEK).
//  4. Verify the report signature using the VCEK public key.
//  5. Enforce security policy (no debug mode).
//  6. Check that host_data contains the expected requestID hash.
//  7. Check that measurement matches the expected TEE binary hash.
//
// Returns the TEE's ephemeral EC public key (from report_data) as PEM,
// which is used to encrypt the key bundle delivered to the TEE.
func (s *AttestationService) Verify(
	report domain.AttestationReport,
	expectedMeasurement string, // hex-encoded SHA-384 of the trusted TEE binary
	requestID string,            // used to verify host_data binding
) (teePublicKeyPEM string, parsed *domain.ParsedSNPReport, err error) {

	// 1. Decode raw report
	rawBytes, err := base64.StdEncoding.DecodeString(report.RawReport)
	if err != nil {
		return "", nil, fmt.Errorf("decode raw report: %w", err)
	}
	if len(rawBytes) < snpReportSize {
		return "", nil, fmt.Errorf("report too short: got %d, want %d", len(rawBytes), snpReportSize)
	}

	// 2. Parse binary fields
	parsed = &domain.ParsedSNPReport{}
	parsed.Version = binary.LittleEndian.Uint32(rawBytes[snpVersionOff:])
	parsed.GuestSVN = binary.LittleEndian.Uint32(rawBytes[snpGuestSVNOff:])
	parsed.Policy = binary.LittleEndian.Uint64(rawBytes[snpPolicyOff:])
	copy(parsed.ReportData[:], rawBytes[snpReportDataOff:snpReportDataOff+64])
	copy(parsed.Measurement[:], rawBytes[snpMeasurementOff:snpMeasurementOff+48])
	copy(parsed.HostData[:], rawBytes[snpHostDataOff:snpHostDataOff+32])

	// 3. Verify certificate chain ARK → ASK → VCEK
	if !s.cfg.SkipChainVerification {
		if err := s.verifyCertChain(report); err != nil {
			return "", nil, fmt.Errorf("cert chain verification failed: %w", err)
		}
	}

	// 4. Verify report signature with VCEK public key
	if !s.cfg.SkipChainVerification {
		if err := s.verifyReportSignature(rawBytes, report.VCEKCert); err != nil {
			return "", nil, fmt.Errorf("report signature verification failed: %w", err)
		}
	}

	// 5. Enforce security policy — debug bit MUST be 0
	if parsed.Policy&snpDebugPolicyBit != 0 {
		return "", nil, fmt.Errorf("TEE is running in debug mode — not allowed in production")
	}

	// 6. Verify host_data encodes the requestID
	//    Convention: host_data[0:32] = SHA-256(requestID)
	expectedHostData, err := hashRequestID(requestID)
	if err != nil {
		return "", nil, err
	}
	var hdSlice [32]byte
	copy(hdSlice[:], expectedHostData)
	if hdSlice != parsed.HostData {
		return "", nil, fmt.Errorf(
			"host_data mismatch: report does not bind to request %s", requestID)
	}

	// 7. Verify measurement matches the trusted TEE binary
	expectedMeasBytes, err := hex.DecodeString(expectedMeasurement)
	if err != nil {
		return "", nil, fmt.Errorf("invalid expected measurement hex: %w", err)
	}
	if len(expectedMeasBytes) != 48 {
		return "", nil, fmt.Errorf("expected measurement must be 48 bytes (SHA-384)")
	}
	var expMeas [48]byte
	copy(expMeas[:], expectedMeasBytes)
	if expMeas != parsed.Measurement {
		return "", nil, fmt.Errorf(
			"measurement mismatch: TEE binary does not match trusted image\n  got : %x\n  want: %x",
			parsed.Measurement, expMeas)
	}

	// 8. Extract TEE ephemeral EC public key from report_data
	//    Convention: report_data[0:65] = uncompressed EC P-256 public key (04 || X || Y)
	teePublicKeyPEM, err = ecPublicKeyToPEM(parsed.ReportData[:65])
	if err != nil {
		return "", nil, fmt.Errorf("extract TEE public key from report_data: %w", err)
	}

	return teePublicKeyPEM, parsed, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (s *AttestationService) verifyCertChain(report domain.AttestationReport) error {
	arkCert := s.arkCert // already loaded at startup

	askCert, err := parsePEMCert(report.ASKCert)
	if err != nil {
		return fmt.Errorf("parse ASK cert: %w", err)
	}
	vcekCert, err := parsePEMCert(report.VCEKCert)
	if err != nil {
		return fmt.Errorf("parse VCEK cert: %w", err)
	}

	// ARK self-signed → ASK → VCEK
	roots := x509.NewCertPool()
	roots.AddCert(arkCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(askCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := vcekCert.Verify(opts); err != nil {
		return fmt.Errorf("VCEK cert chain invalid: %w", err)
	}
	return nil
}

func (s *AttestationService) verifyReportSignature(rawReport []byte, vcekCertPEM string) error {
	vcekCert, err := parsePEMCert(vcekCertPEM)
	if err != nil {
		return err
	}
	ecPub, ok := vcekCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("VCEK public key is not ECDSA")
	}

	// The AMD SNP signature covers bytes [0 : snpSignatureOff] of the report.
	// The signature itself is stored at [snpSignatureOff : snpSignatureOff+512]
	// as a P-384 ECDSA signature (r || s, each 48 bytes, zero-padded to 72).
	signedPart := rawReport[:snpSignatureOff]
	sigBytes := rawReport[snpSignatureOff : snpSignatureOff+96] // r(48) + s(48)

	r := new(big.Int).SetBytes(sigBytes[:48])
	s := new(big.Int).SetBytes(sigBytes[48:96])

	// SHA-384 digest of the signed portion
	h := sha512.New384()
	h.Write(signedPart)
	digest := h.Sum(nil)

	if !ecdsa.Verify(ecPub, digest, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// hashRequestID returns SHA-256(requestID) as 32 bytes.
func hashRequestID(requestID string) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(requestID))
	return h.Sum(nil), nil
}

// ecPublicKeyToPEM converts an uncompressed EC P-256 point (65 bytes) to PEM.
func ecPublicKeyToPEM(raw []byte) (string, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return "", fmt.Errorf("expected uncompressed P-256 point (65 bytes starting with 0x04)")
	}
	curve := elliptic.P256()
	x, y := new(big.Int).SetBytes(raw[1:33]), new(big.Int).SetBytes(raw[33:65])
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parsePEMCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePEMCert(string(data))
}
