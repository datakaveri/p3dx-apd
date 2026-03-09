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

const (
	snpReportSize     = 1184
	snpMeasurementOff = 0x90
	snpHostDataOff    = 0xC0
	snpReportDataOff  = 0x50
	snpPolicyOff      = 0x08
	snpVersionOff     = 0x00
	snpGuestSVNOff    = 0x04
	snpSignatureOff   = 0x2A0
)

const snpDebugPolicyBit = uint64(1 << 19)

type AttestationService struct {
	cfg     config.AMDConfig
	arkCert *x509.Certificate
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

func (s *AttestationService) Verify(
	report domain.AttestationReport,
	expectedMeasurement string,
	requestID string,
) (teePublicKeyPEM string, parsed *domain.ParsedSNPReport, err error) {

	rawBytes, err := base64.StdEncoding.DecodeString(report.RawReport)
	if err != nil {
		return "", nil, fmt.Errorf("decode raw report: %w", err)
	}

	if len(rawBytes) < snpReportSize {
		return "", nil, fmt.Errorf("report too short")
	}

	parsed = &domain.ParsedSNPReport{}
	parsed.Version = binary.LittleEndian.Uint32(rawBytes[snpVersionOff:])
	parsed.GuestSVN = binary.LittleEndian.Uint32(rawBytes[snpGuestSVNOff:])
	parsed.Policy = binary.LittleEndian.Uint64(rawBytes[snpPolicyOff:])

	copy(parsed.ReportData[:], rawBytes[snpReportDataOff:snpReportDataOff+64])
	copy(parsed.Measurement[:], rawBytes[snpMeasurementOff:snpMeasurementOff+48])
	copy(parsed.HostData[:], rawBytes[snpHostDataOff:snpHostDataOff+32])

	if !s.cfg.SkipChainVerification {
		if err := s.verifyCertChain(report); err != nil {
			return "", nil, err
		}
	}

	if !s.cfg.SkipChainVerification {
		if err := s.verifyReportSignature(rawBytes, report.VCEKCert); err != nil {
			return "", nil, err
		}
	}

	if parsed.Policy&snpDebugPolicyBit != 0 {
		return "", nil, fmt.Errorf("TEE running in debug mode")
	}

	expectedHostData, err := hashRequestID(requestID)
	if err != nil {
		return "", nil, err
	}

	var hdSlice [32]byte
	copy(hdSlice[:], expectedHostData)

	if hdSlice != parsed.HostData {
		return "", nil, fmt.Errorf("host_data mismatch")
	}

	expectedMeasBytes, err := hex.DecodeString(expectedMeasurement)
	if err != nil {
		return "", nil, err
	}

	if len(expectedMeasBytes) != 48 {
		return "", nil, fmt.Errorf("invalid measurement length")
	}

	var expMeas [48]byte
	copy(expMeas[:], expectedMeasBytes)

	if expMeas != parsed.Measurement {
		return "", nil, fmt.Errorf("measurement mismatch")
	}

	// Fix: ReportData is 64 bytes so cannot slice 65
	teePublicKeyPEM, err = ecPublicKeyToPEM(parsed.ReportData[:])
	if err != nil {
		return "", nil, err
	}

	return teePublicKeyPEM, parsed, nil
}

func (s *AttestationService) verifyCertChain(report domain.AttestationReport) error {

	arkCert := s.arkCert

	askCert, err := parsePEMCert(report.ASKCert)
	if err != nil {
		return err
	}

	vcekCert, err := parsePEMCert(report.VCEKCert)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	roots.AddCert(arkCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(askCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err = vcekCert.Verify(opts)
	return err
}

func (s *AttestationService) verifyReportSignature(rawReport []byte, vcekCertPEM string) error {

	vcekCert, err := parsePEMCert(vcekCertPEM)
	if err != nil {
		return err
	}

	ecPub, ok := vcekCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("VCEK key not ECDSA")
	}

	signedPart := rawReport[:snpSignatureOff]
	sigBytes := rawReport[snpSignatureOff : snpSignatureOff+96]

	rSig := new(big.Int).SetBytes(sigBytes[:48])
	sSig := new(big.Int).SetBytes(sigBytes[48:96])

	h := sha512.New384()
	h.Write(signedPart)
	digest := h.Sum(nil)

	if !ecdsa.Verify(ecPub, digest, rSig, sSig) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

func hashRequestID(requestID string) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(requestID))
	return h.Sum(nil), nil
}

func ecPublicKeyToPEM(raw []byte) (string, error) {

	if len(raw) < 65 {
		return "", fmt.Errorf("invalid EC key length")
	}

	curve := elliptic.P256()

	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(block)), nil
}

func parsePEMCert(pemStr string) (*x509.Certificate, error) {

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
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
