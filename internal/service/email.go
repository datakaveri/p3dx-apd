package service

import (
	"fmt"
	"net/smtp"
	"strings"

	"github.com/cdpg/dx/apd-go/internal/config"
)

type EmailService struct {
	cfg config.EmailConfig
}

func NewEmailService(cfg config.EmailConfig) *EmailService {
	return &EmailService{cfg: cfg}
}

// SendRuntimeConsentRequest emails the provider a one-time consent link.
func (s *EmailService) SendRuntimeConsentRequest(
	providerEmail, requestID, consumerName, assetName, measurement, consentToken string,
) error {
	subject := fmt.Sprintf("[DX APD] Runtime Consent Required – %s", assetName)
	approveURL := fmt.Sprintf("%s/%s/approve", s.cfg.ConsentBaseURL, consentToken)
	denyURL := fmt.Sprintf("%s/%s/deny", s.cfg.ConsentBaseURL, consentToken)

	body := fmt.Sprintf(`A consumer is requesting real-time access to your dataset inside a verified TEE.

Consumer  : %s
Dataset   : %s
Request ID: %s

TEE Attestation (AMD SEV-SNP)
  Measurement (SHA-384): %s
  Debug mode: OFF  |  Migration: DISABLED

This TEE has been cryptographically verified by the APD.
You are the only person who can approve or deny this computation.

  APPROVE → %s
  DENY    → %s

This link expires in 30 minutes. Do not share it.

— DX Access Policy Domain`,
		consumerName, assetName, requestID, measurement, approveURL, denyURL,
	)

	return s.send(providerEmail, subject, body)
}

// SendConsentGrantedToConsumer notifies the consumer that computation has started.
func (s *EmailService) SendConsentGrantedToConsumer(consumerEmail, requestID, assetName string) error {
	subject := fmt.Sprintf("[DX APD] Access Approved – %s", assetName)
	body := fmt.Sprintf(`The provider has approved your runtime computation request.

Request ID: %s
Dataset   : %s

The TEE is now fetching and processing your data.
You will be notified when results are ready.

— DX Access Policy Domain`, requestID, assetName)
	return s.send(consumerEmail, subject, body)
}

// SendResultReady notifies the consumer that the encrypted result is available.
func (s *EmailService) SendResultReady(consumerEmail, requestID, assetName string) error {
	subject := fmt.Sprintf("[DX APD] Result Ready – %s", assetName)
	body := fmt.Sprintf(`Your computation has completed successfully.

Request ID: %s
Dataset   : %s

Retrieve your encrypted result via:
  GET /api/v1/access-requests/%s/result

The result is encrypted with your public key. Only you can decrypt it.

— DX Access Policy Domain`, requestID, assetName, requestID)
	return s.send(consumerEmail, subject, body)
}

// SendPreApprovalNotification emails the consumer that the provider pre-approved.
func (s *EmailService) SendPreApprovalNotification(consumerEmail, requestID, assetName string) error {
	subject := fmt.Sprintf("[DX APD] Pre-Approval Granted – %s", assetName)
	body := fmt.Sprintf(`Your access request has been pre-approved by the provider.

Request ID: %s
Dataset   : %s

You may now trigger computation by calling:
  POST /api/v1/access-requests/%s/compute

— DX Access Policy Domain`, requestID, assetName, requestID)
	return s.send(consumerEmail, subject, body)
}

// SendConsentDenied notifies the consumer that the provider denied runtime consent.
func (s *EmailService) SendConsentDenied(consumerEmail, requestID, assetName string) error {
	subject := fmt.Sprintf("[DX APD] Runtime Consent Denied – %s", assetName)
	body := fmt.Sprintf(`The provider has denied runtime consent for your computation.

Request ID: %s
Dataset   : %s

If you believe this is an error, please contact the provider directly.

— DX Access Policy Domain`, requestID, assetName)
	return s.send(consumerEmail, subject, body)
}

func (s *EmailService) send(to, subject, body string) error {
	if !s.cfg.Enabled {
		return nil
	}

	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	msg := strings.Join([]string{
		"From: " + s.cfg.FromAddress,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	addr := fmt.Sprintf("%s:%s", s.cfg.SMTPHost, s.cfg.SMTPPort)
	return smtp.SendMail(addr, auth, s.cfg.FromAddress, []string{to}, []byte(msg))
}
