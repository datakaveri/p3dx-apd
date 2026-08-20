package domain

import (
	"time"
)

// ---------------------------------------------------------------------------
// Access Request States
// ---------------------------------------------------------------------------

type Status string

const (
	// Phase 1 – pre-approval (provider agrees in principle)
	StatusPending     Status = "PENDING"
	StatusPreApproved Status = "PRE_APPROVED"
	StatusRejected    Status = "REJECTED"

	// Phase 2 – TEE lifecycle
	StatusTEEProvisioning     Status = "TEE_PROVISIONING"
	StatusAwaitingAttestation Status = "AWAITING_ATTESTATION"
	StatusAttestationVerified Status = "ATTESTATION_VERIFIED"
	StatusAttestationFailed   Status = "ATTESTATION_FAILED"

	// Phase 3 – runtime provider consent
	StatusAwaitingRuntimeConsent Status = "AWAITING_RUNTIME_CONSENT"
	StatusRuntimeConsentGranted  Status = "RUNTIME_CONSENT_GRANTED"
	StatusConsentDenied          Status = "CONSENT_DENIED"

	// Phase 4 – data access (cases 2 & 3 need key release)
	StatusKeyReleased        Status = "KEY_RELEASED"
	StatusDataFetching       Status = "DATA_FETCHING"
	StatusComputationComplete Status = "COMPUTATION_COMPLETE"
	StatusResultDelivered    Status = "RESULT_DELIVERED"
)

// ---------------------------------------------------------------------------
// Data Access Type (the 3 cases)
// ---------------------------------------------------------------------------

type AccessType string

const (
	AccessTypeOpen         AccessType = "OPEN"          // Case 1: open folder/URL
	AccessTypeSSHEncrypted AccessType = "SSH_ENCRYPTED" // Case 2: SSH + decryption key
	AccessTypeEncrypted    AccessType = "ENCRYPTED_ONLY" // Case 3: encrypted, no SSH
)

// ---------------------------------------------------------------------------
// Access Request
// ---------------------------------------------------------------------------

type AccessRequest struct {
	ID          string     `json:"id"`
	ConsumerID  string     `json:"consumerId"`
	ProviderID  string     `json:"providerId"`
	ItemID      string     `json:"itemId"`
	Status      Status     `json:"status"`
	AccessType  AccessType `json:"accessType"`

	// Pre-approval window
	PreApprovedAt *time.Time `json:"preApprovedAt,omitempty"`
	PreApprovalExpiry *time.Time `json:"preApprovalExpiry,omitempty"`

	// TEE
	TEEID             *string    `json:"teeId,omitempty"`
	TEEPublicKey      *string    `json:"teePublicKey,omitempty"` // EC pub key from attestation
	ExpectedMeasurement string   `json:"expectedMeasurement"`    // SHA-384 of trusted TEE binary

	// Attestation
	AttestationReport *string    `json:"attestationReport,omitempty"` // raw base64
	AttestationVerifiedAt *time.Time `json:"attestationVerifiedAt,omitempty"`

	// Runtime consent
	ConsentRequestedAt *time.Time `json:"consentRequestedAt,omitempty"`
	ConsentGrantedAt   *time.Time `json:"consentGrantedAt,omitempty"`

	// Result (encrypted to consumer's public key)
	EncryptedResult *string `json:"encryptedResult,omitempty"`

	// Dataset + app metadata (from catalogue / consumer request)
	AssetName        string `json:"assetName"`
	AssetType        string `json:"assetType"`
	ResourceURL      string `json:"resourceUrl"`      // where provider data lives
	AppImageHash     string `json:"appImageHash"`      // expected TEE binary hash
	AppImageID       string `json:"appImageId"`
	ConsumerPublicKey string `json:"consumerPublicKey"` // result encrypted to this

	AdditionalInfo map[string]interface{} `json:"additionalInfo,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ---------------------------------------------------------------------------
// TEE Contract  (sent to the TEE Orchestrator)
// ---------------------------------------------------------------------------

type Contract struct {
	ContractID string `json:"contractId"`
	RequestID  string `json:"requestId"`

	// Parties
	ConsumerID string `json:"consumerId"`
	ProviderID string `json:"providerId"`

	// Application running inside the TEE
	AppDetails AppDetails `json:"appDetails"`

	// Dataset the TEE will access
	DatasetDetails DatasetDetails `json:"datasetDetails"`

	// How the TEE authenticates to the data source
	AccessConfig AccessConfig `json:"accessConfig"`

	// TEE sends result encrypted to this key
	ConsumerPublicKey string `json:"consumerPublicKey"`

	// TEE calls back here after attestation is ready
	APDCallbackURL string `json:"apdCallbackUrl"`

	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`

	// APD's ECDSA signature over the contract (base64)
	Signature string `json:"signature"`
}

type AppDetails struct {
	ImageID     string            `json:"imageId"`
	ImageHash   string            `json:"imageHash"`   // expected SEV-SNP measurement
	Version     string            `json:"version"`
	EntryPoint  string            `json:"entryPoint"`
	Environment map[string]string `json:"environment,omitempty"`
}

type DatasetDetails struct {
	ItemID      string `json:"itemId"`
	AssetName   string `json:"assetName"`
	AssetType   string `json:"assetType"`
	ResourceURL string `json:"resourceUrl"` // open URL or encrypted file URL
}

type AccessConfig struct {
	Type AccessType `json:"type"`
	// SSH and decryption keys are NOT in the contract.
	// They are delivered post-consent directly to the TEE via /key-relay.
}

// ---------------------------------------------------------------------------
// AMD SEV-SNP Attestation
// ---------------------------------------------------------------------------

// AttestationReport is submitted by the TEE to the APD.
type AttestationReport struct {
	// Raw CBOR/binary report, base64-encoded
	RawReport string `json:"rawReport"`

	// AMD certificate chain (base64 PEM), for offline verification
	VCEKCert string `json:"vcekCert"`
	ASKCert  string `json:"askCert"`
	ARKCert  string `json:"arkCert"`

	// Parsed fields (APD extracts these from rawReport)
	Measurement string `json:"measurement"` // SHA-384, hex
	HostData    string `json:"hostData"`    // hex — should encode requestId
	ReportData  string `json:"reportData"`  // hex — TEE's ephemeral public key
	Policy      uint64 `json:"policy"`
}

// ParsedSNPReport holds the fields APD cares about after parsing.
type ParsedSNPReport struct {
	Measurement [48]byte // SHA-384 of initial TEE state
	HostData    [32]byte // set by host; APD puts requestId hash here
	ReportData  [64]byte // set by guest; TEE puts its ephemeral EC pub key here
	Policy      uint64
	Version     uint32
	GuestSVN    uint32
}

// ---------------------------------------------------------------------------
// Runtime Consent Token
// ---------------------------------------------------------------------------

type ConsentToken struct {
	Token     string    `json:"token"`
	RequestID string    `json:"requestId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Used      bool      `json:"used"`
	CreatedAt time.Time `json:"createdAt"`
}

// ---------------------------------------------------------------------------
// Key Bundle  (provider → APD → TEE, never persisted)
// ---------------------------------------------------------------------------

// KeyBundle carries encrypted credentials from the provider.
// Encrypted with the TEE's ephemeral public key (from attestation ReportData).
// APD forwards it to the TEE and does NOT store the plaintext or ciphertext.
type KeyBundle struct {
	RequestID string `json:"requestId"`

	// Base64-encoded ciphertext (AES-GCM key-wrapped with TEE's EC pub key)
	EncryptedBundle string `json:"encryptedBundle"`

	// For Case 2 (SSH_ENCRYPTED): SSH host, user provided in plaintext
	// so APD can do basic sanity checks; actual credentials are inside the encrypted bundle
	SSHHost *string `json:"sshHost,omitempty"`
	SSHUser *string `json:"sshUser,omitempty"`
}

// ---------------------------------------------------------------------------
// HTTP Request/Response bodies
// ---------------------------------------------------------------------------

type CreateAccessRequestBody struct {
	ItemID            string                 `json:"itemId"`
	AccessType        AccessType             `json:"accessType"`
	AppImageID        string                 `json:"appImageId"`
	AppImageHash      string                 `json:"appImageHash"` // expected TEE measurement
	ConsumerPublicKey string                 `json:"consumerPublicKey"`
	ResourceURL       string                 `json:"resourceUrl"`
	AdditionalInfo    map[string]interface{} `json:"additionalInfo,omitempty"`
}

type PreApproveBody struct {
	ExpiryAt time.Time `json:"expiryAt"`
}

type RejectBody struct {
	Reason string `json:"reason"`
}

type SubmitAttestationBody struct {
	RequestID         string            `json:"requestId"`
	AttestationReport AttestationReport `json:"attestationReport"`
}

type SubmitKeyBundleBody struct {
	EncryptedBundle string  `json:"encryptedBundle"`
	SSHHost         *string `json:"sshHost,omitempty"`
	SSHUser         *string `json:"sshUser,omitempty"`
}

type TEEDataFetchedBody struct {
	RequestID       string `json:"requestId"`
	EncryptedResult string `json:"encryptedResult"` // encrypted to consumer's pub key
}

type TokenRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type TokenResponse struct {
	AccessToken     string `json:"accessToken"`
	TokenType       string `json:"tokenType"`
	ExpiresInMinutes int   `json:"expiresInMinutes"`
}

type APIResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// ---------------------------------------------------------------------------
// Policy  (Phase 0 — ConMan pushes policy; TOP fetches it)
// ---------------------------------------------------------------------------

// Policy represents an access policy issued by the Contract Manager (ConMan).
// It is stored by the APD and served to the Trusted Orchestrator Platform (TOP)
// before any access request is created.
type Policy struct {
	PolicyID  string                 `json:"policyId"`
	ItemID    string                 `json:"itemId"`
	IssuedBy  string                 `json:"issuedBy"` // ConMan identity
	Rules     map[string]interface{} `json:"rules"`
	IssuedAt  time.Time              `json:"issuedAt"`
	ExpiresAt *time.Time             `json:"expiresAt,omitempty"`
}

type ReceivePolicyBody struct {
	PolicyID  string                 `json:"policyId"`
	ItemID    string                 `json:"itemId"`
	IssuedBy  string                 `json:"issuedBy"`
	Rules     map[string]interface{} `json:"rules"`
	ExpiresAt *time.Time             `json:"expiresAt,omitempty"`
}
