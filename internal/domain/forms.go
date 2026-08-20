package domain

import "time"

// ---------------------------------------------------------------------------
// FL Form Submissions (output-owner) and Data-Provider Forms
//
// APD is the store of record for these — aaa forwards the raw UI payload
// here instead of writing to immudb itself. Numeric/string coercion mirrors
// the "value || null" shaping aaa used to do: 0, "", and absent all become
// null on the stored record.
// ---------------------------------------------------------------------------

type FormSubmission struct {
	ID                string                 `json:"id"`
	FormID            string                 `json:"form_id"`
	RequestedBy       string                 `json:"requested_by"`
	OutputOwnerID     string                 `json:"output_owner_id"`
	NumServerRounds   *float64               `json:"num_server_rounds"`
	FractionEvaluate  *float64               `json:"fraction_evaluate"`
	LocalEpochs       *float64               `json:"local_epochs"`
	LearningRate      *float64               `json:"learning_rate"`
	BatchSize         *float64               `json:"batch_size"`
	Model             *string                `json:"model"`
	Framework         *string                `json:"framework"`
	Components        map[string]interface{} `json:"components"`
	Filled            bool                   `json:"filled"`
	RequestedAt       time.Time              `json:"requested_at"`
	FilledAt          time.Time              `json:"filled_at"`
	SelectedProviders []string               `json:"selected_providers"`
	IPAddress         *string                `json:"ip_address"`
	Port              *float64               `json:"port"`
	RAMUsage          *float64               `json:"ram_usage"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// CreateFormSubmissionBody is the raw payload aaa forwards from the UI.
// Numeric fields are interface{} because the JS coercion accepts a number,
// a numeric string, or an absent field — all of which fold into numOrNull.
type CreateFormSubmissionBody struct {
	FormID            string                 `json:"form_id"`
	RequestedBy       string                 `json:"requested_by"`
	OutputOwnerID     string                 `json:"output_owner_id"`
	RequestedAt       string                 `json:"requested_at,omitempty"`
	NumServerRounds   interface{}            `json:"num_server_rounds"`
	FractionEvaluate  interface{}            `json:"fraction_evaluate"`
	LocalEpochs       interface{}            `json:"local_epochs"`
	LearningRate      interface{}            `json:"learning_rate"`
	BatchSize         interface{}            `json:"batch_size"`
	Model             string                 `json:"model"`
	Framework         string                 `json:"framework"`
	Components        map[string]interface{} `json:"components"`
	SelectedProviders []string               `json:"selected_providers"`
	IPAddress         string                 `json:"ip_address"`
	Port              interface{}            `json:"port"`
	RAMUsage          interface{}            `json:"ram_usage"`
}

type ProviderForm struct {
	ID             string    `json:"id"`
	FormID         *string   `json:"form_id"`
	DataOwnerID    *string   `json:"data_owner_id"`
	DatasetName    *string   `json:"dataset_name"`
	RAM            *float64  `json:"ram"`
	MemoryMB       *float64  `json:"memory_mb"`
	DataSizeBytes  *float64  `json:"data_size_bytes"`
	DataResourceID *string   `json:"data_resource_id"`
	IPAddress      *string   `json:"ip_address"`
	Port           *float64  `json:"port"`
	RAMUsage       *float64  `json:"ram_usage"`
	Filled         bool      `json:"filled"`
	FilledAt       time.Time `json:"filled_at"`
	SubmittedBy    *string   `json:"submitted_by"`
	CreatedAt      time.Time `json:"created_at"`
}

type CreateProviderFormBody struct {
	FormID         string      `json:"form_id"`
	DataOwnerID    string      `json:"data_owner_id"`
	DatasetName    string      `json:"dataset_name"`
	RAM            interface{} `json:"ram"`
	MemoryMB       interface{} `json:"memory_mb"`
	DataSizeBytes  interface{} `json:"data_size_bytes"`
	DataResourceID string      `json:"data_resource_id"`
	IPAddress      string      `json:"ip_address"`
	Port           interface{} `json:"port"`
	FilledAt       string      `json:"filled_at,omitempty"`
	SubmittedBy    string      `json:"submitted_by"`
	RAMUsage       interface{} `json:"ram_usage"`
}
