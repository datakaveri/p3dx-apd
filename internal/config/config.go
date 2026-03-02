package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Server   ServerConfig
	DB       DBConfig
	JWT      JWTConfig
	Email    EmailConfig
	TEE      TEEConfig
	AMD      AMDConfig
	APD      APDConfig
}

type ServerConfig struct {
	Port string
}

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

func (d DBConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode,
	)
}

type JWTConfig struct {
	// Path to PEM-encoded EC private key (P-256) for signing tokens
	PrivateKeyPath string
	// Path to PEM-encoded EC public key for verification
	PublicKeyPath string
	ExpiryMinutes int
	Issuer        string
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	FromAddress  string
	Enabled      bool
	// Base URL for consent links sent in emails
	ConsentBaseURL string
}

type TEEConfig struct {
	// Base URL of the TEE Orchestrator service
	OrchestratorURL string
	// How long a provisioned TEE may run before forced teardown
	MaxRuntimeMinutes int
	// APD's own base URL — TEE uses this for callbacks
	APDBaseURL string
}

type AMDConfig struct {
	// AMD Root Key (ARK) PEM, used to verify the VCEK certificate chain
	ARKCertPath string
	// If true, skip certificate chain verification (dev only)
	SkipChainVerification bool
	// Allowed TEE policy bitmask (debug bit must be 0 in production)
	AllowedPolicy uint64
}

type APDConfig struct {
	// Path to PEM-encoded EC private key used to sign contracts sent to TEE
	SigningKeyPath string
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnv("PORT", "8080"),
		},
		DB: DBConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "apd"),
			Password: mustEnv("DB_PASSWORD"),
			Name:     getEnv("DB_NAME", "apd"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		JWT: JWTConfig{
			PrivateKeyPath: mustEnv("JWT_PRIVATE_KEY_PATH"),
			PublicKeyPath:  mustEnv("JWT_PUBLIC_KEY_PATH"),
			ExpiryMinutes:  getEnvInt("JWT_EXPIRY_MINUTES", 60),
			Issuer:         getEnv("JWT_ISSUER", "https://apd.example.com"),
		},
		Email: EmailConfig{
			SMTPHost:       getEnv("SMTP_HOST", "localhost"),
			SMTPPort:       getEnv("SMTP_PORT", "587"),
			SMTPUser:       getEnv("SMTP_USER", ""),
			SMTPPassword:   getEnv("SMTP_PASSWORD", ""),
			FromAddress:    getEnv("EMAIL_FROM", "apd@example.com"),
			Enabled:        getEnvBool("EMAIL_ENABLED", true),
			ConsentBaseURL: getEnv("CONSENT_BASE_URL", "https://apd.example.com/consent"),
		},
		TEE: TEEConfig{
			OrchestratorURL:   mustEnv("TEE_ORCHESTRATOR_URL"),
			MaxRuntimeMinutes: getEnvInt("TEE_MAX_RUNTIME_MINUTES", 60),
			APDBaseURL:        mustEnv("APD_BASE_URL"),
		},
		AMD: AMDConfig{
			ARKCertPath:           getEnv("AMD_ARK_CERT_PATH", ""),
			SkipChainVerification: getEnvBool("AMD_SKIP_CHAIN_VERIFY", false),
			AllowedPolicy:         uint64(getEnvInt("AMD_ALLOWED_POLICY", 0)),
		},
		APD: APDConfig{
			SigningKeyPath: mustEnv("APD_SIGNING_KEY_PATH"),
		},
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required environment variable %q is not set", key))
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
