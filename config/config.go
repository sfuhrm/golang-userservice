// Package config provides configuration management for the User Service.
// It loads settings from environment variables with sensible defaults.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration settings.
// These values are loaded from environment variables at startup.
type Config struct {
	ServerPort               string        // HTTP server port (default: 8080)
	DBHost                   string        // Database host address (default: mariadb)
	DBPort                   string        // Database port (default: 3306)
	DBUser                   string        // Database username (default: userservice)
	DBPassword               string        // Database password (default: userservice)
	DBName                   string        // Database name (default: userservice)
	JWTAlgorithm             string        // JWT signing algorithm: HS256, RS256, or ES256
	JWTSecret                string        // Secret key for HS256 JWT tokens
	JWTPrivateKey            string        // Private key PEM for RS256/ES256 token signing
	JWTPublicKey             string        // Public key PEM for RS256/ES256 token verification
	JWTIssuer                string        // Optional JWT issuer claim (iss)
	JWTAudience              string        // Optional JWT audience claim (aud)
	JWTExpire                time.Duration // Access token expiration time (default: 15 minutes)
	RefreshExpire            time.Duration // Refresh token expiration time (default: 7 days)
	RateLimit                int           // Standard rate limit requests per window (default: 100)
	RateLimitWindow          time.Duration // Rate limit time window (default: 15 minutes)
	AuthRateLimit            int           // Auth endpoints rate limit (default: 5)
	RefreshRateLimit         int           // Refresh endpoint rate limit (default: 30)
	EnableDebugCoverage      bool          // Enables /debug/coverage endpoint and tracking middleware
	RegistrationMailURL      string        // Optional external URL for registration mail service
	RegistrationMailCallback string        // Callback URL for registration email verification
	RecoveryMailURL          string        // Optional external URL for recovery mail service
	RecoveryMailCallback     string        // Callback URL for recovery email verification
}

// Load returns a new Config instance with values loaded from environment variables.
// If an environment variable is not set, the default value is used.
// DB password and JWT secrets/keys can be read from files (for Docker secrets) or env vars.
func Load() (*Config, error) {
	jwtAlgorithm, err := getJWTAlgorithm()
	if err != nil {
		return nil, err
	}

	jwtSecret, err := getJWTSecret()
	if err != nil {
		return nil, err
	}

	jwtPrivateKey, err := getJWTPrivateKey()
	if err != nil {
		return nil, err
	}

	jwtPublicKey, err := getJWTPublicKey()
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		ServerPort:               getEnv("SERVER_PORT", "8080"),
		DBHost:                   getEnv("DB_HOST", "mariadb"),
		DBPort:                   getEnv("DB_PORT", "3306"),
		DBUser:                   getEnv("DB_USER", "userservice"),
		DBPassword:               getDBPassword(),
		DBName:                   getEnv("DB_NAME", "userservice"),
		JWTAlgorithm:             jwtAlgorithm,
		JWTSecret:                jwtSecret,
		JWTPrivateKey:            jwtPrivateKey,
		JWTPublicKey:             jwtPublicKey,
		JWTIssuer:                getEnv("JWT_ISSUER", ""),
		JWTAudience:              getEnv("JWT_AUDIENCE", ""),
		JWTExpire:                getEnvDuration("JWT_EXPIRE", 15*time.Minute),
		RefreshExpire:            getEnvDuration("REFRESH_EXPIRE", 7*24*time.Hour),
		RateLimit:                getEnvInt("RATE_LIMIT", 100),
		RateLimitWindow:          getEnvDuration("RATE_LIMIT_WINDOW", 15*time.Minute),
		AuthRateLimit:            getEnvInt("AUTH_RATE_LIMIT", 5),
		RefreshRateLimit:         getEnvInt("REFRESH_RATE_LIMIT", 30),
		EnableDebugCoverage:      getEnvBool("ENABLE_DEBUG_COVERAGE", false),
		RegistrationMailURL:      getEnv("REGISTRATION_MAIL_URL", ""),
		RegistrationMailCallback: getEnv("REGISTRATION_MAIL_CALLBACK_URL", ""),
		RecoveryMailURL:          getEnv("RECOVERY_MAIL_URL", ""),
		RecoveryMailCallback:     getEnv("RECOVERY_MAIL_CALLBACK_URL", ""),
	}

	if err := validateJWTConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// getDBPassword reads the DB password from a file or environment variable.
// Priority: 1) DB_PASSWORD_FILE env var (path to secret file), 2) DB_PASSWORD env var, 3) default
func getDBPassword() string {
	if passwordFile := os.Getenv("DB_PASSWORD_FILE"); passwordFile != "" {
		password, err := os.ReadFile(passwordFile)
		if err == nil {
			return strings.TrimSpace(string(password))
		}
	}

	if password := os.Getenv("DB_PASSWORD"); password != "" {
		return password
	}

	return "userservice"
}

// getJWTAlgorithm reads and validates JWT_ALGORITHM from environment.
func getJWTAlgorithm() (string, error) {
	rawAlgorithm := strings.TrimSpace(os.Getenv("JWT_ALGORITHM"))
	if rawAlgorithm == "" {
		return "", fmt.Errorf("JWT_ALGORITHM must be set to one of HS256, RS256, or ES256")
	}

	algorithm := strings.ToUpper(rawAlgorithm)
	switch algorithm {
	case "HS256", "RS256", "ES256":
		return algorithm, nil
	default:
		return "", fmt.Errorf("invalid JWT_ALGORITHM %q: must be HS256, RS256, or ES256", rawAlgorithm)
	}
}

// getJWTSecret reads the JWT secret from a file or environment variable.
// Priority: 1) JWT_SECRET_FILE env var (path to secret file), 2) JWT_SECRET env var
func getJWTSecret() (string, error) {
	if secretFile := os.Getenv("JWT_SECRET_FILE"); secretFile != "" {
		secret, err := os.ReadFile(secretFile)
		if err != nil {
			return "", fmt.Errorf("failed to read JWT_SECRET_FILE %q: %w", secretFile, err)
		}
		return strings.TrimSpace(string(secret)), nil
	}

	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		return secret, nil
	}

	return "", nil
}

// getJWTPrivateKey reads the private key from a file or environment variable.
// Priority: 1) JWT_PRIVATE_KEY_FILE env var, 2) JWT_PRIVATE_KEY env var, 3) empty
func getJWTPrivateKey() (string, error) {
	if keyFile := os.Getenv("JWT_PRIVATE_KEY_FILE"); keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("failed to read JWT_PRIVATE_KEY_FILE %q: %w", keyFile, err)
		}
		return strings.TrimSpace(string(key)), nil
	}

	if key := os.Getenv("JWT_PRIVATE_KEY"); key != "" {
		return strings.TrimSpace(key), nil
	}

	return "", nil
}

// getJWTPublicKey reads the public key from a file or environment variable.
// Priority: 1) JWT_PUBLIC_KEY_FILE env var, 2) JWT_PUBLIC_KEY env var, 3) empty
func getJWTPublicKey() (string, error) {
	if keyFile := os.Getenv("JWT_PUBLIC_KEY_FILE"); keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("failed to read JWT_PUBLIC_KEY_FILE %q: %w", keyFile, err)
		}
		return strings.TrimSpace(string(key)), nil
	}

	if key := os.Getenv("JWT_PUBLIC_KEY"); key != "" {
		return strings.TrimSpace(key), nil
	}

	return "", nil
}

func validateJWTConfig(cfg *Config) error {
	switch cfg.JWTAlgorithm {
	case "HS256":
		if strings.TrimSpace(cfg.JWTSecret) == "" {
			return fmt.Errorf("JWT_SECRET or JWT_SECRET_FILE must be set when JWT_ALGORITHM=HS256")
		}
	case "RS256", "ES256":
		if strings.TrimSpace(cfg.JWTPrivateKey) == "" {
			return fmt.Errorf("JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE must be set when JWT_ALGORITHM=%s", cfg.JWTAlgorithm)
		}
	default:
		return fmt.Errorf("invalid JWT_ALGORITHM %q: must be HS256, RS256, or ES256", cfg.JWTAlgorithm)
	}

	return nil
}

// getEnv retrieves an environment variable value or returns a default if not set.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt retrieves an integer environment variable or returns a default when unset/invalid.
func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

// getEnvDuration retrieves a Go duration environment variable or returns a default when unset/invalid.
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

// getEnvBool retrieves a boolean environment variable or returns a default when unset/invalid.
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}
