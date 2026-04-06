// Package config provides configuration management for the User Service.
// It loads settings from environment variables with sensible defaults.
package config

import (
	"os"
	"strings"
	"time"
)

// Config holds all application configuration settings.
// These values are loaded from environment variables at startup.
type Config struct {
	ServerPort      string        // HTTP server port (default: 8080)
	DBHost          string        // Database host address (default: mariadb)
	DBPort          string        // Database port (default: 3306)
	DBUser          string        // Database username (default: userservice)
	DBPassword      string        // Database password (default: userservice)
	DBName          string        // Database name (default: userservice)
	JWTSecret       string        // Secret key for signing JWT tokens
	JWTExpire       time.Duration // Access token expiration time (default: 15 minutes)
	RefreshExpire   time.Duration // Refresh token expiration time (default: 7 days)
	RateLimit       int           // Standard rate limit requests per window (default: 100)
	RateLimitWindow time.Duration // Rate limit time window (default: 15 minutes)
	AuthRateLimit   int           // Auth endpoints rate limit (default: 5)
}

// Load returns a new Config instance with values loaded from environment variables.
// If an environment variable is not set, the default value is used.
// JWT secret is read from a file (for Docker secrets) or falls back to env var.
func Load() *Config {
	return &Config{
		ServerPort:      getEnv("SERVER_PORT", "8080"),
		DBHost:          getEnv("DB_HOST", "mariadb"),
		DBPort:          getEnv("DB_PORT", "3306"),
		DBUser:          getEnv("DB_USER", "userservice"),
		DBPassword:      getEnv("DB_PASSWORD", "userservice"),
		DBName:          getEnv("DB_NAME", "userservice"),
		JWTSecret:       getJWTSecret(),
		JWTExpire:       15 * time.Minute,
		RefreshExpire:   7 * 24 * time.Hour,
		RateLimit:       100,
		RateLimitWindow: 15 * time.Minute,
		AuthRateLimit:   5,
	}
}

// getJWTSecret reads the JWT secret from a file or environment variable.
// Priority: 1) JWT_SECRET_FILE env var (path to secret file), 2) JWT_SECRET env var, 3) default
func getJWTSecret() string {
	if secretFile := os.Getenv("JWT_SECRET_FILE"); secretFile != "" {
		secret, err := os.ReadFile(secretFile)
		if err == nil {
			return strings.TrimSpace(string(secret))
		}
	}

	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		return secret
	}

	return "your-secret-key-change-in-production"
}

// getEnv retrieves an environment variable value or returns a default if not set.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
