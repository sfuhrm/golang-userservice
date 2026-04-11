package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_DefaultValues(t *testing.T) {
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("DB_HOST")
	os.Unsetenv("DB_PORT")
	os.Unsetenv("DB_USER")
	os.Unsetenv("DB_PASSWORD")
	os.Unsetenv("DB_PASSWORD_FILE")
	os.Unsetenv("DB_NAME")
	os.Unsetenv("JWT_SECRET")
	os.Unsetenv("JWT_SECRET_FILE")
	os.Unsetenv("JWT_ISSUER")
	os.Unsetenv("JWT_AUDIENCE")
	os.Unsetenv("REGISTRATION_MAIL_URL")
	os.Unsetenv("REGISTRATION_MAIL_CALLBACK_URL")
	os.Unsetenv("RECOVERY_MAIL_URL")
	os.Unsetenv("RECOVERY_MAIL_CALLBACK_URL")

	cfg := Load()

	if cfg.ServerPort != "8080" {
		t.Errorf("ServerPort = %s, want 8080", cfg.ServerPort)
	}
	if cfg.DBHost != "mariadb" {
		t.Errorf("DBHost = %s, want mariadb", cfg.DBHost)
	}
	if cfg.DBPort != "3306" {
		t.Errorf("DBPort = %s, want 3306", cfg.DBPort)
	}
	if cfg.DBUser != "userservice" {
		t.Errorf("DBUser = %s, want userservice", cfg.DBUser)
	}
	if cfg.DBPassword != "userservice" {
		t.Errorf("DBPassword = %s, want userservice", cfg.DBPassword)
	}
	if cfg.DBName != "userservice" {
		t.Errorf("DBName = %s, want userservice", cfg.DBName)
	}
	if cfg.JWTSecret == "" {
		t.Error("JWTSecret should not be empty")
	}
	if cfg.JWTIssuer != "" {
		t.Errorf("JWTIssuer = %s, want empty", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "" {
		t.Errorf("JWTAudience = %s, want empty", cfg.JWTAudience)
	}
	if cfg.JWTExpire != 15*time.Minute {
		t.Errorf("JWTExpire = %v, want 15m", cfg.JWTExpire)
	}
	if cfg.RefreshExpire != 7*24*time.Hour {
		t.Errorf("RefreshExpire = %v, want 7d", cfg.RefreshExpire)
	}
	if cfg.RateLimit != 100 {
		t.Errorf("RateLimit = %d, want 100", cfg.RateLimit)
	}
	if cfg.RateLimitWindow != 15*time.Minute {
		t.Errorf("RateLimitWindow = %v, want 15m", cfg.RateLimitWindow)
	}
	if cfg.AuthRateLimit != 5 {
		t.Errorf("AuthRateLimit = %d, want 5", cfg.AuthRateLimit)
	}
}

func TestLoad_FromEnvironment(t *testing.T) {
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "3307")
	os.Setenv("DB_USER", "testuser")
	os.Setenv("DB_PASSWORD", "testpass")
	os.Unsetenv("DB_PASSWORD_FILE")
	os.Setenv("DB_NAME", "testdb")
	os.Setenv("JWT_SECRET", "test-secret-from-env")
	os.Setenv("JWT_ISSUER", "userservice")
	os.Setenv("JWT_AUDIENCE", "userservice-api")
	os.Setenv("REGISTRATION_MAIL_URL", "http://mail.example.com/register")
	os.Setenv("REGISTRATION_MAIL_CALLBACK_URL", "http://example.com/verify")
	os.Setenv("RECOVERY_MAIL_URL", "http://mail.example.com/recover")
	os.Setenv("RECOVERY_MAIL_CALLBACK_URL", "http://example.com/reset")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("DB_PORT")
		os.Unsetenv("DB_USER")
		os.Unsetenv("DB_PASSWORD")
		os.Unsetenv("DB_PASSWORD_FILE")
		os.Unsetenv("DB_NAME")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("JWT_ISSUER")
		os.Unsetenv("JWT_AUDIENCE")
		os.Unsetenv("REGISTRATION_MAIL_URL")
		os.Unsetenv("REGISTRATION_MAIL_CALLBACK_URL")
		os.Unsetenv("RECOVERY_MAIL_URL")
		os.Unsetenv("RECOVERY_MAIL_CALLBACK_URL")
	}()

	cfg := Load()

	if cfg.ServerPort != "9090" {
		t.Errorf("ServerPort = %s, want 9090", cfg.ServerPort)
	}
	if cfg.DBHost != "localhost" {
		t.Errorf("DBHost = %s, want localhost", cfg.DBHost)
	}
	if cfg.DBPort != "3307" {
		t.Errorf("DBPort = %s, want 3307", cfg.DBPort)
	}
	if cfg.DBUser != "testuser" {
		t.Errorf("DBUser = %s, want testuser", cfg.DBUser)
	}
	if cfg.DBPassword != "testpass" {
		t.Errorf("DBPassword = %s, want testpass", cfg.DBPassword)
	}
	if cfg.DBName != "testdb" {
		t.Errorf("DBName = %s, want testdb", cfg.DBName)
	}
	if cfg.JWTSecret != "test-secret-from-env" {
		t.Errorf("JWTSecret = %s, want test-secret-from-env", cfg.JWTSecret)
	}
	if cfg.JWTIssuer != "userservice" {
		t.Errorf("JWTIssuer = %s, want userservice", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "userservice-api" {
		t.Errorf("JWTAudience = %s, want userservice-api", cfg.JWTAudience)
	}
	if cfg.RegistrationMailURL != "http://mail.example.com/register" {
		t.Errorf("RegistrationMailURL = %s, want http://mail.example.com/register", cfg.RegistrationMailURL)
	}
	if cfg.RegistrationMailCallback != "http://example.com/verify" {
		t.Errorf("RegistrationMailCallback = %s, want http://example.com/verify", cfg.RegistrationMailCallback)
	}
	if cfg.RecoveryMailURL != "http://mail.example.com/recover" {
		t.Errorf("RecoveryMailURL = %s, want http://mail.example.com/recover", cfg.RecoveryMailURL)
	}
	if cfg.RecoveryMailCallback != "http://example.com/reset" {
		t.Errorf("RecoveryMailCallback = %s, want http://example.com/reset", cfg.RecoveryMailCallback)
	}
}

func TestLoad_JWTSecretFromFile(t *testing.T) {
	os.WriteFile("/tmp/test_jwt_secret.txt", []byte("secret-from-file\n"), 0644)
	defer os.Remove("/tmp/test_jwt_secret.txt")

	os.Setenv("JWT_SECRET_FILE", "/tmp/test_jwt_secret.txt")
	os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("JWT_SECRET_FILE")

	cfg := Load()

	if cfg.JWTSecret != "secret-from-file" {
		t.Errorf("JWTSecret = %s, want secret-from-file", cfg.JWTSecret)
	}
}

func TestLoad_DBPasswordFromFile(t *testing.T) {
	os.WriteFile("/tmp/test_db_password.txt", []byte("db-pass-from-file\n"), 0644)
	defer os.Remove("/tmp/test_db_password.txt")

	os.Setenv("DB_PASSWORD_FILE", "/tmp/test_db_password.txt")
	os.Setenv("DB_PASSWORD", "db-pass-from-env")
	defer os.Unsetenv("DB_PASSWORD_FILE")
	defer os.Unsetenv("DB_PASSWORD")

	cfg := Load()

	if cfg.DBPassword != "db-pass-from-file" {
		t.Errorf("DBPassword = %s, want db-pass-from-file", cfg.DBPassword)
	}
}

func TestLoad_DBPasswordFileNotFoundFallsBackToEnv(t *testing.T) {
	os.Setenv("DB_PASSWORD_FILE", "/nonexistent/db-password.txt")
	os.Setenv("DB_PASSWORD", "db-pass-from-env")
	defer os.Unsetenv("DB_PASSWORD_FILE")
	defer os.Unsetenv("DB_PASSWORD")

	cfg := Load()

	if cfg.DBPassword != "db-pass-from-env" {
		t.Errorf("DBPassword = %s, want db-pass-from-env", cfg.DBPassword)
	}
}

func TestLoad_JWTSecretFileNotFound(t *testing.T) {
	os.Setenv("JWT_SECRET_FILE", "/nonexistent/secret.txt")
	os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("JWT_SECRET_FILE")

	cfg := Load()

	if cfg.JWTSecret == "" {
		t.Error("JWTSecret should not be empty when file not found")
	}
	if cfg.JWTSecret != "your-secret-key-change-in-production" {
		t.Errorf("JWTSecret = %s, want default", cfg.JWTSecret)
	}
}

func TestGetEnv(t *testing.T) {
	os.Setenv("TEST_KEY", "test-value")
	defer os.Unsetenv("TEST_KEY")

	tests := []struct {
		key          string
		defaultValue string
		want         string
	}{
		{"TEST_KEY", "default", "test-value"},
		{"NONEXISTENT_KEY", "default", "default"},
		{"", "empty_key", "empty_key"},
	}

	for _, tt := range tests {
		result := getEnv(tt.key, tt.defaultValue)
		if result != tt.want {
			t.Errorf("getEnv(%s, %s) = %s, want %s", tt.key, tt.defaultValue, result, tt.want)
		}
	}
}
