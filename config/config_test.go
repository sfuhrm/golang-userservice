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
	os.Setenv("JWT_ALGORITHM", "HS256")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Unsetenv("JWT_SECRET_FILE")
	os.Unsetenv("JWT_PRIVATE_KEY")
	os.Unsetenv("JWT_PRIVATE_KEY_FILE")
	os.Unsetenv("JWT_PUBLIC_KEY")
	os.Unsetenv("JWT_PUBLIC_KEY_FILE")
	os.Unsetenv("JWT_ISSUER")
	os.Unsetenv("JWT_AUDIENCE")
	os.Unsetenv("JWT_EXPIRE")
	os.Unsetenv("REFRESH_EXPIRE")
	os.Unsetenv("RATE_LIMIT")
	os.Unsetenv("RATE_LIMIT_WINDOW")
	os.Unsetenv("AUTH_RATE_LIMIT")
	os.Unsetenv("REFRESH_RATE_LIMIT")
	os.Unsetenv("ENABLE_DEBUG_COVERAGE")
	os.Unsetenv("REGISTRATION_MAIL_URL")
	os.Unsetenv("REGISTRATION_MAIL_CALLBACK_URL")
	os.Unsetenv("RECOVERY_MAIL_URL")
	os.Unsetenv("RECOVERY_MAIL_CALLBACK_URL")
	defer os.Unsetenv("JWT_ALGORITHM")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

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
	if cfg.JWTAlgorithm != "HS256" {
		t.Errorf("JWTAlgorithm = %s, want HS256", cfg.JWTAlgorithm)
	}
	if cfg.JWTSecret == "" {
		t.Error("JWTSecret should not be empty")
	}
	if cfg.JWTPrivateKey != "" {
		t.Errorf("JWTPrivateKey = %q, want empty", cfg.JWTPrivateKey)
	}
	if cfg.JWTPublicKey != "" {
		t.Errorf("JWTPublicKey = %q, want empty", cfg.JWTPublicKey)
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
	if cfg.RefreshRateLimit != 30 {
		t.Errorf("RefreshRateLimit = %d, want 30", cfg.RefreshRateLimit)
	}
	if cfg.EnableDebugCoverage {
		t.Errorf("EnableDebugCoverage = %v, want false", cfg.EnableDebugCoverage)
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
	os.Setenv("JWT_ALGORITHM", "RS256")
	os.Setenv("JWT_SECRET", "test-secret-from-env")
	os.Setenv("JWT_PRIVATE_KEY", "private-key-from-env")
	os.Setenv("JWT_PUBLIC_KEY", "public-key-from-env")
	os.Setenv("JWT_ISSUER", "userservice")
	os.Setenv("JWT_AUDIENCE", "userservice-api")
	os.Setenv("JWT_EXPIRE", "20m")
	os.Setenv("REFRESH_EXPIRE", "240h")
	os.Setenv("RATE_LIMIT", "250")
	os.Setenv("RATE_LIMIT_WINDOW", "30m")
	os.Setenv("AUTH_RATE_LIMIT", "25")
	os.Setenv("REFRESH_RATE_LIMIT", "80")
	os.Setenv("ENABLE_DEBUG_COVERAGE", "true")
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
		os.Unsetenv("JWT_ALGORITHM")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("JWT_PRIVATE_KEY")
		os.Unsetenv("JWT_PUBLIC_KEY")
		os.Unsetenv("JWT_ISSUER")
		os.Unsetenv("JWT_AUDIENCE")
		os.Unsetenv("JWT_EXPIRE")
		os.Unsetenv("REFRESH_EXPIRE")
		os.Unsetenv("RATE_LIMIT")
		os.Unsetenv("RATE_LIMIT_WINDOW")
		os.Unsetenv("AUTH_RATE_LIMIT")
		os.Unsetenv("REFRESH_RATE_LIMIT")
		os.Unsetenv("ENABLE_DEBUG_COVERAGE")
		os.Unsetenv("REGISTRATION_MAIL_URL")
		os.Unsetenv("REGISTRATION_MAIL_CALLBACK_URL")
		os.Unsetenv("RECOVERY_MAIL_URL")
		os.Unsetenv("RECOVERY_MAIL_CALLBACK_URL")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

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
	if cfg.JWTAlgorithm != "RS256" {
		t.Errorf("JWTAlgorithm = %s, want RS256", cfg.JWTAlgorithm)
	}
	if cfg.JWTSecret != "test-secret-from-env" {
		t.Errorf("JWTSecret = %s, want test-secret-from-env", cfg.JWTSecret)
	}
	if cfg.JWTPrivateKey != "private-key-from-env" {
		t.Errorf("JWTPrivateKey = %s, want private-key-from-env", cfg.JWTPrivateKey)
	}
	if cfg.JWTPublicKey != "public-key-from-env" {
		t.Errorf("JWTPublicKey = %s, want public-key-from-env", cfg.JWTPublicKey)
	}
	if cfg.JWTIssuer != "userservice" {
		t.Errorf("JWTIssuer = %s, want userservice", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "userservice-api" {
		t.Errorf("JWTAudience = %s, want userservice-api", cfg.JWTAudience)
	}
	if cfg.JWTExpire != 20*time.Minute {
		t.Errorf("JWTExpire = %v, want 20m", cfg.JWTExpire)
	}
	if cfg.RefreshExpire != 240*time.Hour {
		t.Errorf("RefreshExpire = %v, want 240h", cfg.RefreshExpire)
	}
	if cfg.RateLimit != 250 {
		t.Errorf("RateLimit = %d, want 250", cfg.RateLimit)
	}
	if cfg.RateLimitWindow != 30*time.Minute {
		t.Errorf("RateLimitWindow = %v, want 30m", cfg.RateLimitWindow)
	}
	if cfg.AuthRateLimit != 25 {
		t.Errorf("AuthRateLimit = %d, want 25", cfg.AuthRateLimit)
	}
	if cfg.RefreshRateLimit != 80 {
		t.Errorf("RefreshRateLimit = %d, want 80", cfg.RefreshRateLimit)
	}
	if !cfg.EnableDebugCoverage {
		t.Errorf("EnableDebugCoverage = %v, want true", cfg.EnableDebugCoverage)
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

	os.Setenv("JWT_ALGORITHM", "HS256")
	defer os.Unsetenv("JWT_ALGORITHM")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.JWTSecret != "secret-from-file" {
		t.Errorf("JWTSecret = %s, want secret-from-file", cfg.JWTSecret)
	}
}

func TestLoad_JWTKeysFromFile(t *testing.T) {
	os.WriteFile("/tmp/test_jwt_private.pem", []byte("private-key-from-file\n"), 0644)
	os.WriteFile("/tmp/test_jwt_public.pem", []byte("public-key-from-file\n"), 0644)
	defer os.Remove("/tmp/test_jwt_private.pem")
	defer os.Remove("/tmp/test_jwt_public.pem")

	os.Setenv("JWT_PRIVATE_KEY_FILE", "/tmp/test_jwt_private.pem")
	os.Setenv("JWT_PUBLIC_KEY_FILE", "/tmp/test_jwt_public.pem")
	os.Unsetenv("JWT_PRIVATE_KEY")
	os.Unsetenv("JWT_PUBLIC_KEY")
	os.Setenv("JWT_ALGORITHM", "RS256")
	defer os.Unsetenv("JWT_PRIVATE_KEY_FILE")
	defer os.Unsetenv("JWT_PUBLIC_KEY_FILE")
	defer os.Unsetenv("JWT_ALGORITHM")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.JWTPrivateKey != "private-key-from-file" {
		t.Errorf("JWTPrivateKey = %s, want private-key-from-file", cfg.JWTPrivateKey)
	}
	if cfg.JWTPublicKey != "public-key-from-file" {
		t.Errorf("JWTPublicKey = %s, want public-key-from-file", cfg.JWTPublicKey)
	}
}

func TestLoad_DBPasswordFromFile(t *testing.T) {
	os.WriteFile("/tmp/test_db_password.txt", []byte("db-pass-from-file\n"), 0644)
	defer os.Remove("/tmp/test_db_password.txt")

	os.Setenv("DB_PASSWORD_FILE", "/tmp/test_db_password.txt")
	os.Setenv("DB_PASSWORD", "db-pass-from-env")
	defer os.Unsetenv("DB_PASSWORD_FILE")
	defer os.Unsetenv("DB_PASSWORD")

	os.Setenv("JWT_ALGORITHM", "HS256")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_ALGORITHM")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.DBPassword != "db-pass-from-file" {
		t.Errorf("DBPassword = %s, want db-pass-from-file", cfg.DBPassword)
	}
}

func TestLoad_DBPasswordFileNotFoundFallsBackToEnv(t *testing.T) {
	os.Setenv("DB_PASSWORD_FILE", "/nonexistent/db-password.txt")
	os.Setenv("DB_PASSWORD", "db-pass-from-env")
	defer os.Unsetenv("DB_PASSWORD_FILE")
	defer os.Unsetenv("DB_PASSWORD")

	os.Setenv("JWT_ALGORITHM", "HS256")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_ALGORITHM")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.DBPassword != "db-pass-from-env" {
		t.Errorf("DBPassword = %s, want db-pass-from-env", cfg.DBPassword)
	}
}

func TestLoad_JWTSecretFileNotFound(t *testing.T) {
	os.Setenv("JWT_SECRET_FILE", "/nonexistent/secret.txt")
	os.Unsetenv("JWT_SECRET")
	os.Setenv("JWT_ALGORITHM", "HS256")
	defer os.Unsetenv("JWT_SECRET_FILE")
	defer os.Unsetenv("JWT_ALGORITHM")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
	if err.Error() == "" {
		t.Fatal("Load() should return a descriptive error message")
	}
}

func TestLoad_JWTAlgorithmInvalidReturnsError(t *testing.T) {
	os.Setenv("JWT_ALGORITHM", "invalid")
	defer os.Unsetenv("JWT_ALGORITHM")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_SECRET")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoad_JWTAlgorithmES256(t *testing.T) {
	os.Setenv("JWT_ALGORITHM", "es256")
	os.Setenv("JWT_PRIVATE_KEY", "private-key-from-env")
	defer os.Unsetenv("JWT_ALGORITHM")
	defer os.Unsetenv("JWT_PRIVATE_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.JWTAlgorithm != "ES256" {
		t.Errorf("JWTAlgorithm = %s, want ES256", cfg.JWTAlgorithm)
	}
}

func TestLoad_InvalidRateLimitSettingsFallbackToDefaults(t *testing.T) {
	os.Setenv("RATE_LIMIT", "not-an-int")
	os.Setenv("AUTH_RATE_LIMIT", "-3")
	os.Setenv("REFRESH_RATE_LIMIT", "invalid")
	os.Setenv("RATE_LIMIT_WINDOW", "not-a-duration")
	os.Setenv("JWT_EXPIRE", "not-a-duration")
	os.Setenv("REFRESH_EXPIRE", "-3h")
	os.Setenv("ENABLE_DEBUG_COVERAGE", "not-a-bool")
	defer os.Unsetenv("RATE_LIMIT")
	defer os.Unsetenv("AUTH_RATE_LIMIT")
	defer os.Unsetenv("REFRESH_RATE_LIMIT")
	defer os.Unsetenv("RATE_LIMIT_WINDOW")
	defer os.Unsetenv("JWT_EXPIRE")
	defer os.Unsetenv("REFRESH_EXPIRE")
	defer os.Unsetenv("ENABLE_DEBUG_COVERAGE")

	os.Setenv("JWT_ALGORITHM", "HS256")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_ALGORITHM")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.RateLimit != 100 {
		t.Errorf("RateLimit = %d, want default 100", cfg.RateLimit)
	}
	if cfg.AuthRateLimit != 5 {
		t.Errorf("AuthRateLimit = %d, want default 5", cfg.AuthRateLimit)
	}
	if cfg.RefreshRateLimit != 30 {
		t.Errorf("RefreshRateLimit = %d, want default 30", cfg.RefreshRateLimit)
	}
	if cfg.RateLimitWindow != 15*time.Minute {
		t.Errorf("RateLimitWindow = %v, want default 15m", cfg.RateLimitWindow)
	}
	if cfg.JWTExpire != 15*time.Minute {
		t.Errorf("JWTExpire = %v, want default 15m", cfg.JWTExpire)
	}
	if cfg.RefreshExpire != 7*24*time.Hour {
		t.Errorf("RefreshExpire = %v, want default 7d", cfg.RefreshExpire)
	}
	if cfg.EnableDebugCoverage {
		t.Errorf("EnableDebugCoverage = %v, want default false", cfg.EnableDebugCoverage)
	}
}

func TestLoad_JWTAlgorithmMissingReturnsError(t *testing.T) {
	os.Unsetenv("JWT_ALGORITHM")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_SECRET")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
	}
}

func TestLoad_HS256MissingSecretReturnsError(t *testing.T) {
	os.Setenv("JWT_ALGORITHM", "HS256")
	os.Unsetenv("JWT_SECRET")
	os.Unsetenv("JWT_SECRET_FILE")
	defer os.Unsetenv("JWT_ALGORITHM")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want non-nil")
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

func TestGetEnvInt(t *testing.T) {
	os.Setenv("TEST_INT_VALID", "42")
	os.Setenv("TEST_INT_INVALID", "abc")
	os.Setenv("TEST_INT_NEGATIVE", "-1")
	defer os.Unsetenv("TEST_INT_VALID")
	defer os.Unsetenv("TEST_INT_INVALID")
	defer os.Unsetenv("TEST_INT_NEGATIVE")

	tests := []struct {
		key          string
		defaultValue int
		want         int
	}{
		{"TEST_INT_VALID", 10, 42},
		{"TEST_INT_INVALID", 10, 10},
		{"TEST_INT_NEGATIVE", 10, 10},
		{"TEST_INT_UNSET", 10, 10},
	}

	for _, tt := range tests {
		result := getEnvInt(tt.key, tt.defaultValue)
		if result != tt.want {
			t.Errorf("getEnvInt(%s, %d) = %d, want %d", tt.key, tt.defaultValue, result, tt.want)
		}
	}
}

func TestGetEnvDuration(t *testing.T) {
	os.Setenv("TEST_DURATION_VALID", "45m")
	os.Setenv("TEST_DURATION_INVALID", "abc")
	os.Setenv("TEST_DURATION_NEGATIVE", "-1m")
	defer os.Unsetenv("TEST_DURATION_VALID")
	defer os.Unsetenv("TEST_DURATION_INVALID")
	defer os.Unsetenv("TEST_DURATION_NEGATIVE")

	tests := []struct {
		key          string
		defaultValue time.Duration
		want         time.Duration
	}{
		{"TEST_DURATION_VALID", 15 * time.Minute, 45 * time.Minute},
		{"TEST_DURATION_INVALID", 15 * time.Minute, 15 * time.Minute},
		{"TEST_DURATION_NEGATIVE", 15 * time.Minute, 15 * time.Minute},
		{"TEST_DURATION_UNSET", 15 * time.Minute, 15 * time.Minute},
	}

	for _, tt := range tests {
		result := getEnvDuration(tt.key, tt.defaultValue)
		if result != tt.want {
			t.Errorf("getEnvDuration(%s, %v) = %v, want %v", tt.key, tt.defaultValue, result, tt.want)
		}
	}
}

func TestGetEnvBool(t *testing.T) {
	os.Setenv("TEST_BOOL_TRUE", "true")
	os.Setenv("TEST_BOOL_FALSE", "false")
	os.Setenv("TEST_BOOL_INVALID", "abc")
	defer os.Unsetenv("TEST_BOOL_TRUE")
	defer os.Unsetenv("TEST_BOOL_FALSE")
	defer os.Unsetenv("TEST_BOOL_INVALID")

	tests := []struct {
		key          string
		defaultValue bool
		want         bool
	}{
		{"TEST_BOOL_TRUE", false, true},
		{"TEST_BOOL_FALSE", true, false},
		{"TEST_BOOL_INVALID", true, true},
		{"TEST_BOOL_UNSET", false, false},
	}

	for _, tt := range tests {
		result := getEnvBool(tt.key, tt.defaultValue)
		if result != tt.want {
			t.Errorf("getEnvBool(%s, %v) = %v, want %v", tt.key, tt.defaultValue, result, tt.want)
		}
	}
}
