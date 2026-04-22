package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"userservice/config"
	"userservice/models"
)

func generateRSAKeyPairPEM(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	return string(privatePEM), string(publicPEM)
}

func generateECDSAKeyPairPEM(t *testing.T) (string, string) {
	return generateECDSAKeyPairPEMWithCurve(t, elliptic.P256())
}

func generateECDSAKeyPairPEMWithCurve(t *testing.T, curve elliptic.Curve) (string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	return string(privatePEM), string(publicPEM)
}

func testJWTConfigForAlgorithm(t *testing.T, algorithm string) *config.Config {
	t.Helper()

	cfg := &config.Config{
		JWTAlgorithm: algorithm,
		JWTExpire:    15 * time.Minute,
	}

	switch algorithm {
	case "HS256", "HS384", "HS512":
		cfg.JWTSecret = "test-secret"
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		privateKeyPEM, publicKeyPEM := generateRSAKeyPairPEM(t)
		cfg.JWTPrivateKey = privateKeyPEM
		cfg.JWTPublicKey = publicKeyPEM
	case "ES256":
		privateKeyPEM, publicKeyPEM := generateECDSAKeyPairPEMWithCurve(t, elliptic.P256())
		cfg.JWTPrivateKey = privateKeyPEM
		cfg.JWTPublicKey = publicKeyPEM
	case "ES384":
		privateKeyPEM, publicKeyPEM := generateECDSAKeyPairPEMWithCurve(t, elliptic.P384())
		cfg.JWTPrivateKey = privateKeyPEM
		cfg.JWTPublicKey = publicKeyPEM
	case "ES512":
		privateKeyPEM, publicKeyPEM := generateECDSAKeyPairPEMWithCurve(t, elliptic.P521())
		cfg.JWTPrivateKey = privateKeyPEM
		cfg.JWTPublicKey = publicKeyPEM
	default:
		t.Fatalf("unsupported test algorithm: %s", algorithm)
	}

	return cfg
}

func verificationKeyFuncForConfig(cfg *config.Config) jwt.Keyfunc {
	switch cfg.JWTAlgorithm {
	case "HS256", "HS384", "HS512":
		return func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		}
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return func(token *jwt.Token) (interface{}, error) {
			return jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.JWTPublicKey))
		}
	case "ES256", "ES384", "ES512":
		return func(token *jwt.Token) (interface{}, error) {
			return jwt.ParseECPublicKeyFromPEM([]byte(cfg.JWTPublicKey))
		}
	default:
		return nil
	}
}

func TestGenerateAccessToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateAccessToken() should return a non-empty token")
	}
}

func TestGenerateAccessToken_RS256(t *testing.T) {
	privateKeyPEM, publicKeyPEM := generateRSAKeyPairPEM(t)
	cfg := &config.Config{
		JWTAlgorithm:  "RS256",
		JWTPrivateKey: privateKeyPEM,
		JWTPublicKey:  publicKeyPEM,
		JWTExpire:     15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}
	if token == "" {
		t.Error("GenerateAccessToken() should return a non-empty token")
	}

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPEM))
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}
	if parsed.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		t.Errorf("token signing method = %s, want %s", parsed.Method.Alg(), jwt.SigningMethodRS256.Alg())
	}
}

func TestGenerateAccessToken_RS256MissingPrivateKey(t *testing.T) {
	cfg := &config.Config{
		JWTAlgorithm: "RS256",
		JWTExpire:    15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err == nil {
		t.Errorf("GenerateAccessToken() error = nil, want non-nil, token = %q", token)
	}
}

func TestGenerateAccessToken_ES256(t *testing.T) {
	privateKeyPEM, publicKeyPEM := generateECDSAKeyPairPEM(t)
	cfg := &config.Config{
		JWTAlgorithm:  "ES256",
		JWTPrivateKey: privateKeyPEM,
		JWTPublicKey:  publicKeyPEM,
		JWTExpire:     15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}
	if token == "" {
		t.Error("GenerateAccessToken() should return a non-empty token")
	}

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return jwt.ParseECPublicKeyFromPEM([]byte(publicKeyPEM))
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}
	if parsed.Method.Alg() != jwt.SigningMethodES256.Alg() {
		t.Errorf("token signing method = %s, want %s", parsed.Method.Alg(), jwt.SigningMethodES256.Alg())
	}
}

func TestGenerateAccessToken_ES256MissingPrivateKey(t *testing.T) {
	cfg := &config.Config{
		JWTAlgorithm: "ES256",
		JWTExpire:    15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err == nil {
		t.Errorf("GenerateAccessToken() error = nil, want non-nil, token = %q", token)
	}
}

func TestGenerateAccessToken_AdditionalAlgorithms(t *testing.T) {
	algorithms := []string{"HS384", "HS512", "RS384", "RS512", "PS256", "PS384", "PS512", "ES384", "ES512"}

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			cfg := testJWTConfigForAlgorithm(t, algorithm)
			verifyKeyFunc := verificationKeyFuncForConfig(cfg)
			if verifyKeyFunc == nil {
				t.Fatalf("missing verification key func for algorithm %s", algorithm)
			}

			token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
			if err != nil {
				t.Fatalf("GenerateAccessToken() error = %v", err)
			}
			if token == "" {
				t.Fatal("GenerateAccessToken() should return a non-empty token")
			}

			parsed, err := jwt.Parse(token, verifyKeyFunc)
			if err != nil {
				t.Fatalf("jwt.Parse() error = %v", err)
			}
			if parsed.Method.Alg() != algorithm {
				t.Errorf("token signing method = %s, want %s", parsed.Method.Alg(), algorithm)
			}
		})
	}
}

func TestGenerateAccessToken_UsesSubClaim(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:   "test-secret",
		JWTIssuer:   "userservice",
		JWTAudience: "userservice-api",
		JWTExpire:   15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T, want jwt.MapClaims", parsed.Claims)
	}

	if claims["sub"] != "user-123" {
		t.Errorf("sub claim = %v, want user-123", claims["sub"])
	}
	if claims["jti"] == "" {
		t.Error("jti claim should be present and non-empty")
	}
	if claims["iss"] != "userservice" {
		t.Errorf("iss claim = %v, want userservice", claims["iss"])
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != "userservice-api" {
			t.Errorf("aud claim = %v, want userservice-api", claims["aud"])
		}
	case []interface{}:
		if len(aud) != 1 || aud[0] != "userservice-api" {
			t.Errorf("aud claim = %v, want userservice-api", claims["aud"])
		}
	default:
		t.Errorf("aud claim type = %T, want string or []interface{}", claims["aud"])
	}

	if _, exists := claims["userId"]; exists {
		t.Error("userId claim should not be present")
	}
}

func TestGenerateAccessTokenWithJTI_UsesProvidedJTI(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token, err := GenerateAccessTokenWithJTI("user-123", []models.UserRole{models.RoleUser}, "42", cfg)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithJTI() error = %v", err)
	}

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T, want jwt.MapClaims", parsed.Claims)
	}

	if claims["jti"] != "42" {
		t.Errorf("jti claim = %v, want 42", claims["jti"])
	}
}

func TestGenerateAccessToken_WithMultipleRoles(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser, models.RoleAdmin}, cfg)
	if err != nil {
		t.Fatalf("GenerateAccessToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateAccessToken() should return a non-empty token")
	}
}

func TestJWTAuth_MissingHeader(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_InvalidFormat(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat token123")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_InvalidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_InvalidIssuer(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTIssuer: "userservice",
		JWTExpire: 15 * time.Minute,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "user-123",
		"roles": []string{"user"},
		"iss":   "different-issuer",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err = handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_InvalidAudience(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:   "test-secret",
		JWTAudience: "userservice-api",
		JWTExpire:   15 * time.Minute,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "user-123",
		"roles": []string{"user"},
		"aud":   "different-audience",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err = handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_MissingSubject(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"roles": []string{"user"},
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})
	tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err = handler(c)
	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: -1 * time.Hour,
	}

	token, _ := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_ValidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		userID := c.Get("userID").(string)
		return c.String(http.StatusOK, userID)
	})

	err = handler(c)

	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != "user-123" {
		t.Errorf("JWTAuth() userID = %s, want user-123", rec.Body.String())
	}
}

func TestJWTAuth_ValidToken_RS256(t *testing.T) {
	privateKeyPEM, publicKeyPEM := generateRSAKeyPairPEM(t)
	cfg := &config.Config{
		JWTAlgorithm:  "RS256",
		JWTPrivateKey: privateKeyPEM,
		JWTPublicKey:  publicKeyPEM,
		JWTExpire:     15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		userID := c.Get("userID").(string)
		return c.String(http.StatusOK, userID)
	})

	err = handler(c)
	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "user-123" {
		t.Errorf("JWTAuth() userID = %s, want user-123", rec.Body.String())
	}
}

func TestJWTAuth_ValidToken_ES256(t *testing.T) {
	privateKeyPEM, publicKeyPEM := generateECDSAKeyPairPEM(t)
	cfg := &config.Config{
		JWTAlgorithm:  "ES256",
		JWTPrivateKey: privateKeyPEM,
		JWTPublicKey:  publicKeyPEM,
		JWTExpire:     15 * time.Minute,
	}

	token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		userID := c.Get("userID").(string)
		return c.String(http.StatusOK, userID)
	})

	err = handler(c)
	if err != nil {
		t.Errorf("JWTAuth() error = %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "user-123" {
		t.Errorf("JWTAuth() userID = %s, want user-123", rec.Body.String())
	}
}

func TestJWTAuth_ValidToken_AdditionalAlgorithms(t *testing.T) {
	algorithms := []string{"HS384", "HS512", "RS384", "RS512", "PS256", "PS384", "PS512", "ES384", "ES512"}

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			cfg := testJWTConfigForAlgorithm(t, algorithm)

			token, err := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
			if err != nil {
				t.Fatalf("failed to generate token: %v", err)
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := JWTAuth(cfg)(func(c echo.Context) error {
				userID := c.Get("userID").(string)
				return c.String(http.StatusOK, userID)
			})

			err = handler(c)
			if err != nil {
				t.Errorf("JWTAuth() error = %v", err)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusOK)
			}
			if rec.Body.String() != "user-123" {
				t.Errorf("JWTAuth() userID = %s, want user-123", rec.Body.String())
			}
		})
	}
}

func TestJWTAuth_ExtractsRoles(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token, _ := GenerateAccessToken("user-123", []models.UserRole{models.RoleUser, models.RoleAdmin}, cfg)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := JWTAuth(cfg)(func(c echo.Context) error {
		roles := c.Get("roles").([]models.UserRole)
		return c.String(http.StatusOK, strconv.Itoa(len(roles)))
	})

	handler(c)

	if rec.Body.String() != "2" {
		t.Errorf("JWTAuth() roles count = %s, want 2", rec.Body.String())
	}
}

func TestRequireRole_Allowed(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	handler := RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("RequireRole() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireRole_Forbidden(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleUser})

	handler := RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("RequireRole() error = %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireRole_NoRole(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("RequireRole() error = %v", err)
	}

	if rec.Code != http.StatusForbidden {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleUser, models.RoleAdmin})

	handler := RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("RequireRole() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)

	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	if rl.Allow("192.168.1.1") {
		t.Error("Request 6 should be denied")
	}

	if !rl.Allow("192.168.1.2") {
		t.Error("New IP should be allowed")
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)

	if !rl.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}
	if !rl.Allow("192.168.1.1") {
		t.Error("Second request should be allowed")
	}
	if rl.Allow("192.168.1.1") {
		t.Error("Third request should be denied")
	}

	time.Sleep(60 * time.Millisecond)

	if !rl.Allow("192.168.1.1") {
		t.Error("Request after window expiry should be allowed")
	}
}

func TestRateLimiter_Middleware_AllowsRequest(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := rl.Middleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("RateLimiter.Middleware() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("RateLimiter.Middleware() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRateLimiter_Middleware_BlocksRequest(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)

	rl.Allow("192.168.1.1")

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := rl.Middleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	err := handler(c)

	if err != nil {
		t.Errorf("RateLimiter.Middleware() error = %v", err)
	}

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("RateLimiter.Middleware() status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Retry-After header should be set")
	}
	parsedRetryAfter, err := strconv.Atoi(retryAfter)
	if err != nil {
		t.Fatalf("Retry-After should be numeric, got %q: %v", retryAfter, err)
	}
	if parsedRetryAfter != int(time.Minute.Seconds()) {
		t.Errorf("Retry-After = %d, want %d", parsedRetryAfter, int(time.Minute.Seconds()))
	}
}
