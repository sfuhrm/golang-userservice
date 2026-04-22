// Package middleware provides HTTP middleware for authentication and rate limiting.
// Implements JWT Bearer token validation and IP-based request throttling.
package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"userservice/config"
	"userservice/models"
)

// JWTClaims represents the claims stored in a JWT access token.
// Includes the standard subject claim (sub) and user roles extracted from the token.
type JWTClaims struct {
	Roles []models.UserRole `json:"roles"` // User roles from the token
	jwt.RegisteredClaims
}

// RateLimiter implements IP-based rate limiting using a sliding window algorithm.
// Tracks request timestamps per client IP and enforces request limits.
type RateLimiter struct {
	requests map[string][]time.Time // Request timestamps per IP address
	mu       sync.Mutex             // Protects concurrent access to requests map
	limit    int                    // Maximum requests allowed per window
	window   time.Duration          // Time window for rate limiting
}

// NewRateLimiter creates a new RateLimiter instance with the specified limit and window.
// limit: maximum number of requests allowed
// window: time duration for the rate limiting window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request from the given IP is allowed under rate limits.
// Uses a sliding window approach to count recent requests.
// Returns true if the request is allowed, false if rate limit is exceeded.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	requests := rl.requests[ip]
	var validRequests []time.Time

	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= rl.limit {
		rl.requests[ip] = validRequests
		return false
	}

	validRequests = append(validRequests, now)
	rl.requests[ip] = validRequests
	return true
}

// Middleware returns an Echo middleware function that enforces rate limiting.
// Returns 429 Too Many Requests when rate limit is exceeded.
func (rl *RateLimiter) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()

			if !rl.Allow(ip) {
				retryAfter := int(rl.window.Seconds())
				c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
				return c.JSON(http.StatusTooManyRequests, models.ErrorResponse{
					Code:    "RATE_LIMIT_EXCEEDED",
					Message: "Too many requests. Please try again later.",
				})
			}

			return next(c)
		}
	}
}

// JWTAuth returns an Echo middleware that validates JWT Bearer tokens.
// Extracts and validates the access token from the Authorization header.
// Sets the userID and roles in the Echo context for downstream handlers.
func JWTAuth(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
					Code:    "UNAUTHORIZED",
					Message: "Missing or invalid authorization header",
				})
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			claims := &JWTClaims{}
			parseOptions := []jwt.ParserOption{}
			if cfg.JWTIssuer != "" {
				parseOptions = append(parseOptions, jwt.WithIssuer(cfg.JWTIssuer))
			}
			if cfg.JWTAudience != "" {
				parseOptions = append(parseOptions, jwt.WithAudience(cfg.JWTAudience))
			}

			token, err := jwt.ParseWithClaims(tokenString, claims, tokenValidationKeyFunc(cfg), parseOptions...)

			if err != nil || !token.Valid {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
					Code:    "UNAUTHORIZED",
					Message: "Invalid or expired token",
				})
			}
			if claims.Subject == "" {
				return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
					Code:    "UNAUTHORIZED",
					Message: "Invalid token subject",
				})
			}

			c.Set("userID", claims.Subject)
			c.Set("roles", claims.Roles)
			return next(c)
		}
	}
}

// RequireRole returns an Echo middleware that checks if the user has the required role.
func RequireRole(requiredRole models.UserRole) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			roles, ok := c.Get("roles").([]models.UserRole)
			if !ok {
				return c.JSON(http.StatusForbidden, models.ErrorResponse{
					Code:    "FORBIDDEN",
					Message: "Insufficient permissions",
				})
			}

			for _, role := range roles {
				if role == requiredRole {
					return next(c)
				}
			}

			return c.JSON(http.StatusForbidden, models.ErrorResponse{
				Code:    "FORBIDDEN",
				Message: "Insufficient permissions",
			})
		}
	}
}

// GenerateAccessToken creates a new JWT access token for the given user.
// The token contains the user ID, roles, and expires according to configuration.
func GenerateAccessToken(userID string, roles []models.UserRole, cfg *config.Config) (string, error) {
	return GenerateAccessTokenWithJTI(userID, roles, uuid.NewString(), cfg)
}

// GenerateAccessTokenWithJTI creates a new JWT access token with an explicit JWT ID (jti).
func GenerateAccessTokenWithJTI(userID string, roles []models.UserRole, jti string, cfg *config.Config) (string, error) {
	claims := &JWTClaims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			Issuer:    cfg.JWTIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.JWTExpire)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	if cfg.JWTAudience != "" {
		claims.Audience = jwt.ClaimStrings{cfg.JWTAudience}
	}

	signingMethod, signingKey, err := tokenSigningConfig(cfg)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString(signingKey)
}

func jwtAlgorithm(cfg *config.Config) string {
	algorithm := strings.ToUpper(strings.TrimSpace(cfg.JWTAlgorithm))
	switch algorithm {
	case "", jwt.SigningMethodHS256.Alg():
		return jwt.SigningMethodHS256.Alg()
	case
		jwt.SigningMethodHS384.Alg(),
		jwt.SigningMethodHS512.Alg(),
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodPS384.Alg(),
		jwt.SigningMethodPS512.Alg(),
		jwt.SigningMethodES256.Alg(),
		jwt.SigningMethodES384.Alg(),
		jwt.SigningMethodES512.Alg():
		return algorithm
	default:
		return jwt.SigningMethodHS256.Alg()
	}
}

func tokenValidationKeyFunc(cfg *config.Config) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		algorithm := jwtAlgorithm(cfg)
		if token.Method.Alg() != algorithm {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}

		verificationKey, err := tokenVerificationKey(cfg, algorithm)
		if err != nil {
			return nil, err
		}
		return verificationKey, nil
	}
}

func tokenSigningConfig(cfg *config.Config) (jwt.SigningMethod, interface{}, error) {
	algorithm := jwtAlgorithm(cfg)
	switch algorithm {
	case jwt.SigningMethodHS256.Alg():
		return jwt.SigningMethodHS256, []byte(cfg.JWTSecret), nil
	case jwt.SigningMethodHS384.Alg():
		return jwt.SigningMethodHS384, []byte(cfg.JWTSecret), nil
	case jwt.SigningMethodHS512.Alg():
		return jwt.SigningMethodHS512, []byte(cfg.JWTSecret), nil
	case jwt.SigningMethodRS256.Alg():
		fallthrough
	case jwt.SigningMethodRS384.Alg():
		fallthrough
	case jwt.SigningMethodRS512.Alg():
		fallthrough
	case jwt.SigningMethodPS256.Alg():
		fallthrough
	case jwt.SigningMethodPS384.Alg():
		fallthrough
	case jwt.SigningMethodPS512.Alg():
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.JWTPrivateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("parse jwt private key: %w", err)
		}
		switch algorithm {
		case jwt.SigningMethodRS256.Alg():
			return jwt.SigningMethodRS256, privateKey, nil
		case jwt.SigningMethodRS384.Alg():
			return jwt.SigningMethodRS384, privateKey, nil
		case jwt.SigningMethodRS512.Alg():
			return jwt.SigningMethodRS512, privateKey, nil
		case jwt.SigningMethodPS256.Alg():
			return jwt.SigningMethodPS256, privateKey, nil
		case jwt.SigningMethodPS384.Alg():
			return jwt.SigningMethodPS384, privateKey, nil
		default:
			return jwt.SigningMethodPS512, privateKey, nil
		}
	case jwt.SigningMethodES256.Alg():
		fallthrough
	case jwt.SigningMethodES384.Alg():
		fallthrough
	case jwt.SigningMethodES512.Alg():
		privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(cfg.JWTPrivateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("parse jwt private key: %w", err)
		}
		switch algorithm {
		case jwt.SigningMethodES256.Alg():
			return jwt.SigningMethodES256, privateKey, nil
		case jwt.SigningMethodES384.Alg():
			return jwt.SigningMethodES384, privateKey, nil
		default:
			return jwt.SigningMethodES512, privateKey, nil
		}
	default:
		return nil, nil, fmt.Errorf("unsupported jwt algorithm: %s", algorithm)
	}
}

func tokenVerificationKey(cfg *config.Config, algorithm string) (interface{}, error) {
	switch algorithm {
	case jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg():
		return []byte(cfg.JWTSecret), nil
	case
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodPS384.Alg(),
		jwt.SigningMethodPS512.Alg():
		return jwtRSAVerificationKey(cfg)
	case jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg(), jwt.SigningMethodES512.Alg():
		return jwtECDSAVerificationKey(cfg)
	default:
		return nil, fmt.Errorf("unsupported jwt algorithm: %s", algorithm)
	}
}

func jwtRSAVerificationKey(cfg *config.Config) (interface{}, error) {
	if strings.TrimSpace(cfg.JWTPublicKey) != "" {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.JWTPublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse jwt public key: %w", err)
		}
		return publicKey, nil
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.JWTPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse jwt private key: %w", err)
	}
	return &privateKey.PublicKey, nil
}

func jwtECDSAVerificationKey(cfg *config.Config) (interface{}, error) {
	if strings.TrimSpace(cfg.JWTPublicKey) != "" {
		publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(cfg.JWTPublicKey))
		if err != nil {
			return nil, fmt.Errorf("parse jwt public key: %w", err)
		}
		return publicKey, nil
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(cfg.JWTPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("parse jwt private key: %w", err)
	}
	return &privateKey.PublicKey, nil
}
