// Package middleware provides HTTP middleware for authentication and rate limiting.
// Implements JWT Bearer token validation and IP-based request throttling.
package middleware

import (
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

			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return []byte(cfg.JWTSecret), nil
			}, parseOptions...)

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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWTSecret))
}
