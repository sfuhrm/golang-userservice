// Package models defines the data structures used throughout the User Service.
// It includes database entities, request/response types, and API schemas.
package models

import (
	"encoding/json"
	"time"
)

// UserRole represents the role of a user.
type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
)

// User represents a user entity in the database.
// PasswordHash is excluded from JSON serialization for security.
type User struct {
	ID            string    `json:"id"`            // Unique user identifier (UUID)
	Username      string    `json:"username"`      // Unique username
	Email         string    `json:"email"`         // Unique email address
	PasswordHash  string    `json:"-"`             // Bcrypt password hash (never exposed)
	EmailVerified bool      `json:"emailVerified"` // Email verification status
	Disabled      bool      `json:"disabled"`      // Whether the user account is disabled
	CreatedAt     time.Time `json:"createdAt"`     // Account creation timestamp
	UpdatedAt     time.Time `json:"updatedAt"`     // Last update timestamp
}

// RefreshToken represents a refresh token stored in the database.
// Used for token rotation during authentication.
type RefreshToken struct {
	ID        string    `json:"id"`        // Unique token identifier (UUID)
	UserID    string    `json:"userId"`    // Associated user ID
	Token     string    `json:"token"`     // The refresh token value
	ExpiresAt time.Time `json:"expiresAt"` // Token expiration timestamp
	CreatedAt time.Time `json:"createdAt"` // Token creation timestamp
}

// RegisterRequest represents the request body for user registration.
// Contains username, email, and password for new account creation.
type RegisterRequest struct {
	Username string `json:"username"` // 3-30 alphanumeric characters or underscores
	Email    string `json:"email"`    // Valid email format
	Password string `json:"password"` // 8-128 characters
}

// LoginRequest represents the request body for user authentication.
// Contains credentials needed to authenticate a user.
type LoginRequest struct {
	Email    string `json:"email"`    // User's email address
	Password string `json:"password"` // User's password
}

// ChangePasswordRequest represents the request body for changing password.
// Requires both current password verification and new password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"` // Current password for verification
	NewPassword     string `json:"newPassword"`     // New password (8-128 chars)
}

// RefreshRequest represents the request body for token refresh.
// Contains the refresh token to be exchanged for new access/refresh tokens.
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"` // Valid refresh token
}

// LogoutRequest represents the request body for user logout.
// Contains the refresh token to be invalidated.
type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"` // Refresh token to invalidate
}

// AuthResponse represents the response body after successful authentication.
// Contains access token, refresh token, and token metadata.
type AuthResponse struct {
	AccessToken           string    `json:"accessToken"`           // JWT access token
	RefreshToken          string    `json:"refreshToken"`          // Refresh token for token rotation
	TokenType             string    `json:"tokenType"`             // Token type (e.g., "Bearer")
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`  // Access token expiration timestamp
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"` // Refresh token expiration timestamp
}

// ErrorResponse represents an error response body.
// Returned for validation errors, conflicts, and other API errors.
type ErrorResponse struct {
	Code    string `json:"code"`    // Error code identifier
	Message string `json:"message"` // Human-readable error message
}

// UserProfile represents the public user profile returned by the API.
// Excludes sensitive data like password hash.
type UserProfile struct {
	ID            string          `json:"id"`            // User UUID
	Username      string          `json:"username"`      // Username
	Email         string          `json:"email"`         // Email address
	EmailVerified bool            `json:"emailVerified"` // Email verification status
	Roles         []UserRole      `json:"roles"`         // User roles
	Misc          json.RawMessage `json:"misc"`          // Custom key/value data (JSON)
	CreatedAt     time.Time       `json:"createdAt"`     // Account creation time
	UpdatedAt     time.Time       `json:"updatedAt"`     // Last update time
}

// UpdateProfileRequest represents the request body for updating user profile.
// Contains optional misc data to merge with existing misc.
type UpdateProfileRequest struct {
	Misc map[string]interface{} `json:"misc"` // Key-value pairs to update
}

// AdminUser represents a user viewed by an admin.
// Includes role information and disabled status.
type AdminUser struct {
	ID            string          `json:"id"`            // User UUID
	Username      string          `json:"username"`      // Username
	Email         string          `json:"email"`         // Email address
	EmailVerified bool            `json:"emailVerified"` // Email verification status
	Disabled      bool            `json:"disabled"`      // Whether the account is disabled
	Roles         []UserRole      `json:"roles"`         // User roles
	Misc          json.RawMessage `json:"misc"`          // Custom key/value data (JSON)
	CreatedAt     time.Time       `json:"createdAt"`     // Account creation time
	UpdatedAt     time.Time       `json:"updatedAt"`     // Last update time
}

// AdminUpdateUserRequest represents the request body for admin updating a user.
type AdminUpdateUserRequest struct {
	Username      *string    `json:"username,omitempty"`      // New username (optional)
	Email         *string    `json:"email,omitempty"`         // New email (optional)
	EmailVerified *bool      `json:"emailVerified,omitempty"` // Email verification status
	Disabled      *bool      `json:"disabled,omitempty"`      // Account disabled status
	Roles         []UserRole `json:"roles,omitempty"`         // User roles (replaces existing)
}

// UserListResponse represents a paginated list of users for admin.
type UserListResponse struct {
	Users      []AdminUser `json:"users"`      // List of users
	TotalCount int         `json:"totalCount"` // Total number of users
	Page       int         `json:"page"`       // Current page
	PageSize   int         `json:"pageSize"`   // Page size
}
