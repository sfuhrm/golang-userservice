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

// TokenType represents the type of verification token.
type TokenType string

const (
	TokenTypeRegistration TokenType = "registration"
	TokenTypeRecovery     TokenType = "recovery"
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

// VerificationToken represents a token for email verification or password recovery.
type VerificationToken struct {
	ID        string    `json:"id"`        // Unique token identifier (UUID)
	UserID    string    `json:"userId"`    // Associated user ID
	Token     string    `json:"token"`     // The verification token value
	Type      TokenType `json:"type"`      // Token type (registration or recovery)
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
	User                  *User     `json:"user,omitempty"`        // User profile
	Links                 []Link    `json:"links"`                 // Hypermedia links
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
	Links         []Link          `json:"links"`         // Hypermedia links
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
	Links         []Link          `json:"links"`         // Hypermedia links
}

// AdminUpdateUserRequest represents the request body for admin updating a user.
type AdminUpdateUserRequest struct {
	Username      *string    `json:"username,omitempty"`      // New username (optional)
	Email         *string    `json:"email,omitempty"`         // New email (optional)
	EmailVerified *bool      `json:"emailVerified,omitempty"` // Email verification status
	Disabled      *bool      `json:"disabled,omitempty"`      // Account disabled status
	Roles         []UserRole `json:"roles,omitempty"`         // User roles (replaces existing)
}

// Link represents a hypermedia link for HATEOAS.
type Link struct {
	Rel    string `json:"rel"`              // Relation type (e.g., self, next, previous)
	Href   string `json:"href"`             // URL of the linked resource
	Method string `json:"method,omitempty"` // HTTP method for the link
}

// RegisterResponse represents the response body after successful user registration.
type RegisterResponse struct {
	UserID  string `json:"userId"`  // ID of the newly created user
	Message string `json:"message"` // Success message
	Links   []Link `json:"links"`   // Hypermedia links
}

// UserListResponse represents a paginated list of users for admin.
type UserListResponse struct {
	Users      []AdminUser `json:"users"`      // List of users
	TotalCount int         `json:"totalCount"` // Total number of users
	Page       int         `json:"page"`       // Current page
	PageSize   int         `json:"pageSize"`   // Page size
	Links      []Link      `json:"links"`      // Hypermedia links
}

// RegistrationMailRequest represents the request body sent to external registration mail service.
type RegistrationMailRequest struct {
	Username string `json:"username"` // User's username
	Email    string `json:"email"`    // User's email address
	Token    string `json:"token"`    // Verification token
	Callback string `json:"callback"` // Callback URL for verification
}

// RecoveryMailRequest represents the request body sent to external recovery mail service.
type RecoveryMailRequest struct {
	Email    string `json:"email"`    // User's email address
	Token    string `json:"token"`    // Recovery token
	Callback string `json:"callback"` // Callback URL for verification
}

// VerifyRegistrationRequest represents the request body for email verification.
type VerifyRegistrationRequest struct {
	Token string `json:"token"` // Verification token from email
}

// ResetPasswordRequest represents the request body for password reset with token.
type ResetPasswordRequest struct {
	Token       string `json:"token"`       // Recovery token from email
	NewPassword string `json:"newPassword"` // New password (8-128 chars)
}
