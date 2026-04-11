// Package handlers implements HTTP request handlers for the User Service API.
// Each handler corresponds to an API endpoint defined in the OpenAPI specification.
package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"userservice/config"
	"userservice/middleware"
	"userservice/models"
)

// Handler holds the dependencies for HTTP handlers.
// Provides access to the database and configuration.
type Handler struct {
	db         *sql.DB        // Database connection
	cfg        *config.Config // Application configuration
	httpClient *http.Client   // HTTP client for external service calls
}

// New creates a new Handler instance with the provided dependencies.
func New(db *sql.DB, cfg *config.Config) *Handler {
	return &Handler{
		db:         db,
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// getUserRoles retrieves all roles for a user from the database.
func (h *Handler) getUserRoles(userID string) ([]models.UserRole, error) {
	rows, err := h.db.Query("SELECT role FROM user_roles WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.UserRole
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, models.UserRole(role))
	}

	if len(roles) == 0 {
		roles = []models.UserRole{models.RoleUser}
	}

	return roles, nil
}

// nextJWTID returns the next unique JWT ID (jti) from the database sequence.
func (h *Handler) nextJWTID() (string, error) {
	var nextVal int64
	if err := h.db.QueryRow("SELECT NEXT VALUE FOR jwt_jti_seq").Scan(&nextVal); err != nil {
		return "", err
	}
	return strconv.FormatInt(nextVal, 10), nil
}

// sendRegistrationMail sends a registration verification email via external service.
func (h *Handler) sendRegistrationMail(username, email, token string) error {
	reqBody := models.RegistrationMailRequest{
		Username: username,
		Email:    email,
		Token:    token,
		Callback: h.cfg.RegistrationMailCallback,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := h.httpClient.Post(h.cfg.RegistrationMailURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("registration mail service returned status %d", resp.StatusCode)
	}

	return nil
}

// sendRecoveryMail sends a password recovery email via external service.
func (h *Handler) sendRecoveryMail(email, token string) error {
	reqBody := models.RecoveryMailRequest{
		Email:    email,
		Token:    token,
		Callback: h.cfg.RecoveryMailCallback,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := h.httpClient.Post(h.cfg.RecoveryMailURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("recovery mail service returned status %d", resp.StatusCode)
	}

	return nil
}

// Register handles user registration requests.
// Creates a new user account with hashed password and default "user" role.
// If REGISTRATION_MAIL_URL is configured, calls the external service to send verification email.
// Returns 201 Created on success, 400 for validation errors, 409 for conflicts.
func (h *Handler) Register(c echo.Context) error {
	var req models.RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	if err := h.validateRegistration(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: err.Error(),
		})
	}

	var exists int
	err := h.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?", req.Username, req.Email).Scan(&exists)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to check existing user",
		})
	}

	if exists > 0 {
		return c.JSON(http.StatusConflict, models.ErrorResponse{
			Code:    "CONFLICT",
			Message: "Username or email already exists",
		})
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to process password",
		})
	}

	userID := uuid.New().String()
	now := time.Now()

	_, err = h.db.Exec(
		"INSERT INTO users (id, username, email, password_hash, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		userID, req.Username, req.Email, string(passwordHash), false, now, now,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to create user",
		})
	}

	_, err = h.db.Exec(
		"INSERT INTO user_roles (id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
		uuid.New().String(), userID, models.RoleUser, now,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to assign default role",
		})
	}

	if h.cfg.RegistrationMailURL != "" {
		token := uuid.New().String()
		tokenExpires := now.Add(24 * time.Hour)

		_, err = h.db.Exec(
			"INSERT INTO verification_tokens (id, user_id, token, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			uuid.New().String(), userID, token, models.TokenTypeRegistration, tokenExpires, now,
		)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Code:    "INTERNAL_ERROR",
				Message: "Failed to store verification token",
			})
		}

		if err := h.sendRegistrationMail(req.Username, req.Email, token); err != nil {
			return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Code:    "INTERNAL_ERROR",
				Message: "Failed to send registration email",
			})
		}
	}

	c.Response().Header().Set("Location", fmt.Sprintf("/v1/users/%s", userID))
	return c.JSON(http.StatusCreated, models.RegisterResponse{
		UserID:  userID,
		Message: "User created successfully",
		Links: []models.Link{
			{Rel: "login", Href: "/v1/auth/login", Method: "POST"},
		},
	})
}

// Login handles user authentication requests.
// Validates credentials and generates access/refresh token pair.
// Returns 200 OK with tokens on success, 401 for invalid credentials or disabled account.
func (h *Handler) Login(c echo.Context) error {
	var req models.LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	var user models.User
	err := h.db.QueryRow(
		"SELECT id, username, email, password_hash, email_verified, disabled, created_at, updated_at FROM users WHERE email = ?",
		req.Email,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.Disabled, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Code:    "INVALID_CREDENTIALS",
			Message: "Invalid email or password",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to authenticate",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Code:    "INVALID_CREDENTIALS",
			Message: "Invalid email or password",
		})
	}

	if user.Disabled {
		return c.JSON(http.StatusForbidden, models.ErrorResponse{
			Code:    "ACCOUNT_DISABLED",
			Message: "Account is disabled",
		})
	}

	roles, err := h.getUserRoles(user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user roles",
		})
	}

	return h.generateTokens(c, user.ID, roles)
}

// Refresh handles token refresh requests using token rotation.
// Invalidates the old refresh token and generates new token pair.
// Returns 200 OK with new tokens on success, 401 for invalid/expired tokens, 403 if account disabled.
func (h *Handler) Refresh(c echo.Context) error {
	var req models.RefreshRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	var tokenRecord models.RefreshToken
	err := h.db.QueryRow(
		"SELECT id, user_id, expires_at FROM refresh_tokens WHERE token = ?",
		req.RefreshToken,
	).Scan(&tokenRecord.ID, &tokenRecord.UserID, &tokenRecord.ExpiresAt)

	if err == sql.ErrNoRows || tokenRecord.ExpiresAt.Before(time.Now()) {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Code:    "INVALID_TOKEN",
			Message: "Refresh token is invalid or expired",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to validate refresh token",
		})
	}

	var disabled bool
	err = h.db.QueryRow("SELECT disabled FROM users WHERE id = ?", tokenRecord.UserID).Scan(&disabled)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to validate user status",
		})
	}

	if disabled {
		return c.JSON(http.StatusForbidden, models.ErrorResponse{
			Code:    "ACCOUNT_DISABLED",
			Message: "Account is disabled",
		})
	}

	roles, err := h.getUserRoles(tokenRecord.UserID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user roles",
		})
	}

	_, err = h.db.Exec("DELETE FROM refresh_tokens WHERE id = ?", tokenRecord.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to invalidate old token",
		})
	}

	return h.generateTokens(c, tokenRecord.UserID, roles)
}

// Logout handles user logout requests.
// Invalidates the provided refresh token server-side.
// Returns 204 No Content on success.
func (h *Handler) Logout(c echo.Context) error {
	var req models.LogoutRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	_, err := h.db.Exec("DELETE FROM refresh_tokens WHERE token = ?", req.RefreshToken)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to logout",
		})
	}

	return c.NoContent(http.StatusNoContent)
}

// GetProfile returns the current authenticated user's profile.
// Requires valid JWT access token.
// Returns 200 OK with UserProfile, 404 if user not found.
func (h *Handler) GetProfile(c echo.Context) error {
	userID := c.Param("id")
	authUserID := c.Get("userID").(string)

	if userID != authUserID {
		return c.JSON(http.StatusForbidden, models.ErrorResponse{
			Code:    "FORBIDDEN",
			Message: "Cannot access other user's profile",
		})
	}

	var user models.User
	err := h.db.QueryRow(
		"SELECT id, username, email, email_verified, created_at, updated_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "User not found",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user",
		})
	}

	roles, err := h.getUserRoles(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user roles",
		})
	}

	var miscData json.RawMessage
	err = h.db.QueryRow("SELECT data FROM user_misc WHERE user_id = ?", userID).Scan(&miscData)
	if err == sql.ErrNoRows {
		miscData = json.RawMessage("{}")
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve misc data",
		})
	}

	return c.JSON(http.StatusOK, models.UserProfile{
		ID:            user.ID,
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Roles:         roles,
		Misc:          miscData,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		Links: []models.Link{
			{Rel: "self", Href: fmt.Sprintf("/v1/users/%s", user.ID), Method: "GET"},
		},
	})
}

// UpdateProfile updates the current authenticated user's profile misc data.
// Merges provided misc with existing misc data.
// Returns 200 OK with updated UserProfile, 404 if user not found.
func (h *Handler) UpdateProfile(c echo.Context) error {
	userID := c.Param("id")
	authUserID := c.Get("userID").(string)

	if userID != authUserID {
		return c.JSON(http.StatusForbidden, models.ErrorResponse{
			Code:    "FORBIDDEN",
			Message: "Cannot update other user's profile",
		})
	}

	var req models.UpdateProfileRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	var currentUser models.User
	err := h.db.QueryRow(
		"SELECT id, username, email, email_verified, created_at, updated_at FROM users WHERE id = ?",
		userID,
	).Scan(&currentUser.ID, &currentUser.Username, &currentUser.Email, &currentUser.EmailVerified, &currentUser.CreatedAt, &currentUser.UpdatedAt)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "User not found",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user",
		})
	}

	roles, err := h.getUserRoles(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user roles",
		})
	}

	var currentMisc json.RawMessage
	var miscExists bool
	err = h.db.QueryRow("SELECT data FROM user_misc WHERE user_id = ?", userID).Scan(&currentMisc)
	if err == sql.ErrNoRows {
		miscExists = false
		currentMisc = json.RawMessage("{}")
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve misc data",
		})
	} else {
		miscExists = true
	}

	existingData := make(map[string]interface{})

	if currentMisc != nil && len(currentMisc) > 0 {
		if err := json.Unmarshal(currentMisc, &existingData); err != nil {
			existingData = make(map[string]interface{})
		}
	}

	if req.Misc != nil {
		for key, value := range req.Misc {
			existingData[key] = value
		}
	}

	var mergedMisc json.RawMessage
	mergedMisc, err = json.Marshal(existingData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to process misc data",
		})
	}

	if miscExists {
		_, err = h.db.Exec("UPDATE user_misc SET data = ?, updated_at = ? WHERE user_id = ?", mergedMisc, time.Now(), userID)
	} else {
		_, err = h.db.Exec("INSERT INTO user_misc (id, user_id, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			uuid.New().String(), userID, mergedMisc, time.Now(), time.Now())
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to update misc data",
		})
	}

	return c.JSON(http.StatusOK, models.UserProfile{
		ID:            currentUser.ID,
		Username:      currentUser.Username,
		Email:         currentUser.Email,
		EmailVerified: currentUser.EmailVerified,
		Roles:         roles,
		Misc:          mergedMisc,
		CreatedAt:     currentUser.CreatedAt,
		UpdatedAt:     time.Now(),
		Links: []models.Link{
			{Rel: "self", Href: fmt.Sprintf("/v1/users/%s", currentUser.ID), Method: "GET"},
		},
	})
}

// DeleteAccount handles account deletion requests.
// Removes the user and associated refresh tokens from the database.
// Returns 202 Accepted on success.
func (h *Handler) DeleteAccount(c echo.Context) error {
	userID := c.Param("id")
	authUserID := c.Get("userID").(string)

	if userID != authUserID {
		return c.JSON(http.StatusForbidden, models.ErrorResponse{
			Code:    "FORBIDDEN",
			Message: "Cannot delete other user's account",
		})
	}

	result, err := h.db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to delete user",
		})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "User not found",
		})
	}

	return c.JSON(http.StatusAccepted, nil)
}

// ChangePassword handles password change requests.
// Verifies current password and updates to new password.
// Invalidates all existing refresh tokens for security.
// Returns 204 No Content on success.
func (h *Handler) ChangePassword(c echo.Context) error {
	userID := c.Param("id")
	authUserID := c.Get("userID").(string)

	if userID != authUserID {
		return c.JSON(http.StatusForbidden, models.ErrorResponse{
			Code:    "FORBIDDEN",
			Message: "Cannot change other user's password",
		})
	}

	var req models.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	if len(req.NewPassword) < 8 || len(req.NewPassword) > 128 {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Password must be between 8 and 128 characters",
		})
	}

	var currentHash string
	err := h.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&currentHash)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Code:    "UNAUTHORIZED",
			Message: "User not found",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to verify current password",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		return c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Code:    "INVALID_PASSWORD",
			Message: "Current password is incorrect",
		})
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to process new password",
		})
	}

	_, err = h.db.Exec("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", string(newHash), time.Now(), userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to update password",
		})
	}

	_, err = h.db.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", userID)
	if err != nil {
	}

	return c.NoContent(http.StatusNoContent)
}

// PasswordRecovery initiates the password recovery process.
// If RECOVERY_MAIL_URL is configured, calls the external service to send recovery email.
// If RECOVERY_MAIL_URL is not configured, returns 501 Not Implemented.
func (h *Handler) PasswordRecovery(c echo.Context) error {
	if h.cfg.RecoveryMailURL == "" {
		return c.JSON(http.StatusNotImplemented, models.ErrorResponse{
			Code:    "NOT_IMPLEMENTED",
			Message: "Password recovery service is not configured",
		})
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid email format",
		})
	}

	var userID string
	err := h.db.QueryRow("SELECT id FROM users WHERE email = ?", req.Email).Scan(&userID)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusAccepted, nil)
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to check user",
		})
	}

	now := time.Now()
	token := uuid.New().String()
	tokenExpires := now.Add(1 * time.Hour)

	_, err = h.db.Exec(
		"INSERT INTO verification_tokens (id, user_id, token, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		uuid.New().String(), userID, token, models.TokenTypeRecovery, tokenExpires, now,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to store recovery token",
		})
	}

	if err := h.sendRecoveryMail(req.Email, token); err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to send recovery email",
		})
	}

	return c.JSON(http.StatusAccepted, nil)
}

// VerifyRegistration verifies a user's email using the registration verification token.
func (h *Handler) VerifyRegistration(c echo.Context) error {
	var req models.VerifyRegistrationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	if req.Token == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Token is required",
		})
	}

	var tokenRecord models.VerificationToken
	err := h.db.QueryRow(
		"SELECT id, user_id, token, type, expires_at FROM verification_tokens WHERE token = ? AND type = ?",
		req.Token, models.TokenTypeRegistration,
	).Scan(&tokenRecord.ID, &tokenRecord.UserID, &tokenRecord.Token, &tokenRecord.Type, &tokenRecord.ExpiresAt)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "INVALID_TOKEN",
			Message: "Invalid or expired verification token",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to validate token",
		})
	}

	if tokenRecord.ExpiresAt.Before(time.Now()) {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "INVALID_TOKEN",
			Message: "Verification token has expired",
		})
	}

	_, err = h.db.Exec("UPDATE users SET email_verified = ?, updated_at = ? WHERE id = ?", true, time.Now(), tokenRecord.UserID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to verify email",
		})
	}

	_, err = h.db.Exec("DELETE FROM verification_tokens WHERE id = ?", tokenRecord.ID)
	if err != nil {
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Email verified successfully",
		"links": []models.Link{
			{Rel: "login", Href: "/v1/auth/login", Method: "POST"},
		},
	})
}

// ResetPassword resets a user's password using a recovery token.
func (h *Handler) ResetPassword(c echo.Context) error {
	var req models.ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	if req.Token == "" {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Token is required",
		})
	}

	if len(req.NewPassword) < 8 || len(req.NewPassword) > 128 {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Password must be between 8 and 128 characters",
		})
	}

	var tokenRecord models.VerificationToken
	err := h.db.QueryRow(
		"SELECT id, user_id, token, type, expires_at FROM verification_tokens WHERE token = ? AND type = ?",
		req.Token, models.TokenTypeRecovery,
	).Scan(&tokenRecord.ID, &tokenRecord.UserID, &tokenRecord.Token, &tokenRecord.Type, &tokenRecord.ExpiresAt)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "INVALID_TOKEN",
			Message: "Invalid or expired recovery token",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to validate token",
		})
	}

	if tokenRecord.ExpiresAt.Before(time.Now()) {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "INVALID_TOKEN",
			Message: "Recovery token has expired",
		})
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to process new password",
		})
	}

	now := time.Now()
	_, err = h.db.Exec("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", string(newHash), now, tokenRecord.UserID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to reset password",
		})
	}

	_, err = h.db.Exec("DELETE FROM verification_tokens WHERE user_id = ? AND type = ?", tokenRecord.UserID, models.TokenTypeRecovery)
	if err != nil {
	}

	_, err = h.db.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", tokenRecord.UserID)
	if err != nil {
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Password reset successfully",
		"links": []models.Link{
			{Rel: "login", Href: "/v1/auth/login", Method: "POST"},
		},
	})
}

// generateTokens creates a new access/refresh token pair for the given user.
// Stores the refresh token in the database for later validation.
func (h *Handler) generateTokens(c echo.Context, userID string, roles []models.UserRole) error {
	jti, err := h.nextJWTID()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to generate token ID",
		})
	}

	accessToken, err := middleware.GenerateAccessTokenWithJTI(userID, roles, jti, h.cfg)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to generate access token",
		})
	}

	refreshToken := uuid.New().String()
	expiresAt := time.Now().Add(h.cfg.RefreshExpire)

	_, err = h.db.Exec(
		"INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		uuid.New().String(), userID, refreshToken, expiresAt, time.Now(),
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to store refresh token",
		})
	}

	var user models.User
	err = h.db.QueryRow(
		"SELECT id, username, email, email_verified, created_at, updated_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user",
		})
	}

	return c.JSON(http.StatusOK, models.AuthResponse{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		TokenType:             "Bearer",
		AccessTokenExpiresAt:  time.Now().Add(h.cfg.JWTExpire),
		RefreshTokenExpiresAt: expiresAt,
		User:                  &user,
		Links: []models.Link{
			{Rel: "self", Href: "/v1/auth/login", Method: "POST"},
			{Rel: "refresh", Href: "/v1/auth/refresh", Method: "POST"},
			{Rel: "logout", Href: "/v1/auth/logout", Method: "POST"},
		},
	})
}

// validateRegistration validates the registration request fields.
// Checks username format (alphanumeric with underscores, 3-30 chars),
// email format, and password length (8-128 chars).
func (h *Handler) validateRegistration(req *models.RegisterRequest) error {
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !usernameRegex.MatchString(req.Username) || len(req.Username) < 3 || len(req.Username) > 30 {
		return echo.NewHTTPError(http.StatusBadRequest, "Username must be 3-30 alphanumeric characters or underscores")
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid email format")
	}

	if len(req.Password) < 8 || len(req.Password) > 128 {
		return echo.NewHTTPError(http.StatusBadRequest, "Password must be between 8 and 128 characters")
	}

	return nil
}

// ListUsers returns a paginated list of all users.
// Requires admin role.
func (h *Handler) ListUsers(c echo.Context) error {
	page := 1
	pageSize := 20

	if p := c.QueryParam("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.QueryParam("pageSize"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	var totalCount int
	err := h.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalCount)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to count users",
		})
	}

	offset := (page - 1) * pageSize
	rows, err := h.db.Query(
		"SELECT id, username, email, email_verified, disabled, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
		pageSize, offset,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve users",
		})
	}
	defer rows.Close()

	var users []models.AdminUser
	for rows.Next() {
		var user models.AdminUser
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.Disabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
			continue
		}

		user.Roles, err = h.getUserRoles(user.ID)
		if err != nil {
			user.Roles = []models.UserRole{models.RoleUser}
		}

		var miscData json.RawMessage
		err := h.db.QueryRow("SELECT data FROM user_misc WHERE user_id = ?", user.ID).Scan(&miscData)
		if err == sql.ErrNoRows {
			miscData = json.RawMessage("{}")
		} else if err != nil {
			miscData = json.RawMessage("{}")
		}
		user.Misc = miscData

		users = append(users, user)
	}

	links := []models.Link{
		{Rel: "self", Href: "/v1/admin/users?page=" + strconv.Itoa(page) + "&pageSize=" + strconv.Itoa(pageSize), Method: "GET"},
	}
	if totalCount > page*pageSize {
		links = append(links, models.Link{Rel: "next", Href: "/v1/admin/users?page=" + strconv.Itoa(page+1) + "&pageSize=" + strconv.Itoa(pageSize), Method: "GET"})
	}
	if totalCount > page*pageSize {
		links = append(links, models.Link{Rel: "next", Href: "/v1/admin/users?page=" + strconv.Itoa(page+1) + "&pageSize=" + strconv.Itoa(pageSize), Method: "GET"})
	}

	return c.JSON(http.StatusOK, models.UserListResponse{
		Users:      users,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
		Links:      links,
	})
}

// GetUser returns a user by ID.
// Requires admin role.
func (h *Handler) GetUser(c echo.Context) error {
	userID := c.Param("id")

	var user models.AdminUser
	err := h.db.QueryRow(
		"SELECT id, username, email, email_verified, disabled, created_at, updated_at FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &user.Email, &user.EmailVerified, &user.Disabled, &user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "User not found",
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user",
		})
	}

	user.Roles, err = h.getUserRoles(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve user roles",
		})
	}

	var miscData json.RawMessage
	err = h.db.QueryRow("SELECT data FROM user_misc WHERE user_id = ?", userID).Scan(&miscData)
	if err == sql.ErrNoRows {
		miscData = json.RawMessage("{}")
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to retrieve misc data",
		})
	}
	user.Misc = miscData
	user.Links = []models.Link{
		{Rel: "self", Href: "/v1/admin/users/" + userID, Method: "GET"},
		{Rel: "update", Href: "/v1/admin/users/" + userID, Method: "PUT"},
		{Rel: "delete", Href: "/v1/admin/users/" + userID, Method: "DELETE"},
	}

	return c.JSON(http.StatusOK, user)
}

// UpdateUser updates a user by ID.
// Requires admin role.
func (h *Handler) UpdateUser(c echo.Context) error {
	userID := c.Param("id")

	var req models.AdminUpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Code:    "VALIDATION_ERROR",
			Message: "Invalid request body",
		})
	}

	var exists int
	err := h.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&exists)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to check user",
		})
	}
	if exists == 0 {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "User not found",
		})
	}

	if req.Username != nil {
		usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
		if !usernameRegex.MatchString(*req.Username) || len(*req.Username) < 3 || len(*req.Username) > 30 {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Code:    "VALIDATION_ERROR",
				Message: "Username must be 3-30 alphanumeric characters or underscores",
			})
		}
	}

	if req.Email != nil {
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(*req.Email) {
			return c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid email format",
			})
		}
	}

	if req.Roles != nil {
		for _, role := range req.Roles {
			if role != models.RoleUser && role != models.RoleAdmin {
				return c.JSON(http.StatusBadRequest, models.ErrorResponse{
					Code:    "VALIDATION_ERROR",
					Message: "Role must be 'user' or 'admin'",
				})
			}
		}
	}

	setClauses := []string{}
	args := []interface{}{}

	if req.Username != nil {
		setClauses = append(setClauses, "username = ?")
		args = append(args, *req.Username)
	}
	if req.Email != nil {
		setClauses = append(setClauses, "email = ?")
		args = append(args, *req.Email)
	}
	if req.EmailVerified != nil {
		setClauses = append(setClauses, "email_verified = ?")
		args = append(args, *req.EmailVerified)
	}
	if req.Disabled != nil {
		setClauses = append(setClauses, "disabled = ?")
		args = append(args, *req.Disabled)
	}

	if len(setClauses) > 0 {
		setClauses = append(setClauses, "updated_at = ?")
		args = append(args, time.Now())
		args = append(args, userID)

		query := "UPDATE users SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"
		_, err = h.db.Exec(query, args...)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Code:    "INTERNAL_ERROR",
				Message: "Failed to update user",
			})
		}
	}

	if req.Roles != nil {
		_, err = h.db.Exec("DELETE FROM user_roles WHERE user_id = ?", userID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Code:    "INTERNAL_ERROR",
				Message: "Failed to update user roles",
			})
		}

		for _, role := range req.Roles {
			_, err = h.db.Exec(
				"INSERT INTO user_roles (id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
				uuid.New().String(), userID, role, time.Now(),
			)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
					Code:    "INTERNAL_ERROR",
					Message: "Failed to update user roles",
				})
			}
		}
	}

	return h.GetUser(c)
}

// DeleteUser deletes a user by ID.
// Requires admin role.
func (h *Handler) DeleteUser(c echo.Context) error {
	userID := c.Param("id")

	result, err := h.db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Code:    "INTERNAL_ERROR",
			Message: "Failed to delete user",
		})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, models.ErrorResponse{
			Code:    "NOT_FOUND",
			Message: "User not found",
		})
	}

	return c.NoContent(http.StatusNoContent)
}
