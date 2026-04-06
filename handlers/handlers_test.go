package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"userservice/config"
	"userservice/middleware"
	"userservice/models"
)

func newTestHandler(t *testing.T) (*Handler, sqlmock.Sqlmock, *echo.Echo) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	cfg := &config.Config{
		JWTSecret:       "test-secret-key",
		JWTExpire:       15 * time.Minute,
		RefreshExpire:   7 * 24 * time.Hour,
		RateLimit:       100,
		RateLimitWindow: 15 * time.Minute,
		AuthRateLimit:   5,
	}

	h := New(db, cfg)
	e := echo.New()

	return h, mock, e
}

func generateTestToken(userID string, t *testing.T, cfg *config.Config) string {
	token, err := middleware.GenerateAccessToken(userID, []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

func TestRegister_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"username":"testuser","email":"test@example.com","password":"password123"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectQuery("SELECT COUNT").WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec("INSERT INTO users").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO user_roles").WillReturnResult(sqlmock.NewResult(1, 1))

	if err := h.Register(c); err != nil {
		t.Errorf("Register() error = %v", err)
	}

	if rec.Code != http.StatusCreated {
		t.Errorf("Register() status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader("invalid json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h.Register(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Register() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "VALIDATION_ERROR" {
		t.Errorf("Register() error code = %s, want VALIDATION_ERROR", resp.Code)
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	testCases := []struct {
		name     string
		username string
	}{
		{"too short", "ab"},
		{"too long", strings.Repeat("a", 31)},
		{"invalid chars", "user@name"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := `{"username":"` + tc.username + `","email":"test@example.com","password":"password123"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h.Register(c)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("Register() status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	testCases := []struct {
		name  string
		email string
	}{
		{"no @", "testexample.com"},
		{"no domain", "test@"},
		{"no tld", "test@example"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := `{"username":"testuser","email":"` + tc.email + `","password":"password123"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h.Register(c)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("Register() status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestRegister_InvalidPassword(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	testCases := []struct {
		name     string
		password string
	}{
		{"too short", "short"},
		{"too long", strings.Repeat("a", 129)},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := `{"username":"testuser","email":"test@example.com","password":"` + tc.password + `"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h.Register(c)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("Register() status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestRegister_UserConflict(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"username":"existinguser","email":"existing@example.com","password":"password123"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	h.Register(c)

	if rec.Code != http.StatusConflict {
		t.Errorf("Register() status = %d, want %d", rec.Code, http.StatusConflict)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "CONFLICT" {
		t.Errorf("Register() error code = %s, want CONFLICT", resp.Code)
	}
}

func TestLogin_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	hashedPwd, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	passwordHash := string(hashedPwd)
	reqBody := `{"email":"test@example.com","password":"password123"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	rows := sqlmock.NewRows([]string{"id", "username", "email", "password_hash", "email_verified", "disabled", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", passwordHash, true, false, time.Now(), time.Now())
	mock.ExpectQuery("SELECT id, username, email, password_hash").WithArgs("test@example.com").WillReturnRows(rows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectExec("INSERT INTO refresh_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT id, username, email, email_verified, created_at, updated_at FROM users WHERE id = ?").
		WithArgs("user-123").
		WillReturnRows(
			sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "created_at", "updated_at"}).
				AddRow("user-123", "testuser", "test@example.com", true, time.Now(), time.Now()),
		)

	if err := h.Login(c); err != nil {
		t.Errorf("Login() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Login() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.AuthResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.AccessToken == "" {
		t.Error("Login() access token should not be empty")
	}
	if resp.RefreshToken == "" {
		t.Error("Login() refresh token should not be empty")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("Login() token type = %s, want Bearer", resp.TokenType)
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader("invalid json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h.Login(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Login() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"email":"notfound@example.com","password":"password123"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectQuery("SELECT id, username, email, password_hash").WillReturnError(sql.ErrNoRows)

	h.Login(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Login() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "INVALID_CREDENTIALS" {
		t.Errorf("Login() error code = %s, want INVALID_CREDENTIALS", resp.Code)
	}
}

func TestLogin_InvalidPassword(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	hashedPwd, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	passwordHash := string(hashedPwd)
	reqBody := `{"email":"test@example.com","password":"wrongpassword"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	rows := sqlmock.NewRows([]string{"id", "username", "email", "password_hash", "email_verified", "disabled", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", passwordHash, true, false, time.Now(), time.Now())
	mock.ExpectQuery("SELECT id, username, email, password_hash").WithArgs("test@example.com").WillReturnRows(rows)

	h.Login(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Login() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestLogin_DisabledUser(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	hashedPwd, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	passwordHash := string(hashedPwd)
	reqBody := `{"email":"test@example.com","password":"password123"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	rows := sqlmock.NewRows([]string{"id", "username", "email", "password_hash", "email_verified", "disabled", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", passwordHash, true, true, time.Now(), time.Now())
	mock.ExpectQuery("SELECT id, username, email, password_hash").WithArgs("test@example.com").WillReturnRows(rows)

	h.Login(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Login() status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "ACCOUNT_DISABLED" {
		t.Errorf("Login() error code = %s, want ACCOUNT_DISABLED", resp.Code)
	}
}

func TestRefresh_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"refreshToken":"valid-refresh-token"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	rows := sqlmock.NewRows([]string{"id", "user_id", "expires_at"}).
		AddRow("token-id", "user-123", time.Now().Add(7*24*time.Hour))
	mock.ExpectQuery("SELECT id, user_id, expires_at").WillReturnRows(rows)
	mock.ExpectQuery("SELECT disabled FROM users").WillReturnRows(sqlmock.NewRows([]string{"disabled"}).AddRow(false))
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectExec("DELETE FROM refresh_tokens").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO refresh_tokens").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT id, username, email, email_verified, created_at, updated_at FROM users WHERE id = ?").
		WithArgs("user-123").
		WillReturnRows(
			sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "created_at", "updated_at"}).
				AddRow("user-123", "testuser", "test@example.com", true, time.Now(), time.Now()),
		)

	if err := h.Refresh(c); err != nil {
		t.Errorf("Refresh() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Refresh() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.AuthResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.AccessToken == "" {
		t.Error("Refresh() access token should not be empty")
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"refreshToken":"invalid-token"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectQuery("SELECT id, user_id, expires_at").WillReturnError(sql.ErrNoRows)

	h.Refresh(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Refresh() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "INVALID_TOKEN" {
		t.Errorf("Refresh() error code = %s, want INVALID_TOKEN", resp.Code)
	}
}

func TestRefresh_ExpiredToken(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"refreshToken":"expired-token"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	rows := sqlmock.NewRows([]string{"id", "user_id", "expires_at"}).
		AddRow("token-id", "user-123", time.Now().Add(-1*time.Hour))
	mock.ExpectQuery("SELECT id, user_id, expires_at").WillReturnRows(rows)

	h.Refresh(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Refresh() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestLogout_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"refreshToken":"token-to-delete"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectExec("DELETE FROM refresh_tokens").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := h.Logout(c); err != nil {
		t.Errorf("Logout() error = %v", err)
	}

	if rec.Code != http.StatusNoContent {
		t.Errorf("Logout() status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestLogout_InvalidJSON(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", strings.NewReader("invalid"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h.Logout(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Logout() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestGetProfile_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", true, now, now)
	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectQuery("SELECT data FROM user_misc").WillReturnError(sql.ErrNoRows)

	if err := h.GetProfile(c); err != nil {
		t.Errorf("GetProfile() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("GetProfile() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.UserProfile
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.ID != "user-123" {
		t.Errorf("GetProfile() id = %s, want user-123", resp.ID)
	}
	if resp.Username != "testuser" {
		t.Errorf("GetProfile() username = %s, want testuser", resp.Username)
	}
	if resp.Email != "test@example.com" {
		t.Errorf("GetProfile() email = %s, want test@example.com", resp.Email)
	}
	if len(resp.Links) == 0 || resp.Links[0].Href != "/v1/users/user-123" {
		t.Errorf("GetProfile() self link = %v, want /v1/users/user-123", resp.Links)
	}
}

func TestGetProfile_WithMisc(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", true, now, now)
	mock.ExpectQuery("SELECT .+ FROM users WHERE id").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	miscRows := sqlmock.NewRows([]string{"data"}).AddRow([]byte(`{"theme":"dark","notifications":true}`))
	mock.ExpectQuery("SELECT .+ FROM user_misc WHERE user_id").WillReturnRows(miscRows)

	if err := h.GetProfile(c); err != nil {
		t.Errorf("GetProfile() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("GetProfile() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.UserProfile
	json.Unmarshal(rec.Body.Bytes(), &resp)

	var misc map[string]interface{}
	json.Unmarshal(resp.Misc, &misc)

	if misc["theme"] != "dark" {
		t.Errorf("GetProfile() misc theme = %v, want dark", misc["theme"])
	}
}

func TestGetProfile_UserNotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnError(sql.ErrNoRows)

	h.GetProfile(c)

	if rec.Code != http.StatusNotFound {
		t.Errorf("GetProfile() status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "NOT_FOUND" {
		t.Errorf("GetProfile() error code = %s, want NOT_FOUND", resp.Code)
	}
}

func TestUpdateProfile_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"misc":{"theme":"dark","language":"en"}}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", true, now, now)
	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectQuery("SELECT data FROM user_misc").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO user_misc").WillReturnResult(sqlmock.NewResult(1, 1))

	if err := h.UpdateProfile(c); err != nil {
		t.Errorf("UpdateProfile() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("UpdateProfile() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.UserProfile
	json.Unmarshal(rec.Body.Bytes(), &resp)

	var misc map[string]interface{}
	json.Unmarshal(resp.Misc, &misc)

	if misc["theme"] != "dark" {
		t.Errorf("UpdateProfile() misc theme = %v, want dark", misc["theme"])
	}
	if misc["language"] != "en" {
		t.Errorf("UpdateProfile() misc language = %v, want en", misc["language"])
	}
	if len(resp.Links) == 0 || resp.Links[0].Href != "/v1/users/user-123" {
		t.Errorf("UpdateProfile() self link = %v, want /v1/users/user-123", resp.Links)
	}
}

func TestUpdateProfile_MergeWithExisting(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"misc":{"theme":"light"}}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", true, now, now)
	mock.ExpectQuery("SELECT .+ FROM users WHERE id").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	miscRows := sqlmock.NewRows([]string{"data"}).AddRow([]byte(`{"notifications":true,"language":"en"}`))
	mock.ExpectQuery("SELECT .+ FROM user_misc WHERE user_id").WillReturnRows(miscRows)
	mock.ExpectExec("UPDATE user_misc").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := h.UpdateProfile(c); err != nil {
		t.Errorf("UpdateProfile() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("UpdateProfile() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.UserProfile
	json.Unmarshal(rec.Body.Bytes(), &resp)

	var misc map[string]interface{}
	json.Unmarshal(resp.Misc, &misc)

	if misc["theme"] != "light" {
		t.Errorf("UpdateProfile() misc theme = %v, want light", misc["theme"])
	}
	if misc["notifications"] != true {
		t.Errorf("UpdateProfile() misc notifications = %v, want true", misc["notifications"])
	}
	if misc["language"] != "en" {
		t.Errorf("UpdateProfile() misc language = %v, want en", misc["language"])
	}
}

func TestUpdateProfile_UserNotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"misc":{"theme":"dark"}}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnError(sql.ErrNoRows)

	h.UpdateProfile(c)

	if rec.Code != http.StatusNotFound {
		t.Errorf("UpdateProfile() status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "NOT_FOUND" {
		t.Errorf("UpdateProfile() error code = %s, want NOT_FOUND", resp.Code)
	}
}

func TestUpdateProfile_InvalidJSON(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123", strings.NewReader("invalid"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	h.UpdateProfile(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("UpdateProfile() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDeleteAccount_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodDelete, "/v1/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectExec("DELETE FROM users").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := h.DeleteAccount(c); err != nil {
		t.Errorf("DeleteAccount() error = %v", err)
	}

	if rec.Code != http.StatusAccepted {
		t.Errorf("DeleteAccount() status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func TestDeleteAccount_UserNotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodDelete, "/v1/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectExec("DELETE FROM users").WillReturnResult(sqlmock.NewResult(0, 0))

	h.DeleteAccount(c)

	if rec.Code != http.StatusNotFound {
		t.Errorf("DeleteAccount() status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestChangePassword_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	hashedPwd, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	currentHash := string(hashedPwd)
	reqBody := `{"currentPassword":"oldpassword","newPassword":"newpassword123"}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123/password", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectQuery("SELECT password_hash").WithArgs("user-123").WillReturnRows(sqlmock.NewRows([]string{"password_hash"}).AddRow(currentHash))
	mock.ExpectExec("UPDATE users").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM refresh_tokens").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := h.ChangePassword(c); err != nil {
		t.Errorf("ChangePassword() error = %v", err)
	}

	if rec.Code != http.StatusNoContent {
		t.Errorf("ChangePassword() status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestChangePassword_InvalidJSON(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123/password", strings.NewReader("invalid"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	h.ChangePassword(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("ChangePassword() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestChangePassword_NewPasswordTooShort(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"currentPassword":"oldpassword","newPassword":"short"}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123/password", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	h.ChangePassword(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("ChangePassword() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if !strings.Contains(resp.Message, "8") {
		t.Errorf("ChangePassword() error message should mention password length requirement")
	}
}

func TestChangePassword_NewPasswordTooLong(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"currentPassword":"oldpassword","newPassword":"` + strings.Repeat("a", 129) + `"}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123/password", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	h.ChangePassword(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("ChangePassword() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestChangePassword_UserNotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"currentPassword":"oldpassword","newPassword":"newpassword123"}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123/password", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectQuery("SELECT password_hash").WillReturnError(sql.ErrNoRows)

	h.ChangePassword(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("ChangePassword() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestChangePassword_IncorrectCurrentPassword(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	hashedPwd, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	currentHash := string(hashedPwd)
	reqBody := `{"currentPassword":"wrongpassword","newPassword":"newpassword123"}`

	req := httptest.NewRequest(http.MethodPut, "/v1/users/user-123/password", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("userID", "user-123")
	c.SetParamNames("id")
	c.SetParamValues("user-123")

	mock.ExpectQuery("SELECT password_hash").WithArgs("user-123").WillReturnRows(sqlmock.NewRows([]string{"password_hash"}).AddRow(currentHash))

	h.ChangePassword(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("ChangePassword() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var resp models.ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.Code != "INVALID_PASSWORD" {
		t.Errorf("ChangePassword() error code = %s, want INVALID_PASSWORD", resp.Code)
	}
}

func TestPasswordRecovery_ValidEmail(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"email":"test@example.com"}`

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-recovery", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.PasswordRecovery(c); err != nil {
		t.Errorf("PasswordRecovery() error = %v", err)
	}

	if rec.Code != http.StatusAccepted {
		t.Errorf("PasswordRecovery() status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func TestPasswordRecovery_InvalidEmail(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	testCases := []struct {
		name  string
		email string
	}{
		{"no @", "testexample.com"},
		{"no domain", "test@"},
		{"no tld", "test@example"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := `{"email":"` + tc.email + `"}`
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-recovery", strings.NewReader(reqBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			h.PasswordRecovery(c)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("PasswordRecovery() status = %d, want %d", rec.Code, http.StatusBadRequest)
			}

			var resp models.ErrorResponse
			json.Unmarshal(rec.Body.Bytes(), &resp)

			if resp.Code != "VALIDATION_ERROR" {
				t.Errorf("PasswordRecovery() error code = %s, want VALIDATION_ERROR", resp.Code)
			}
		})
	}
}

func TestPasswordRecovery_InvalidJSON(t *testing.T) {
	h, _, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/password-recovery", strings.NewReader("invalid"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h.PasswordRecovery(c)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("PasswordRecovery() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestJWTAuth_MissingHeader(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := middleware.JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_InvalidFormat(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	req.Header.Set("Authorization", "InvalidFormat token123")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := middleware.JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_InvalidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := middleware.JWTAuth(cfg)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_ValidToken(t *testing.T) {
	cfg := &config.Config{
		JWTSecret: "test-secret",
		JWTExpire: 15 * time.Minute,
	}

	token, err := middleware.GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/user-123", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := middleware.JWTAuth(cfg)(func(c echo.Context) error {
		userID := c.Get("userID").(string)
		return c.String(http.StatusOK, userID)
	})

	handler(c)

	if rec.Code != http.StatusOK {
		t.Errorf("JWTAuth() status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != "user-123" {
		t.Errorf("JWTAuth() userID = %s, want user-123", rec.Body.String())
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := middleware.NewRateLimiter(5, time.Minute)

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
	rl := middleware.NewRateLimiter(2, 50*time.Millisecond)

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

func TestRequireRole_Allowed(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	handler := middleware.RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusOK {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireRole_Forbidden(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleUser})

	handler := middleware.RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireRole_NoRole(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := middleware.RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusForbidden {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleUser, models.RoleAdmin})

	handler := middleware.RequireRole(models.RoleAdmin)(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	if rec.Code != http.StatusOK {
		t.Errorf("RequireRole() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestListUsers_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "disabled", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", true, false, now, now)
	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectQuery("SELECT data FROM user_misc").WillReturnError(sql.ErrNoRows)

	if err := h.ListUsers(c); err != nil {
		t.Errorf("ListUsers() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("ListUsers() status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp models.UserListResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp.TotalCount != 1 {
		t.Errorf("ListUsers() totalCount = %d, want 1", resp.TotalCount)
	}
	if len(resp.Users) != 1 {
		t.Errorf("ListUsers() users count = %d, want 1", len(resp.Users))
	}
}

func TestGetUser_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("user-123")
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "disabled", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", "test@example.com", true, false, now, now)
	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectQuery("SELECT data FROM user_misc").WillReturnError(sql.ErrNoRows)

	if err := h.GetUser(c); err != nil {
		t.Errorf("GetUser() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("GetUser() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/nonexistent", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("nonexistent")
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnError(sql.ErrNoRows)

	h.GetUser(c)

	if rec.Code != http.StatusNotFound {
		t.Errorf("GetUser() status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestDeleteUser_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/users/user-123", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("user-123")
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	mock.ExpectExec("DELETE FROM users").WillReturnResult(sqlmock.NewResult(0, 1))

	if err := h.DeleteUser(c); err != nil {
		t.Errorf("DeleteUser() error = %v", err)
	}

	if rec.Code != http.StatusNoContent {
		t.Errorf("DeleteUser() status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/users/nonexistent", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("nonexistent")
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	mock.ExpectExec("DELETE FROM users").WillReturnResult(sqlmock.NewResult(0, 0))

	h.DeleteUser(c)

	if rec.Code != http.StatusNotFound {
		t.Errorf("DeleteUser() status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestUpdateUser_Success(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	email := "new@example.com"
	verified := true
	reqBody := `{"email":"new@example.com","emailVerified":true}`

	req := httptest.NewRequest(http.MethodPut, "/v1/admin/users/user-123", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("user-123")
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectExec("UPDATE users").WillReturnResult(sqlmock.NewResult(0, 1))

	now := time.Now()
	userRows := sqlmock.NewRows([]string{"id", "username", "email", "email_verified", "disabled", "created_at", "updated_at"}).
		AddRow("user-123", "testuser", email, verified, false, now, now)
	mock.ExpectQuery("SELECT id, username, email, email_verified").WillReturnRows(userRows)
	mock.ExpectQuery("SELECT role FROM user_roles").WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("user"))
	mock.ExpectQuery("SELECT data FROM user_misc").WillReturnError(sql.ErrNoRows)

	if err := h.UpdateUser(c); err != nil {
		t.Errorf("UpdateUser() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("UpdateUser() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestUpdateUser_NotFound(t *testing.T) {
	h, mock, e := newTestHandler(t)
	defer h.db.Close()

	reqBody := `{"roles":["admin"]}`

	req := httptest.NewRequest(http.MethodPut, "/v1/admin/users/nonexistent", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("nonexistent")
	c.Set("roles", []models.UserRole{models.RoleAdmin})

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	h.UpdateUser(c)

	if rec.Code != http.StatusNotFound {
		t.Errorf("UpdateUser() status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
