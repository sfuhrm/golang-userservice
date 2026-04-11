package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
	"userservice/config"
)

func TestLive_UP(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	h := New(db, &config.Config{})
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/q/health/live", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectPing()

	if err := h.Live(c); err != nil {
		t.Fatalf("Live() returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Live() status = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != "UP" {
		t.Fatalf("Live() body = %q, want %q", rec.Body.String(), "UP")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestLive_DOWN(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	h := New(db, &config.Config{})
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/q/health/live", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	mock.ExpectPing().WillReturnError(errors.New("db unavailable"))

	if err := h.Live(c); err != nil {
		t.Fatalf("Live() returned error: %v", err)
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Live() status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	if rec.Body.String() != "DOWN" {
		t.Fatalf("Live() body = %q, want %q", rec.Body.String(), "DOWN")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}
