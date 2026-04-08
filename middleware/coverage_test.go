package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestNewCoverageTracker(t *testing.T) {
	tracker := NewCoverageTracker()
	if tracker == nil {
		t.Error("NewCoverageTracker() should return non-nil tracker")
	}
}

func TestCoverageTracker_IgnoresDebugRoute(t *testing.T) {
	ResetCoverage()

	tracker := NewCoverageTracker()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/debug/coverage", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := tracker.Middleware()(func(c echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	handler(c)

	covered := GetCoveredRoutes()
	if covered["/debug/coverage"] {
		t.Error("Debug route should not be marked as covered")
	}
}

func TestResetCoverage(t *testing.T) {
	tracker := NewCoverageTracker()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	c := e.NewContext(req, httptest.NewRecorder())
	tracker.Middleware()(func(c echo.Context) error { return nil })(c)

	ResetCoverage()

	routes := GetCoveredRoutes()
	if len(routes) != 0 {
		t.Errorf("After ResetCoverage() count = %d, want 0", len(routes))
	}
}

func TestGetAllRoutes(t *testing.T) {
	routes := GetAllRoutes()

	expected := []string{
		"/v1/auth/login",
		"/v1/auth/refresh",
		"/v1/auth/logout",
		"/v1/auth/password-recovery",
		"/v1/users",
		"/v1/users/:id/password",
		"/v1/users/:id",
		"/v1/admin/users",
		"/v1/admin/users/:id",
	}

	if len(routes) != len(expected) {
		t.Errorf("GetAllRoutes() count = %d, want %d", len(routes), len(expected))
	}

	for i, r := range expected {
		if routes[i] != r {
			t.Errorf("Route %d = %s, want %s", i, routes[i], r)
		}
	}
}

func TestCalculateCoverage_Zero(t *testing.T) {
	ResetCoverage()

	coverage := CalculateCoverage()

	if coverage != 0 {
		t.Errorf("CalculateCoverage() = %f, want 0", coverage)
	}
}

func TestCalculateCoverage(t *testing.T) {
	ResetCoverage()

	covered := make(map[string]bool)
	routesToCover := []string{
		"/v1/users",
		"/v1/auth/login",
		"/v1/auth/refresh",
	}
	for _, route := range routesToCover {
		covered[route] = true
	}

	setCoveredRoutesForTest(covered)

	coverage := CalculateCoverage()

	expected := float64(3) / float64(9) * 100
	if coverage != expected {
		t.Errorf("CalculateCoverage() = %f, want %f", coverage, expected)
	}
}

func TestCalculateCoverage_Full(t *testing.T) {
	ResetCoverage()

	allRoutes := GetAllRoutes()
	covered := make(map[string]bool)

	for _, route := range allRoutes {
		covered[route] = true
	}

	setCoveredRoutesForTest(covered)

	coverage := CalculateCoverage()

	if coverage != 100 {
		t.Errorf("CalculateCoverage() = %f, want 100", coverage)
	}
}
