package middleware

import (
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

var (
	coverageLock   sync.RWMutex
	coveredRoutes  = make(map[string]bool)
	coverageTicker *time.Ticker
	coverageDone   chan bool
)

func init() {
	coveredRoutes = make(map[string]bool)
}

type CoverageTracker struct {
}

func NewCoverageTracker() *CoverageTracker {
	return &CoverageTracker{}
}

func (t *CoverageTracker) Middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			route := c.Path()
			if route != "" && c.Path() != "/debug/coverage" {
				coverageLock.Lock()
				coveredRoutes[route] = true
				coverageLock.Unlock()
			}
			return next(c)
		}
	}
}

func GetCoveredRoutes() map[string]bool {
	coverageLock.RLock()
	defer coverageLock.RUnlock()

	result := make(map[string]bool)
	for k, v := range coveredRoutes {
		result[k] = v
	}
	return result
}

func ResetCoverage() {
	coverageLock.Lock()
	defer coverageLock.Unlock()
	coveredRoutes = make(map[string]bool)
}

func GetAllRoutes() []string {
	return []string{
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
}

func CalculateCoverage() float64 {
	covered := GetCoveredRoutes()
	allRoutes := GetAllRoutes()

	coveredCount := 0
	for _, route := range allRoutes {
		if covered[route] {
			coveredCount++
		}
	}

	return float64(coveredCount) / float64(len(allRoutes)) * 100
}
