// Package main provides the entry point for the User Service API.
// It initializes the database connection, sets up middleware, and registers routes.
package main

import (
	"log"
	"net/http"

	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"userservice/config"
	"userservice/database"
	"userservice/handlers"
	"userservice/middleware"
	"userservice/models"
)

// main is the application entry point that initializes and starts the HTTP server.
// It performs the following steps:
//   - Loads configuration from environment variables
//   - Establishes a connection to the MariaDB database
//   - Runs database migrations using goose
//   - Configures Echo framework with middleware (CORS, rate limiting)
//   - Registers API routes for user and authentication endpoints
//   - Starts the HTTP server on the configured port
func main() {
	cfg := config.Load()

	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := database.Migrate(db, "migrations"); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	e := echo.New()

	e.Use(echomiddleware.Logger())
	e.Use(echomiddleware.Recover())
	e.Use(echomiddleware.CORSWithConfig(echomiddleware.CORSConfig{
		AllowOrigins: []string{
			"https://*.example.com",
			"http://localhost:8081",
			"http://127.0.0.1:8081",
		},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	standardLimiter := middleware.NewRateLimiter(cfg.RateLimit, cfg.RateLimitWindow)
	authLimiter := middleware.NewRateLimiter(cfg.AuthRateLimit, cfg.RateLimitWindow)
	refreshLimiter := middleware.NewRateLimiter(cfg.RefreshRateLimit, cfg.RateLimitWindow)

	e.Use(standardLimiter.Middleware())

	coverageTracker := middleware.NewCoverageTracker()
	e.Use(coverageTracker.Middleware())

	h := handlers.New(db, cfg)

	e.GET("/q/health/live", h.Live)

	e.GET("/debug/coverage", func(c echo.Context) error {
		coverage := middleware.CalculateCoverage()
		coveredRoutes := middleware.GetCoveredRoutes()
		allRoutes := middleware.GetAllRoutes()
		return c.JSON(http.StatusOK, map[string]interface{}{
			"coverage":       coverage,
			"covered_routes": coveredRoutes,
			"total_routes":   allRoutes,
		})
	})

	api := e.Group("/v1")

	apiAuth := api.Group("/auth")
	apiAuth.POST("/login", h.Login, authLimiter.Middleware())
	apiAuth.POST("/refresh", h.Refresh, refreshLimiter.Middleware())
	apiAuth.POST("/logout", h.Logout, middleware.JWTAuth(cfg))
	apiAuth.POST("/password-recovery", h.PasswordRecovery, authLimiter.Middleware())
	apiAuth.POST("/verify-registration", h.VerifyRegistration)
	apiAuth.POST("/reset-password", h.ResetPassword)

	api.POST("/users", h.Register)
	api.PUT("/users/:id/password", h.ChangePassword, middleware.JWTAuth(cfg))
	api.GET("/users/:id", h.GetProfile, middleware.JWTAuth(cfg))
	api.PUT("/users/:id", h.UpdateProfile, middleware.JWTAuth(cfg))
	api.DELETE("/users/:id", h.DeleteAccount, middleware.JWTAuth(cfg))

	apiAdmin := api.Group("/admin")
	apiAdmin.Use(middleware.JWTAuth(cfg))
	apiAdmin.Use(middleware.RequireRole(models.RoleAdmin))
	apiAdmin.GET("/users", h.ListUsers)
	apiAdmin.GET("/users/:id", h.GetUser)
	apiAdmin.PUT("/users/:id", h.UpdateUser)
	apiAdmin.DELETE("/users/:id", h.DeleteUser)

	log.Printf("Server starting on port %s", cfg.ServerPort)
	if err := e.Start(":" + cfg.ServerPort); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
