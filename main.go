// Package main provides the entry point for the User Service API.
// It initializes the database connection, sets up middleware, and registers routes.
package main

import (
	"log"

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
		AllowOrigins: []string{"https://*.example.com"},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))

	standardLimiter := middleware.NewRateLimiter(cfg.RateLimit, cfg.RateLimitWindow)
	authLimiter := middleware.NewRateLimiter(cfg.AuthRateLimit, cfg.RateLimitWindow)

	e.Use(standardLimiter.Middleware())

	h := handlers.New(db, cfg)

	api := e.Group("/v1")

	apiAuth := api.Group("/auth")
	apiAuth.POST("/login", h.Login, authLimiter.Middleware())
	apiAuth.POST("/refresh", h.Refresh, authLimiter.Middleware())
	apiAuth.POST("/logout", h.Logout, middleware.JWTAuth(cfg))
	apiAuth.POST("/password-recovery", h.PasswordRecovery, authLimiter.Middleware())

	api.POST("/users", h.Register)
	api.PUT("/users/me/password", h.ChangePassword, middleware.JWTAuth(cfg))
	api.GET("/users/me", h.GetProfile, middleware.JWTAuth(cfg))
	api.PUT("/users/me", h.UpdateProfile, middleware.JWTAuth(cfg))
	api.DELETE("/users/me", h.DeleteAccount, middleware.JWTAuth(cfg))

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
