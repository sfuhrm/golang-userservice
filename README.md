# User Service API

[![Build and Deploy](https://github.com/sfuhrm/golang-userservice/actions/workflows/docker.yml/badge.svg)](https://github.com/sfuhrm/golang-userservice/actions/workflows/docker.yml)
[![Coverage](https://raw.githubusercontent.com/sfuhrm/golang-userservice/refs/heads/gh-pages/coverage_badge.svg)](https://sfuhrm.github.io/golang-userservice/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

A RESTful API service for user registration, authentication, and account management built with Go and Echo framework.

## Features

- User registration with email verification flow
- JWT-based authentication with access/refresh token pairs
- Token rotation for security
- Password change with current password verification
- Custom profile data (`misc`) via key-value JSON storage
- User roles (multiple roles per user: user, admin)
- Admin disable/enable user accounts
- Admin endpoints for user management
- Rate limiting on authentication endpoints
- CORS support for web applications
- Database migrations with goose

## Prerequisites

- Go 1.21+
- Docker & Docker Compose (for containerized deployment)
- MySQL/MariaDB (if running locally without Docker)

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start the application and database
docker-compose up -d

# View logs
docker-compose logs -f app
```

The API will be available at `http://localhost:8080`

### Local Development

```bash
# Start MariaDB locally (or use an existing instance)
docker run -d \
  --name userservice-db \
  -e MARIADB_ROOT_PASSWORD=root \
  -e MARIADB_DATABASE=userservice \
  -e MARIADB_USER=userservice \
  -e MARIADB_PASSWORD=userservice \
  mariadb:10.11

# Run the application
go run main.go
```

## Configuration

Configuration is loaded from environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | `8080` | HTTP server port |
| `DB_HOST` | `mariadb` | Database host address |
| `DB_PORT` | `3306` | Database port |
| `DB_USER` | `userservice` | Database username |
| `DB_PASSWORD` | `userservice` | Database password |
| `DB_NAME` | `userservice` | Database name |
| `JWT_SECRET_FILE` | - | Path to file containing JWT secret (for Docker secrets) |
| `JWT_SECRET` | `your-secret-key-change-in-production` | Secret key for signing JWT tokens (fallback) |

### Token Configuration

These are compiled-in defaults and cannot be changed via environment variables:

| Setting | Value | Description |
|---------|-------|-------------|
| JWT Expiry | 15 minutes | Access token lifetime |
| Refresh Token Expiry | 7 days | Refresh token lifetime |
| Standard Rate Limit | 100 requests / 15 min | Per IP address |
| Auth Rate Limit | 5 requests / 15 min | Per IP address (login, register, password-recovery) |

## API Endpoints

### Authentication

| Method | Endpoint | Auth | Rate Limited | Description |
|--------|----------|------|-------------|-------------|
| POST | `/v1/auth/login` | No | Yes (auth) | User login |
| POST | `/v1/auth/refresh` | No | Yes (auth) | Refresh access token |
| POST | `/v1/auth/logout` | Yes | Yes | Invalidate refresh token |
| POST | `/v1/auth/password-recovery` | No | Yes (auth) | Initiate password reset |

### Account Management

| Method | Endpoint | Auth | Rate Limited | Description |
|--------|----------|------|-------------|-------------|
| POST | `/v1/users` | No | Yes (standard) | Register new user |
| GET | `/v1/users/:id` | Yes | Yes (standard) | Get current user profile |
| PUT | `/v1/users/:id` | Yes | Yes (standard) | Update user profile (misc data) |
| PUT | `/v1/users/:id/password` | Yes | Yes (standard) | Change password |
| DELETE | `/v1/users/:id` | Yes | Yes (standard) | Delete account |

### Admin (Requires admin role)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/v1/admin/users` | Yes (admin) | List all users (paginated) |
| GET | `/v1/admin/users/:id` | Yes (admin) | Get user by ID |
| PUT | `/v1/admin/users/:id` | Yes (admin) | Update user |
| DELETE | `/v1/admin/users/:id` | Yes (admin) | Delete user |

## Usage Examples

### Register a New User

```bash
curl -X POST http://localhost:8080/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

### Get Profile

```bash
curl -X GET http://localhost:8080/v1/users/<user_id> \
  -H "Authorization: Bearer <access_token>"
```

Response includes a `misc` field containing custom key-value data:

```json
{
  "id": "uuid-here",
  "username": "john_doe",
  "email": "john@example.com",
  "emailVerified": false,
  "roles": ["user"],
  "misc": {"theme": "dark", "notifications": true},
  "createdAt": "2024-01-01T00:00:00Z",
  "updatedAt": "2024-01-01T00:00:00Z"
}
```

### Update Profile

```bash
curl -X PUT http://localhost:8080/v1/users/<user_id> \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "misc": {
      "theme": "light",
      "language": "en"
    }
  }'
```

The `misc` field is merged with existing data, not replaced. New keys are added, existing keys are updated.

### Change Password

```bash
curl -X PUT http://localhost:8080/v1/users/<user_id>/password \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "oldpassword",
    "newPassword": "newpassword123"
  }'
```

### Refresh Token

```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "<refresh_token>"
  }'
```

### Logout

```bash
curl -X POST http://localhost:8080/v1/auth/logout \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "<refresh_token>"
  }'
```

### Admin Examples (requires admin role)

```bash
# List all users (paginated)
curl -X GET "http://localhost:8080/v1/admin/users?page=1&pageSize=20" \
  -H "Authorization: Bearer <admin_access_token>"

# Get user by ID
curl -X GET http://localhost:8080/v1/admin/users/<user_id> \
  -H "Authorization: Bearer <admin_access_token>"

# Update user (change roles, email, etc.)
curl -X PUT http://localhost:8080/v1/admin/users/<user_id> \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "roles": ["user", "admin"],
    "emailVerified": true
  }'

# Disable user account (user cannot login)
curl -X PUT http://localhost:8080/v1/admin/users/<user_id> \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"disabled": true}'

# Enable user account
curl -X PUT http://localhost:8080/v1/admin/users/<user_id> \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"disabled": false}'

# Delete user
curl -X DELETE http://localhost:8080/v1/admin/users/<user_id> \
  -H "Authorization: Bearer <admin_access_token>"
```

## Project Structure

```
├── main.go              # Entry point, route registration
├── handlers/            # HTTP request handlers
│   └── handlers.go
├── middleware/           # JWT auth, rate limiting
│   └── auth.go
├── models/              # Data models and DTOs
│   └── user.go
├── config/               # Configuration loading
│   └── config.go
├── database/             # Database connection
│   └── database.go
├── migrations/           # Database migrations (goose)
│   └── *.sql
├── docker-compose.yml    # Docker Compose configuration
├── Dockerfile            # Container build
├── openapi.yaml          # OpenAPI specification
└── go.mod / go.sum       # Go module files
```

## Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test -v ./handlers/...
```

## Building

```bash
# Build for local platform
go build -o userservice .

# Build for Linux (Docker)
CGO_ENABLED=0 GOOS=linux go build -o userservice .
```

## Development

### Database Migrations

Migrations run automatically on startup. To manually run migrations:

```bash
# Install goose
go install github.com/pressly/goose/v3/cmd/goose@v3.27.0

# Run migrations
goose mysql "userservice:userservice@tcp(localhost:3306)/userservice?parseTime=true" up
```

### Generate Test Token

For testing, you can generate a JWT token manually:

```go
package main

import (
    "fmt"
    "time"
    "userservice/config"
    "userservice/middleware"
    "userservice/models"
)

func main() {
    cfg := &config.Config{
        JWTSecret: "your-secret-key",
        JWTExpire: 15 * time.Minute,
    }
    token, _ := middleware.GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
    fmt.Println(token)
}
```

## Security Considerations

- Change `JWT_SECRET` in production to a secure random value
- Use HTTPS in production (configure your reverse proxy)
- The password recovery endpoint currently returns 202 Accepted (email sending is a stub)
- Refresh tokens are invalidated server-side on logout and password change
