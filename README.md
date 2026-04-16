# User Service API

[![Build and Deploy](https://github.com/sfuhrm/golang-userservice/actions/workflows/docker.yml/badge.svg)](https://github.com/sfuhrm/golang-userservice/actions/workflows/docker.yml)
[![Coverage](https://raw.githubusercontent.com/sfuhrm/golang-userservice/refs/heads/gh-pages/coverage_badge.svg)](https://sfuhrm.github.io/golang-userservice/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

A RESTful API service for user registration, authentication, and account management built with Go and Echo framework.

## Status

:warning: Experimental status! Features / API may change. Use with caution.

## Features

- User registration with email verification via external mail service
- Password recovery via external mail service
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
- Small memory footprint of around 10 MB

## Prerequisites

- Go 1.26+
- Docker & Docker Compose (for containerized deployment)
- MySQL/MariaDB (if running locally without Docker)

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start the application and database
docker compose up -d

# View logs
docker compose logs -f app
```

The API will be available at `http://localhost:8080`
Swagger UI will be available at `http://localhost:8081`

The compose setup is preconfigured for `JWT_ALGORITHM=RS256` and reads key files from:
- `./secrets/jwt_private.pem`
- `./secrets/jwt_public.pem`

### Local Development

```bash
# Start MariaDB locally (or use an existing instance)
docker run -d \
  --name userservice-db \
  -p 3306:3306 \
  -e MARIADB_ROOT_PASSWORD=root \
  -e MARIADB_DATABASE=userservice \
  -e MARIADB_USER=userservice \
  -e MARIADB_PASSWORD=userservice \
  mariadb:10.11

# Run the application against local MariaDB
DB_HOST=127.0.0.1 \
DB_PORT=3306 \
DB_USER=userservice \
DB_PASSWORD=userservice \
DB_NAME=userservice \
JWT_ALGORITHM=RS256 \
JWT_PRIVATE_KEY_FILE=./secrets/jwt_private.pem \
JWT_PUBLIC_KEY_FILE=./secrets/jwt_public.pem \
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
| `DB_PASSWORD_FILE` | - | Path to file containing database password (for Docker secrets) |
| `DB_PASSWORD` | `userservice` | Database password |
| `DB_NAME` | `userservice` | Database name |
| `JWT_ALGORITHM` | `HS256` | Access token signing algorithm (`HS256`, `RS256`, or `ES256`) |
| `JWT_SECRET_FILE` | - | Path to file containing JWT secret (HS256) |
| `JWT_SECRET` | `your-secret-key-change-in-production` | Secret key for HS256 signing (fallback) |
| `JWT_PRIVATE_KEY_FILE` | - | Path to private key PEM file (`RS256`/`ES256` signing) |
| `JWT_PRIVATE_KEY` | - | Private key PEM (`RS256`/`ES256` signing) |
| `JWT_PUBLIC_KEY_FILE` | - | Path to public key PEM file (`RS256`/`ES256` verification) |
| `JWT_PUBLIC_KEY` | - | Public key PEM (`RS256`/`ES256` verification; optional when private key is provided) |
| `JWT_ISSUER` | - | Optional JWT issuer claim (`iss`) for access tokens. When set, incoming access tokens must match this issuer. |
| `JWT_AUDIENCE` | - | Optional JWT audience claim (`aud`) for access tokens. When set, incoming access tokens must include this audience. |
| `JWT_EXPIRE` | `15m` | Access token lifetime (Go duration, e.g. `5m`, `30m`, `1h`) |
| `REFRESH_EXPIRE` | `168h` | Refresh token lifetime (Go duration, e.g. `24h`, `168h`) |
| `RATE_LIMIT` | `100` | Standard rate limit requests per window (per IP) |
| `AUTH_RATE_LIMIT` | `5` | Auth endpoint rate limit requests per window (per IP) |
| `REFRESH_RATE_LIMIT` | `30` | Refresh endpoint rate limit requests per window (per IP) |
| `RATE_LIMIT_WINDOW` | `15m` | Rate-limit window duration (Go duration, e.g. `1m`, `15m`, `1h`) |
| `ENABLE_DEBUG_COVERAGE` | `false` | Enables `/debug/coverage` endpoint and route coverage tracking middleware (for testing only) |

### External Mail Service Configuration (Optional)

When configured, the service integrates with external mail services for sending verification and recovery emails.

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRATION_MAIL_URL` | - | External URL for sending registration verification emails. If not set, users are created directly without email verification. |
| `REGISTRATION_MAIL_CALLBACK_URL` | - | Callback URL for registration verification (included in mail request) |
| `RECOVERY_MAIL_URL` | - | External URL for sending password recovery emails. If not set, returns HTTP 501. |
| `RECOVERY_MAIL_CALLBACK_URL` | - | Callback URL for password recovery verification (included in mail request) |

### Token and Rate Limit Configuration

Token expiry and rate limits are configurable via environment variables.

| Setting | Value | Description |
|---------|-------|-------------|
| JWT Expiry (default) | 15 minutes | Access token lifetime (`JWT_EXPIRE`) |
| Refresh Token Expiry (default) | 7 days | Refresh token lifetime (`REFRESH_EXPIRE`) |
| Standard Rate Limit (default) | 100 requests / 15 min | Per IP address |
| Auth Rate Limit (default) | 5 requests / 15 min | Per IP address (login, password-recovery) |
| Refresh Rate Limit (default) | 30 requests / 15 min | Per IP address (`/v1/auth/refresh`) |

### JWT Access Token Components

The `accessToken` returned by `/v1/auth/login` and `/v1/auth/refresh` is a JWT with this format:

`<base64url(header)>.<base64url(payload)>.<base64url(signature)>`

JWT content is signed, not encrypted. Anyone who has the token can decode header/payload, but cannot forge a valid signature without the server signing key.

**1) Header**

The header defines how the token is signed:

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

- `alg`: Signing algorithm from `JWT_ALGORITHM` (`HS256`, `RS256`, or `ES256`)
- `typ`: Token type (`JWT`)

**2) Payload (claims)**

The payload contains user identity and authorization data used by middleware:

```json
{
  "aud": "userservice-api",
  "iss": "userservice",
  "jti": "12345",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "roles": ["user", "admin"],
  "iat": 1712831400,
  "exp": 1712832300
}
```

- `aud`: Optional audience claim (included when `JWT_AUDIENCE` is configured)
- `iss`: Optional issuer claim (included when `JWT_ISSUER` is configured)
- `jti`: Unique token ID (JWT ID claim). Generated per token from MariaDB sequence `jwt_jti_seq`.
- `sub`: User UUID used to identify the authenticated user (JWT subject claim)
- `roles`: User roles used for authorization checks (`user`, `admin`)
- `iat`: Issued-at timestamp (Unix seconds)
- `exp`: Expiration timestamp (Unix seconds, default +15 minutes)

**3) Signature**

The signature protects integrity:

- For `HS256`: `HMACSHA256(base64url(header) + "." + base64url(payload), JWT_SECRET)`
- For `RS256`: `RSASSA-PKCS1-v1_5-SHA256(base64url(header) + "." + base64url(payload), JWT_PRIVATE_KEY)`
- For `ES256`: `ECDSA-P256-SHA256(base64url(header) + "." + base64url(payload), JWT_PRIVATE_KEY)`

If header or payload is modified, signature validation fails and the API returns `401`.

**Refresh Token Note**

`refreshToken` is not a JWT in this service. It is an opaque UUID value stored server-side in `refresh_tokens` and rotated on every successful `/v1/auth/refresh`.

## API Endpoints

### Authentication

| Method | Endpoint | Auth | Rate Limited | Description |
|--------|----------|------|-------------|-------------|
| POST | `/v1/auth/login` | No | Yes (auth) | User login |
| POST | `/v1/auth/refresh` | No | Yes (refresh) | Refresh access token |
| POST | `/v1/auth/logout` | Yes | Yes | Invalidate refresh token |
| POST | `/v1/auth/password-recovery` | No | Yes (auth) | Initiate password reset (requires mail service) |
| POST | `/v1/auth/verify-registration` | No | No | Verify email registration |
| POST | `/v1/auth/reset-password` | No | No | Reset password with recovery token |

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

### Verify Email Registration

```bash
curl -X POST http://localhost:8080/v1/auth/verify-registration \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<verification_token_from_email>"
  }'
```

### Reset Password

```bash
curl -X POST http://localhost:8080/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<recovery_token_from_email>",
    "newPassword": "newSecurePassword123"
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
        JWTAlgorithm:  "RS256",
        JWTPrivateKey: "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
        JWTPublicKey:  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        JWTExpire:     15 * time.Minute,
    }
    token, _ := middleware.GenerateAccessToken("user-123", []models.UserRole{models.RoleUser}, cfg)
    fmt.Println(token)
}
```

## Security Considerations

- Prefer asymmetric JWT algorithms (`RS256` or `ES256`) in production
- Protect `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_FILE` as a secret
- Rotate JWT keys regularly
- If you use HS256, set `JWT_SECRET` to a secure random value
- Use HTTPS in production (configure your reverse proxy)
- Configure external mail service URLs for production use (see environment variables)
- Refresh tokens are invalidated server-side on logout and password change
- All refresh tokens are invalidated after password reset
- Verification tokens expire after 24 hours (registration) or 1 hour (recovery)
