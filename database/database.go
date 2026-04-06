// Package database provides database connection and migration functionality.
// It handles connection pooling and uses goose for schema migrations.
package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
	"userservice/config"
)

// Connect establishes a connection to the MariaDB database using the provided configuration.
// It configures connection pooling with appropriate limits for concurrent requests.
// Returns the database connection or an error if connection fails.
func Connect(cfg *config.Config) (*sql.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

// Migrate runs pending database migrations using goose.
// The dir parameter specifies the directory containing migration files.
func Migrate(db *sql.DB, dir string) error {
	if err := goose.SetDialect("mysql"); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	if err := goose.Up(db, dir); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
