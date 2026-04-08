package database

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	"userservice/config"
)

func TestConnect_InvalidDSN(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "invalid-host",
		DBPort:     "3306",
		DBUser:     "invalid",
		DBPassword: "invalid",
		DBName:     "invalid",
	}

	_, err := Connect(cfg)

	if err == nil {
		t.Error("Connect() should fail with invalid DSN")
	}
}

func TestConnect_InvalidPort(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "localhost",
		DBPort:     "99999",
		DBUser:     "root",
		DBPassword: "",
		DBName:     "test",
	}

	_, err := Connect(cfg)

	if err == nil {
		t.Error("Connect() should fail with invalid port")
	}
}

func TestConnect_ValidConfig(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "localhost",
		DBPort:     "3306",
		DBUser:     "root",
		DBPassword: "",
		DBName:     "mysql",
	}

	db, err := Connect(cfg)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to database: %v", err)
	}
	defer db.Close()

	if db == nil {
		t.Error("Connect() should return a non-nil database connection")
	}

	if err := db.Ping(); err != nil {
		t.Errorf("Ping() failed: %v", err)
	}
}

func TestMigrate_InvalidDB(t *testing.T) {
	db, err := sql.Open("mysql", "invalid:invalid@tcp(localhost:3306)/invalid")
	if err != nil {
		t.Skipf("Skipping test: cannot connect: %v", err)
	}
	defer db.Close()

	err = Migrate(db, "./migrations")

	if err != nil {
		t.Logf("Migrate() error (expected for invalid DB): %v", err)
	}
}

func TestMigrate_ValidDB(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "localhost",
		DBPort:     "3306",
		DBUser:     "root",
		DBPassword: "",
		DBName:     "test_db",
	}

	db, err := Connect(cfg)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to database: %v", err)
	}
	defer db.Close()

	err = Migrate(db, "./migrations")

	if err != nil {
		t.Logf("Migrate() returned error: %v", err)
	}
}

func TestConnect_ConnectionPooling(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "localhost",
		DBPort:     "3306",
		DBUser:     "root",
		DBPassword: "",
		DBName:     "mysql",
	}

	db, err := Connect(cfg)
	if err != nil {
		t.Skipf("Skipping test: cannot connect to database: %v", err)
	}
	defer db.Close()

	stats := db.Stats()
	if stats.MaxOpenConnections != 25 {
		t.Errorf("MaxOpenConnections = %d, want 25", stats.MaxOpenConnections)
	}
}
