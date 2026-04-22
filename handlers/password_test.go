package handlers

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword_UsesArgon2id(t *testing.T) {
	hash, err := hashPassword("password123")
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hashPassword() should return argon2id hash, got %q", hash)
	}

	if err := verifyPasswordHash(hash, "password123"); err != nil {
		t.Fatalf("verifyPasswordHash() failed for generated argon2id hash: %v", err)
	}
}

func TestVerifyPasswordHash_SupportsBcrypt(t *testing.T) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}

	if err := verifyPasswordHash(string(bcryptHash), "password123"); err != nil {
		t.Fatalf("verifyPasswordHash() should support bcrypt hashes: %v", err)
	}
}

func TestVerifyPasswordHash_RejectsWrongPassword(t *testing.T) {
	argon2Hash, err := hashPassword("password123")
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}

	if err := verifyPasswordHash(argon2Hash, "wrong-password"); err == nil {
		t.Fatal("verifyPasswordHash() should fail for wrong password against argon2id hash")
	}

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}

	if err := verifyPasswordHash(string(bcryptHash), "wrong-password"); err == nil {
		t.Fatal("verifyPasswordHash() should fail for wrong password against bcrypt hash")
	}
}

func TestVerifyPasswordHash_RejectsUnexpectedArgon2idHashLength(t *testing.T) {
	salt := make([]byte, argon2SaltLength)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	invalidKeyLen := uint32(16)
	hash := argon2.IDKey([]byte("password123"), salt, argon2Time, argon2MemoryKiB, argon2Threads, invalidKeyLen)
	b64 := base64.RawStdEncoding

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2MemoryKiB,
		argon2Time,
		argon2Threads,
		b64.EncodeToString(salt),
		b64.EncodeToString(hash),
	)

	if err := verifyPasswordHash(encoded, "password123"); err == nil {
		t.Fatal("verifyPasswordHash() should fail for argon2id hash with unsupported key length")
	}
}
