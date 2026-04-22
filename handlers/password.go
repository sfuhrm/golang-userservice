package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	argon2Time       uint32 = 3
	argon2MemoryKiB  uint32 = 64 * 1024
	argon2Threads    uint8  = 2
	argon2SaltLength uint32 = 16
	argon2KeyLength  uint32 = 32
)

func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2MemoryKiB, argon2Threads, argon2KeyLength)
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

	return encoded, nil
}

func verifyPasswordHash(storedHash, password string) error {
	if strings.HasPrefix(storedHash, "$argon2id$") {
		ok, err := verifyArgon2idHash(password, storedHash)
		if err != nil || !ok {
			return errors.New("invalid password")
		}
		return nil
	}

	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
}

func verifyArgon2idHash(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid argon2id hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("unsupported argon2id version")
	}

	var memoryKiB, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &iterations, &parallelism); err != nil {
		return false, err
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	if len(hash) == 0 {
		return false, errors.New("invalid argon2id hash length")
	}

	calculated := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, uint32(len(hash)))
	return subtle.ConstantTimeCompare(hash, calculated) == 1, nil
}
