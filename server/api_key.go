package server

import (
	"crypto/sha256"
	"crypto/subtle"
)

type ApiKey []byte

// Creates an ApiKey that is later used to validate against client supplied keys.
func NewApiKey(key string) ApiKey {
	h := sha256.Sum256([]byte(key))
	return ApiKey(h[:])
}

// Validates that the supplied key matches the expected one.
func (k ApiKey) Validate(key string) bool {
	return subtle.ConstantTimeCompare(NewApiKey(key), k) == 1
}
