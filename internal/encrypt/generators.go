package encrypt

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateSecretKey(length int) (string, error) {
	if length != 16 && length != 32 {
		return "", &EncryptError{
			Message: "Invalid key length",
			Reason:  "Key length must be 16 or 32",
			Code:    ErrorCodeInvalidKey,
		}
	}

	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to generate random key",
			Code:    ErrorCodeInvalidKey,
		}
	}

	return hex.EncodeToString(key), nil
}
