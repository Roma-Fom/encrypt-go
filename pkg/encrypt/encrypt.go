package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// EncryptResult represents the result of encryption
type EncryptResult struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
}

// Hash hashes the input data using the specified algorithm
func Hash(input string, algorithm string) (string, error) {
	var hash []byte

	switch algorithm {
	case "sha256":
		h := sha256.New()
		h.Write([]byte(input))
		hash = h.Sum(nil)
	case "sha512":
		h := sha512.New()
		h.Write([]byte(input))
		hash = h.Sum(nil)
	default:
		return "", &EncryptError{
			Message: "Invalid algorithm",
			Reason:  "Hash failed",
			Code:    ErrorCodeHash,
		}
	}

	return hex.EncodeToString(hash), nil
}

// Encrypt encrypts the plaintext using the provided secret key
func Encrypt(plaintext, secretKey string) (*EncryptResult, error) {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return nil, &EncryptError{
			Message: err.Error(),
			Reason:  "Invalid secret key format",
			Code:    ErrorCodeEncrypt,
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to create cipher",
			Code:    ErrorCodeEncrypt,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to create GCM",
			Code:    ErrorCodeEncrypt,
		}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to generate nonce",
			Code:    ErrorCodeEncrypt,
		}
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	return &EncryptResult{
		Ciphertext: hex.EncodeToString(ciphertext),
		IV:         hex.EncodeToString(nonce),
	}, nil
}

// Decrypt decrypts the ciphertext using the provided secret key and IV
func Decrypt(ciphertext, secretKey, iv string) (string, error) {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Invalid secret key format",
			Code:    ErrorCodeEncrypt,
		}
	}

	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Invalid ciphertext format",
			Code:    ErrorCodeDecrypt,
		}
	}

	nonce, err := hex.DecodeString(iv)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Invalid IV format",
			Code:    ErrorCodeDecrypt,
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to create cipher",
			Code:    ErrorCodeDecrypt,
		}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to create GCM",
			Code:    ErrorCodeDecrypt,
		}
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Decryption failed",
			Code:    ErrorCodeDecrypt,
		}
	}

	return string(plaintext), nil

}
