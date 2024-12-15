package encrypt

import "fmt"

// EncryptError represents an error that occurred during encryption or decryption
type EncryptError struct {
	Message string
	Reason  string
	Code    string
}

// Error returns the error message
func (e *EncryptError) Error() string {
	return fmt.Sprintf("%s: %s (code: %s)", e.Message, e.Reason, e.Code)
}

const (
	ErrorCodeEncrypt    = "ENCRYPT_ERROR"
	ErrorCodeDecrypt    = "DECRYPT_ERROR"
	ErrorCodeHash       = "HASH_ERROR"
	ErrorCodeInvalidKey = "INVALID_KEY_LENGTH"
	ErrorCodeNanoID     = "NANOID_ERROR"
)
