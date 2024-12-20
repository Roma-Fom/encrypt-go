package encrypt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
)

// SignOptions represents the options for signing data
type SignOptions struct {
	Data       string
	PrivateKey string
	Secret     string
	Algorithm  string
}

// VerifyOptions represents the options for verifying data
type VerifyOptions struct {
	Data      string
	Signature string
	PublicKey string
	Secret    string
	Algorithm string
}

// Sign signs the data using the provided options
func Sign(options SignOptions) (string, error) {
	if options.PrivateKey != "" {
		return SignAssymetric(options.Data, options.PrivateKey)
	}
	if options.Secret == "" {
		return "", &EncryptError{
			Message: "No signing method provided",
			Reason:  "Either private key or secret must be provided",
			Code:    "SIGN_ERROR",
		}
	}
	return SignSymmetric(options.Data, options.Secret, options.Algorithm)
}

// Verify verifies the data using the provided options
func Verify(options VerifyOptions) bool {
	if options.PublicKey != "" {
		result, err := VerifyAssymetric(options.Data, options.Signature, options.PublicKey)
		if err != nil {
			return false
		}
		return result
	}
	if options.Secret != "" {
		result, err := VerifySymmetric(options.Data, options.Signature, options.Secret, options.Algorithm)
		if err != nil {
			return false
		}
		return result
	}
	return false
}

// SignAssymetric signs the data using the provided private key
func SignAssymetric(data, privateKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", &EncryptError{
			Message: "Failed to parse private key",
			Reason:  "Invalid PEM format",
			Code:    "SIGN_ASYMMETRIC_ERROR",
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to parse private key",
			Code:    "SIGN_ASYMMETRIC_ERROR",
		}
	}
	hashed := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Signing failed",
			Code:    "SIGN_ASYMMETRIC_ERROR",
		}
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyAssymetric verifies the data using the provided public key
func VerifyAssymetric(data, signature, publicKeyPEM string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, nil
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false, nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, nil
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false, nil
	}

	hashed := sha256.Sum256([]byte(data))

	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], sig)
	return err == nil, nil
}

// SignSymmetric signs the data using the provided secret key
func SignSymmetric(data, secret, algorithm string) (string, error) {
	var h hash.Hash
	switch algorithm {
	case "sha256":
		h = hmac.New(sha256.New, []byte(secret))
	case "sha512":
		h = hmac.New(sha512.New, []byte(secret))
	default:
		return "", &EncryptError{
			Message: "Invalid algorithm",
			Reason:  "Algorithm must be sha256 or sha512",
			Code:    "SIGN_ERROR",
		}
	}

	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// VerifySymmetric verifies the data using the provided secret key
func VerifySymmetric(data, signature, secret, algorithm string) (bool, error) {
	expectedSig, err := SignSymmetric(data, secret, algorithm)
	if err != nil {
		return false, nil
	}
	return expectedSig == signature, nil
}
