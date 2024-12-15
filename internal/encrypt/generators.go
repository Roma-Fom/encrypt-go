package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

type RSAKeyPair struct {
	PrivateKey string
	PublicKey  string
}

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

func GenerateRSAKeyPair() (*RSAKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, &EncryptError{
			Message: err.Error(),
			Reason:  "Key pair generation failed",
			Code:    "KEYPAIR_ERROR",
		}
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, &EncryptError{
			Message: err.Error(),
			Reason:  "Public key encoding failed",
			Code:    "KEYPAIR_ERROR",
		}
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &RSAKeyPair{
		PrivateKey: string(privateKeyPEM),
		PublicKey:  string(publicKeyPEM),
	}, nil
}

func GenerateNanoID(prefix string, size int) (string, error) {
	if size < 21 {
		size = 21
	}
	id, err := gonanoid.New(size)
	if err != nil {
		return "", &EncryptError{
			Message: err.Error(),
			Reason:  "Failed to generate NanoID",
			Code:    ErrorCodeNanoID,
		}
	}
	if prefix != "" {
		return prefix + "_" + id, nil
	}
	return id, nil
}
