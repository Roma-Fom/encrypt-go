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

func VerifySymmetric(data, signature, secret, algorithm string) (bool, error) {
	expectedSig, err := SignSymmetric(data, secret, algorithm)
	if err != nil {
		return false, nil
	}
	return expectedSig == signature, nil
}
