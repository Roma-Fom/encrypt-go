package main

import (
	"fmt"
	"log"

	"github.com/roma-fom/encrypt-tools/internal/encrypt"
)

func main() {
	secretKey, err := encrypt.GenerateSecretKey(16)
	if err != nil {
		log.Fatalf("Error generating secret key: %v", err)
	}

	plaintext := "Hello, World!"
	encrypted, err := encrypt.Encrypt(plaintext, secretKey)
	if err != nil {
		log.Fatalf("Error encrypting: %v", err)
	}

	fmt.Printf("Generated Secret Key: %s\n", secretKey)
	fmt.Printf("Encrypted: %s\n", encrypted.Ciphertext)
	fmt.Printf("IV: %s\n", encrypted.IV)
}
