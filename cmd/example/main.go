package main

import (
	"fmt"

	"github.com/roma-fom/encrypt-go/pkg/encrypt"
)

type Metadata struct {
	Id        string `json:"id"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	DeletedAt string `json:"deletedAt"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	UserId    string `json:"userId"`
	OrgId     string `json:"orgId"`
	TenantId  string `json:"tenantId"`
	IsDeleted bool   `json:"isDeleted"`
}

type User struct {
	Name     string   `json:"name"`
	LastName string   `json:"lastName"`
	Age      int      `json:"age"`
	Email    string   `json:"email"`
	Metadata Metadata `json:"metadata"`
}

func main() {
	userData := User{
		Name:     "John",
		LastName: "Doe",
		Age:      30,
		Email:    "john.doe@example.com",
		Metadata: Metadata{
			Id:        "123",
			CreatedAt: "2024-01-02",
			UpdatedAt: "2023-01-04",
			DeletedAt: "2022-01-05",
			Version:   "1.0.0",
			Status:    "active",
			UserId:    "123",
			OrgId:     "123",
			TenantId:  "123",
			IsDeleted: false,
		},
	}
	rsaKeyPair, _ := encrypt.GenerateRSAKeyPair()
	canonical, err := encrypt.CanonicalJSON(userData)
	if err != nil {
		fmt.Printf("Error canonicalizing JSON: %v\n", err)
		return
	}

	signature, err := encrypt.Sign(encrypt.SignOptions{
		Data:       canonical,
		PrivateKey: rsaKeyPair.PrivateKey,
	})
	if err != nil {
		fmt.Printf("Error signing data: %v\n", err)
		return
	}
	fmt.Printf("Signature: %s\n", signature)

	valid := encrypt.Verify(encrypt.VerifyOptions{
		Data:      canonical,
		Signature: signature,
		PublicKey: rsaKeyPair.PublicKey,
	})
	fmt.Printf("Valid: %t\n", valid)
}
