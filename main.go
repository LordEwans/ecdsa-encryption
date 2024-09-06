package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func main() {
	// First, we'll generate a new ECDSA private key
	privateKeyECDSA, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Oops! Something went wrong generating the private key: %v", err)
	}

	// Now, let's get the public key from the private key
	publicKeyECDSA := privateKeyECDSA.Public()

	// We'll try encrypting and decrypting a simple message: "hello, world!"
	message := []byte("hello, world!")

	// Now, let's encrypt the message with our public key
	publicKeyECIES := ecies.ImportECDSAPublic(publicKeyECDSA.(*ecdsa.PublicKey))
	ciphertext, err := ecies.Encrypt(rand.Reader, publicKeyECIES, message, nil, nil)
	if err != nil {
		log.Fatalf("Oh no! The encryption didn't work: %v", err)
	}

	// Finally, let's decrypt the message with our private key
	privateKeyECIES := ecies.ImportECDSA(privateKeyECDSA)
	plaintext, err := privateKeyECIES.Decrypt(ciphertext, nil, nil)
	if err != nil {
		log.Fatalf("Yikes! We ran into an issue decrypting the message: %v", err)
	}

	// If everything went smoothly, this will print: hello, world!
	fmt.Println(string(plaintext), " from ", ciphertext, " as ", string(ciphertext))
}
