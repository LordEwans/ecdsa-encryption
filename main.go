package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
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
	message := []byte("lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?")

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
	fmt.Println("Original message from ciphertext:", string(plaintext))

	// Convert ciphertext to a hexadecimal string
	ciphertextHex := fmt.Sprintf("%x", ciphertext)
	fmt.Printf("Ciphertext hex string length: %d\n", len(ciphertextHex))
	fmt.Printf("Ciphertext as hex string: %s\n", ciphertextHex)

	// Convert hexadecimal string back to []byte
	ciphertextBytes, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}

	// Verify that the converted ciphertext matches the original
	if !bytes.Equal(ciphertext, ciphertextBytes) {
		log.Fatalf("Converted ciphertext doesn't match the original")
	}

	// Decrypt the converted ciphertext to ensure it still works
	convertedPlaintext, err := privateKeyECIES.Decrypt(ciphertextBytes, nil, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt converted ciphertext: %v", err)
	}

	fmt.Println("Decrypted message from converted ciphertext:", string(convertedPlaintext))
}
