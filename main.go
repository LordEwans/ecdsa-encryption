package main

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
	message := []byte("{\"name\":\"John\", \"age\":30, \"city\":\"New York\", \"more\":{\"name\":\"John\", \"age\":30, \"city\":\"New York\"}, \"array\":[1,2,3,4,5,6,7,8,9,10]}")

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
	// Compress the ciphertext using zlib
	var compressedCiphertext bytes.Buffer
	zlibWriter := zlib.NewWriter(&compressedCiphertext)
	_, err = zlibWriter.Write(ciphertext)
	if err != nil {
		log.Fatalf("Failed to compress ciphertext: %v", err)
	}
	zlibWriter.Close()

	// Convert compressed ciphertext to a base64 string
	compressedCiphertextBase64 := base64.StdEncoding.EncodeToString(compressedCiphertext.Bytes())
	fmt.Printf("Compressed ciphertext base64 string length: %d\n", len(compressedCiphertextBase64))
	fmt.Printf("Compressed ciphertext as base64 string: %s\n", compressedCiphertextBase64)

	// Demonstrate decompression and decryption
	decodedCompressedCiphertext, err := base64.StdEncoding.DecodeString(compressedCiphertextBase64)
	if err != nil {
		log.Fatalf("Failed to decode base64 string: %v", err)
	}

	zlibReader, err := zlib.NewReader(bytes.NewReader(decodedCompressedCiphertext))
	if err != nil {
		log.Fatalf("Failed to create zlib reader: %v", err)
	}
	decompressedCiphertext, err := io.ReadAll(zlibReader)
	zlibReader.Close()
	if err != nil {
		log.Fatalf("Failed to decompress ciphertext: %v", err)
	}

	decompressedPlaintext, err := privateKeyECIES.Decrypt(decompressedCiphertext, nil, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt decompressed ciphertext: %v", err)
	}

	fmt.Println("Decrypted message from decompressed ciphertext:", string(decompressedPlaintext))

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
