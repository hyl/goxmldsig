// xenc is custom XML encryption functionality for vendor-specific xmlenc creation.
package xenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
)

// ParseCertificateBytes takes a []byte and converts it into an X509 certificate and an RSA public key.
func ParseCertificateBytes(keyBytes []byte) (*x509.Certificate, *rsa.PublicKey, error) {
	var err error
	block, rest := pem.Decode(keyBytes)

	fmt.Printf("\nblock: %v\n", block)
	fmt.Printf("\nrest: %v\n", rest)

	var blockBytes []byte
	if block != nil {
		blockBytes = block.Bytes
	} else {
		// already a certificate (we hope)
		blockBytes = keyBytes
	}

	// parse our public key
	cert, err := x509.ParseCertificate(blockBytes)

	if err != nil {
		return nil, nil, err
	}

	publicKey := cert.PublicKey.(*rsa.PublicKey)

	return cert, publicKey, nil
}

// GenerateEncryptedSymmetricKey returns an encrypted key for payload encryption.
func GenerateEncryptedSymmetricKey(publicKey *rsa.PublicKey) ([]byte, []byte, error) {
	symmetricKey := make([]byte, 32)
	_, err := rand.Read(symmetricKey)
	if err != nil {
		// handle error here
		return nil, nil, err
	}

	hash := sha1.New()
	random := rand.Reader

	encryptedKey, err := rsa.EncryptOAEP(hash, random, publicKey, symmetricKey, nil)
	if err != nil {
		// handle error here
		return nil, nil, err
	}

	return symmetricKey, encryptedKey, nil
}

// EncryptAssertion encrypts our signed assertion using the provided AES-256 symmetric key.
func EncryptAssertion(signedAssertion string, aesKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Printf("failed to create cipher block: %v", err)
		os.Exit(1)
	}

	// init GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("failed to initialise Galois/Counter Mode: %v", err)
		os.Exit(1)
	}

	// create a nonce from the GCM
	nonce := make([]byte, aesGCM.NonceSize())
	
	// populate our nonce
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// encrypt our data
	encryptedAssertion := aesGCM.Seal(nonce, nonce, []byte(signedAssertion), nil)

	return encryptedAssertion, nil
}
