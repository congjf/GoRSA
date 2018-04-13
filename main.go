package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func main() {
	bits := 1024

	GenRSAPrivateKey(bits)
}

// GenRSAPrivateKey use to generate RSA Key Pair
func GenRSAPrivateKey(bits int) error {

	// Generate the raw RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	// Convert the raw private key to a ASN.1 DER encoded form
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create a new PEM object with derStream
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}

	// Create a file object for save the PEM object
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}

	// Encode the PEM object to the file created before
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	// Get the raw public key of the private key created before
	publicKey := &privateKey.PublicKey

	// Convert the raw public key to a PXIX encoded form
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	// Create a new PEM object with derStream
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	// Create a file object for save the PEM object of public key
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}

	// Encode the PEM object to the file created before
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}
