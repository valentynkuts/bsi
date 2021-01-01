//https://www.youtube.com/watch?v=wXB-V_Keiu8
//https://pkg.go.dev/crypto/rsa
//https://pkg.go.dev/crypto/rand

//"RSA encryption and decryption" and "RSA signatures"
//author: Valentyn Kuts

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {

	//--------------------------------------------------------------
	//---- Use the public and private keys -------------------------
	//--------------------------------------------------------------
	fmt.Println("-------- Use the public and private keys-------- ")
	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey
	//SHA256 algorithm
	hash := sha256.New()

	// rand.Reader
	//A random reader used for generating random bits so that the same
	//input doesn’t give the same output twice

	//byte slice
	message := []byte("the code must be like a piece of music")

	//label := []byte("")

	// EncryptOAEP method for encrypting an arbitrary message.
	//OAEP is the recommended standard for the number of bytes
	//added to the original record.
	encryptedBytes, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		&publicKey,
		message,
		nil)

	if err != nil {
		panic(err)
	}

	//print out the encrypted bytes
	fmt.Println("encrypted bytes: ", encryptedBytes)

	// The first argument is an optional random data generator (the rand.Reader we used before)
	// we can set this value as nil
	// The OAEPOptions in the end signify that we encrypted the data using OAEP, and that we used
	// SHA256 to hash the input.
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	fmt.Println("decrypted message: ", string(decryptedBytes))

	//--------------------------------------------------------------
	//---- Signing And Verification --------------------------------
	//--------------------------------------------------------------
	//RSA keys are also used for signing and verification.
	//Signing is different from encryption, in that it enables you
	//to assert authenticity, rather than confidentiality.

	//What this means is that instead of masking the contents of the original
	//message (like what was done in encryption), a piece of data is generated
	//from the message, called the “signature”.

	//Anyone who has the signature, the message, and the public key,
	//can use RSA verification to make sure that the message actually came from
	//the party by whom the public key is issued. If the data or signature don’t match,
	//the verification process fails.

	//Note that only the party with the private key can sign a message,
	//but anyone with the public key can verify it.
	fmt.Println("-------- Signing And Verification -------- ")

	msg := []byte("verifiable message")

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err = rsa.VerifyPSS(&publicKey, crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	fmt.Println("signature verified")

}
