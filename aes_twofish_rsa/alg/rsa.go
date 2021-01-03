package alg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

type Rsa struct {
	Plaintext  string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

}
func (r Rsa) GenerateKey() {
	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	saveGobKey("rsa_keys/private.key", privateKey)
	savePEMKey("rsa_keys/private.pem", privateKey)

	//fmt.Println("PRIVATE: ",privateKey)

	// The public key is a part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey

	saveGobKey("rsa_keys/public.key", publicKey)
	savePublicPEMKey("rsa_keys/public.pem", publicKey)

	//fmt.Println("PUBLIC: ", publicKey)

}

//encrypts the text and save it in the file
func (r Rsa) EncryptionRsa(publicKey *rsa.PublicKey){
	//SHA256 algorithm
	hash := sha256.New()

	// rand.Reader
	//A random reader used for generating random bits so that the same
	//input doesn’t give the same output twice

	//byte slice
	message := []byte(r.Plaintext)

	//label := []byte("")

	// EncryptOAEP method for encrypting an arbitrary message.
	//OAEP is the recommended standard for the number of bytes
	//added to the original record.
	//publicKey := r.publicKey  //todo delete
	encryptedBytes, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		publicKey,
		message,
		nil)

	if err != nil {
		panic(err)
	}

	//print out the encrypted bytes
	fmt.Println("encrypted bytes: ", encryptedBytes)

	// the WriteFile method returns an error if unsuccessful
	err = ioutil.WriteFile("rsa_data/myfile.data", encryptedBytes, 0777)
	// handle this error
	if err != nil {
		// print it out
		fmt.Println(err)
	}

}

//read the file and decrypts the information from the file
//return decrypted text
func (r Rsa) DecryptionRsa(privateKey *rsa.PrivateKey) string{

	encryptedBytes, err := ioutil.ReadFile("rsa_data/myfile.data")
	// if our program was unable to read the file
	// print out the reason why it can't

	if err != nil {
		panic(err)
	}

	// The first argument is an optional random data generator (the rand.Reader we used before)
	// we can set this value as nil
	// The OAEPOptions in the end signify that we encrypted the data using OAEP, and that we used
	// SHA256 to hash the input.
	////privateKey := r.privateKey //todo delete
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}

	// We get back the original information in the form of bytes, which we
	// the cast to a string and print
	decryptedText := string(decryptedBytes)
	fmt.Println("decrypted message: ", decryptedText)

    return decryptedText
}

//If you are sending data from a Go program to another Go one
//(as you show in your examples), you can use the package encoding/gob
//https://golang.org/pkg/encoding/gob/ to serialize (Encode) an object
//into a slice of bytes and deserialize (Decode) the received bytes back
//into the Go object.

func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	checkError(err)
}

//Privacy-Enhanced Mail (PEM) is a de facto file format for storing and sending
//cryptographic keys, certificates, and other data

//Package x509 parses X.509-encoded keys and certificates.
func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}
//Abstract Syntax Notation One (asn1)
//It builds self-describing serialised data from complex data structures.
func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

//get public key from file
func (r Rsa) GetPublicKey() *rsa.PublicKey {
	pemStringPub, err := ioutil.ReadFile("rsa_keys/public.pem")
	if err != nil {
		panic(err)
	}
	blockPub, _ := pem.Decode([]byte(pemStringPub))
	publicKey, _ := x509.ParsePKCS1PublicKey (blockPub.Bytes)
	r.publicKey = publicKey
	//fmt.Println("After file PUBLIC: ",publicKey)
	return publicKey
}
//get private key from file
func (r Rsa) GetPrivateKey() *rsa.PrivateKey {
	pemString, err := ioutil.ReadFile("rsa_keys/private.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode([]byte(pemString))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	//fmt.Println("After file PRIVATE: ",privateKey)
	r.privateKey = privateKey
	return privateKey
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
