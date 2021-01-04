package alg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
)

type Aes struct {
	Plaintext string
	Key       string

}

//encrypts the text and save it in the file
func (a Aes) Encryption(){

	key := []byte(a.Key)
	text := []byte(a.Plaintext)

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//GSM provides authenticated encryption
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	//nonce - piece of data should not be repeated
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	fmt.Println(gcm.Seal(nonce, nonce, text, nil))

	// the WriteFile method returns an error if unsuccessful
	err = ioutil.WriteFile("aes_data/myfile.data", gcm.Seal(nonce, nonce, text, nil), 0777)
	// handle this error
	if err != nil {
		// print it out
		fmt.Println(err)
	}

}

//read the file and decrypts the information from the file
//return decrypted text
func (a Aes) Decryption() string{
	key := []byte(a.Key)
	ciphertext, err := ioutil.ReadFile("aes_data/myfile.data")
	// if our program was unable to read the file
	// print out the reason why it can't

	/*if err != nil {
		fmt.Println(err)
	}*/

	checkerror(err)

	//Create the new Cipher using an aes.NewCipher() function,
	//passing in our shared key as it’s a primary parameter.
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
    // Generate our GCM.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

    //Get Nonce size using the gcm.NonceSize()
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}
	//Extract the nonce from the prefix of the encrypted data.
	//This is a very important since you can't decrypt the data without the correct nonce.
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	//The gcm.Open() function authenticates and decrypts ciphertext.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(plaintext))

	return string(plaintext)
}

func checkerror(err error) {
	if err != nil {
		panic(err)
	}
}

//----for test time ----

func (a Aes) Encryption_aes_test(){

	key := []byte(a.Key)
	text := []byte(a.Plaintext)

	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	gcm.Seal(nonce, nonce, text, nil)

}