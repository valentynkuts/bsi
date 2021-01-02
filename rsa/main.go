//https://www.youtube.com/watch?v=wXB-V_Keiu8
//https://pkg.go.dev/crypto/rsa
//https://pkg.go.dev/crypto/rand
//https://golang.org/pkg/encoding/gob/
//https://golang.org/pkg/crypto/sha256/
//https://golang.org/pkg/crypto/x509/
//https://golang.org/pkg/encoding/asn1/
//https://golang.org/pkg/encoding/pem/

//"RSA encryption and decryption"
//author: Valentyn Kuts

package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
    var crypto string
	var option string

	if len(os.Args) == 1{
		crypto = "rsa"
		option = "encr"
	} else {
		//selected version of the algorithm: rsa
		crypto = os.Args[1]
		fmt.Println(crypto)
		//selected  option: encr or decr
		option = os.Args[2]
		fmt.Println(option)
	}

		reader := bufio.NewReader(os.Stdin)

	r := Rsa{}

	r.generateKey() //TODO  → to comment when decrypt

	if crypto == "rsa" {

		if option == "encr" {
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			r.plaintext = text
			fmt.Println(r.plaintext)
			publicKey := r.getPublicKey()
			r.encryption(publicKey)
		}

		if option == "decr" {
			privateKey := r.getPrivateKey()
			res := r.decryption(privateKey)
			fmt.Print(res)
		}
	}
}
