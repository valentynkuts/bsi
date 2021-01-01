
//https://www.youtube.com/watch?v=wXB-V_Keiu8
//https://pkg.go.dev/crypto/rsa
//https://pkg.go.dev/crypto/rand

//"RSA encryption and decryption"
//author: Valentyn Kuts

package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	//selected version of the algorithm: aes or twofish
	crypto := os.Args[1]
	fmt.Println(crypto)
	//selected  option: encr or decr
	option := os.Args[2]
	fmt.Println(option)

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
			//publicKey := r.publicKey
			//fmt.Println(publicKey)
			r.encryption(publicKey)
		}

		if option == "decr" {
			privateKey := r.getPrivateKey()
			res := r.decryption(privateKey)
			fmt.Print(res)
		}
	}
}
