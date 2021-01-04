//---- Advanced Encryption Standard (AES) ----
//https://www.youtube.com/watch?v=2r_KMzXB74w
//https://blog.golang.org/godoc
//https://golang.org/pkg/crypto/aes

//---- Twofish ----
//https://godoc.org/golang.org/x/crypto/twofish

//---- RSA ----
//https://www.youtube.com/watch?v=wXB-V_Keiu8
//https://pkg.go.dev/crypto/rsa
//https://pkg.go.dev/crypto/rand
//https://golang.org/pkg/encoding/gob/
//https://golang.org/pkg/crypto/sha256/
//https://golang.org/pkg/crypto/x509/
//https://golang.org/pkg/encoding/asn1/
//https://golang.org/pkg/encoding/pem/

//time
//https://golang.org/pkg/time/

//author: Valentyn Kuts

package main

import (
	"bsi/aes_twofish_rsa/alg"
	"bufio"
	"fmt"
	"os"
	"time"
)

func encryption(e alg.Enigma) {
	e.Encryption()
}

func decryption(e alg.Enigma) string {
	s := e.Decryption()
	return s
}

func main() {
	var crypto string
	var option string

	if len(os.Args) == 1 {
		crypto = "RSAvsAES"
		option = "time"
	} else {
		//selected version of the algorithm: aes, twofish, rsa
		crypto = os.Args[1]
		fmt.Println(crypto)
		//selected  option: encr or decr
		option = os.Args[2]
		fmt.Println(option)
	}

	reader := bufio.NewReader(os.Stdin)

	if crypto == "aes" {
		if option == "encr" {
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			a := alg.Aes{
				Plaintext: text,
				//key: "thisis32bitlongpassphraseimusing",
				Key: k,
			}
			encryption(a)
		}

		if option == "decr" {
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			a := alg.Aes{
				//key: "thisis32bitlongpassphraseimusing",
				Key: k,
			}
			res := decryption(a)
			fmt.Print(res)
		}
	}

	if crypto == "twofish" {
		if option == "encr" {
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			t := alg.Twofish{
				Plaintext: text,
				//key: "123456789012345678901234",
				Key: k,
			}
			encryption(t)
		}

		if option == "decr" {
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			t := alg.Twofish{
				//key: "123456789012345678901234",
				Key: k,
			}
			res := decryption(t)
			fmt.Print(res)
		}
	}

	// Algorithm RSA doesn't use the interface Enigma
	if crypto == "rsa" {
		r := alg.Rsa{}

		if option == "encr" {
			//Generate private and public keys
			r.GenerateKey()
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			r.Plaintext = text
			fmt.Println(r.Plaintext)
			publicKey := r.GetPublicKey()
			r.EncryptionRsa(publicKey)
		}

		if option == "decr" {
			privateKey := r.GetPrivateKey()
			res := r.DecryptionRsa(privateKey)
			fmt.Print(res)
		}
	}

	//---------------------------------------//
	//---- test time ------------------------//
	//---------------------------------------//

	//µs - microsecond
	//ms - millisecond
	//1 microseconds = 0.001 milliseconds

	if crypto == "RSAvsAES" {

		if option == "time" {

			rsa := alg.Rsa{}
			publicKey := rsa.GeneratePublicKey_test()

			aes := alg.Aes{
				Key: "thisis32bitlongpassphraseimusing",
			}

			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			rsa.Plaintext = text
			aes.Plaintext = text

			//fmt.Println("---- rsa -----")
			//fmt.Println(rsa.Plaintext)
			//fmt.Println(publicKey)
			//fmt.Println("---- aes-----")
			//fmt.Println(aes.Plaintext)
			//fmt.Println(aes.Key)
			//-------- RSA -----------
			n := 100

			start := time.Now()
			for i := 1; i < n; i++ {
				rsa.Encryption_rsa_test(publicKey)
			}
			t := time.Now()
			elapsed := t.Sub(start)

			fmt.Printf("Time after %d itetation of RSA encryption: \n", n)
			fmt.Println(elapsed)
			//--------- AES ---------------
			start1 := time.Now()
			for i := 1; i < n; i++ {
				aes.Encryption_aes_test()
			}
			t1 := time.Now()
			elapsed1 := t1.Sub(start1)

			fmt.Printf("Time after %d itetation of AES encryption: \n", n)
			fmt.Println(elapsed1)

		}

	}
}
