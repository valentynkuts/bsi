//https://www.youtube.com/watch?v=2r_KMzXB74w
//https://blog.golang.org/godoc
//https://golang.org/pkg/crypto/aes
//https://godoc.org/golang.org/x/crypto/twofish

//Advanced Encryption Standard (AES)
//Twofish

//author: Valentyn Kuts

package main

import (
	"bufio"
	"fmt"
	"os"
)

func encryption(e enigma){
	e.encryption()
}

func decryption(e enigma) string{
	s := e.decryption()
	return s
}

func main() {
	//selected version of the algorithm: aes or twofish
	crypto := os.Args[1]
	fmt.Println(crypto)
	//selected  option: encr or decr
	option := os.Args[2]
	fmt.Println(option)

	reader := bufio.NewReader(os.Stdin)

    if crypto == "aes" {
		if option == "encr" {
			fmt.Print("Enter text: ")
			text, _ := reader.ReadString('\n')
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			a := Aes{
				plaintext: text,
				//key: "thisis32bitlongpassphraseimusing",
				key: k,
			}
			encryption(a)
	    }

		if option == "decr" {
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			a := Aes{
				//key: "thisis32bitlongpassphraseimusing",
				key: k,
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

			t := Twofish {
				plaintext: text,
				//key: "123456789012345678901234",
				key: k,
			}
			encryption(t)
		}

		if option == "decr" {
			fmt.Print("Enter key: ")
			k, _ := reader.ReadString('\n')

			t := Twofish {
				//key: "123456789012345678901234",
				key: k,
			}
			res := decryption(t)
			fmt.Print(res)
		}
	}
}

