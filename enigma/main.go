//https://www.youtube.com/watch?v=2r_KMzXB74w
//https://blog.golang.org/godoc
//https://golang.org/pkg/crypto/aes
//https://godoc.org/golang.org/x/crypto/twofish

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
	crypto := os.Args[1]
	//fmt.Println(os.Args[0])
	fmt.Println(crypto)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter text: ")
	text, _ := reader.ReadString('\n')
	//fmt.Println(text)

    if crypto == "aes" {
		a := Aes {
			plaintext: text,
			key: "thisis32bitlongpassphraseimusing",
		}
		encryption(a)
		res := decryption(a)
		fmt.Print(res)
	}

	if crypto == "twofish" {
		t := Twofish {
			plaintext: text,
			key: "123456789012345678901234",
		}
		encryption(t)
		res := decryption(t)
		fmt.Print(res)
	}

}

