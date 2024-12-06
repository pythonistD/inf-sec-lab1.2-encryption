package main

import "github.com/pythonistD/inf-sec-lab1.2-encryption/internal/cli"

func main() {
	/*var key = []byte{0x01, 0xff, 0xae, 0x00,
		0x15, 0x16, 0xea, 0xbc,
		0xbb, 0x11, 0x00, 0x10,
		0xff, 0xb1, 0xc7, 0x86}
	r, _ := algorithms.NewRijndael(key)

	m := "Hello, AES-128"
	encrypted := r.EncryptECB([]byte(m))
	fmt.Printf("Encrypted Data: %x", encrypted)
	decrypted := r.DecryptECB(encrypted)
	fmt.Printf("Decrypted Data: %s", string(decrypted))*/

	cli.Execute()
}
