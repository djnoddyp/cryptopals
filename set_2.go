package main

import (
	"crypto/aes"
	"fmt"
)

// Challenge 9
func ImplementPkcs7Padding(plaintext []byte, padLength int) {
	buf := make([]byte, padLength)
	copy(buf, plaintext)
	for i := len(plaintext); i < padLength; i++ {
		buf[i] = byte('\x04')
	}
	fmt.Printf("%q", buf)
}

// Challenge 10
// C = E(K, P ^ C-1)
func ImplementCbcEnc(plaintext []byte) []byte {
	const blockSize = 16
	const key = "YELLOW SUBMARINE"
	iv := make([]byte, blockSize)
	for i := range iv {
		iv[i] = byte(0)
	}

	cipher, _ := aes.NewCipher([]byte(key))
	buf := make([]byte, len(plaintext))
	ciphertext := make([]byte, 0)

	cipherBlock := make([]byte, blockSize)

	for i := 0; i < len(plaintext)/blockSize; i++ {
		// get next 8 byte block
		plainBlock := plaintext[blockSize*i : blockSize*(i+1)]
		// first block xor'd with IV
		if i == 0 {
			for j := 0; j < blockSize; j++ {
				plainBlock[j] = plainBlock[j] ^ iv[j]
			}
			// rest xor'd with previous ciphertext block
		} else {
			for j := 0; j < blockSize; j++ {
				plainBlock[j] = plainBlock[j] ^ cipherBlock[j]
			}
		}
		cipher.Encrypt(buf, plainBlock)
		ciphertext = append(ciphertext, buf...)
		copy(cipherBlock, buf)
	}
	return ciphertext
}

// P = (D(K, C) ^ C-1)
func ImplementCbcDec(ciphertext []byte) []byte {
	const blockSize = 16
	const key = "YELLOW SUBMARINE"
	// const filename = "2_9.txt"
	// ciphertext, _ := ioutil.ReadFile(filename)

	iv := make([]byte, blockSize)
	for i := range iv {
		iv[i] = byte(0)
	}

	cipher, _ := aes.NewCipher([]byte(key))
	buf := make([]byte, len(ciphertext))
	plaintext := make([]byte, 0)
	prevCipherBlock := make([]byte, blockSize)

	for i := 0; i < len(ciphertext)/blockSize; i++ {
		// get next 16 byte block
		cipherBlock := ciphertext[blockSize*i : blockSize*(i+1)]
		// decrypt it
		cipher.Decrypt(buf, cipherBlock)
		// first decrypted block xor'd with the IV
		if i == 0 {
			for j := 0; j < blockSize; j++ {
				buf[j] = buf[j] ^ iv[j]
			}
			// rest xor'd with the previous cipherblock
		} else {
			for j := 0; j < blockSize; j++ {
				buf[j] = buf[j] ^ prevCipherBlock[j]
			}
		}
		plaintext = append(plaintext, buf...)
		copy(prevCipherBlock, cipherBlock)
	}
	return plaintext
}
