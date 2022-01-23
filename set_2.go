package main

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	r "math/rand"
	"time"
)

// Challenge 9
func ImplementPkcs7Padding(plaintext []byte, blockSize int) []byte {
	// determine how many bytes of padding are needed
	padLength := blockSize - (len(plaintext) % blockSize)
	buf := make([]byte, len(plaintext)+padLength)

	copy(buf, plaintext)
	for i := len(plaintext); i < len(buf); i++ {
		buf[i] = byte(padLength)
	}
	return buf
}

// Challenge 10
// C = E(K, P ^ C-1)
func ImplementCbcEnc(plaintext, key, iv []byte) []byte {
	const blockSize = 16
	// const key = "YELLOW SUBMARINE"
	// iv := make([]byte, blockSize)
	// for i := range iv {
	// 	iv[i] = byte(0)
	// }

	// pad if necessary
	r := len(plaintext) % blockSize
	if r > 0 {
		plaintext = ImplementPkcs7Padding(plaintext, blockSize)
	}

	cipher, _ := aes.NewCipher([]byte(key))
	// buffer for holding the current encrypted block
	buf := make([]byte, blockSize)
	ciphertext := make([]byte, 0)

	prevCipherBlock := make([]byte, blockSize)

	for i := 0; i < len(plaintext)/blockSize; i++ {
		// get next 16 byte block
		plainBlock := plaintext[blockSize*i : blockSize*(i+1)]
		// first block xor'd with IV
		if i == 0 {
			prevCipherBlock = iv
			// rest xor'd with previous ciphertext block
		}
		for j := 0; j < blockSize; j++ {
			plainBlock[j] = plainBlock[j] ^ prevCipherBlock[j]
		}
		cipher.Encrypt(buf, plainBlock)
		ciphertext = append(ciphertext, buf...)
		copy(prevCipherBlock, buf)
	}
	return ciphertext
}

// P = (D(K, C) ^ C-1)
func ImplementCbcDec(ciphertext []byte) []byte {
	const blockSize = 16
	const key = "YELLOW SUBMARINE"
	// const filename = "2_9.txt"
	// content, _ := ioutil.ReadFile(filename)
	// ciphertext := make([]byte, b64.StdEncoding.DecodedLen(len(content)))
	// l, _ := b64.RawStdEncoding.Decode(ciphertext, content)
	// ciphertext = ciphertext[:l]

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

// ECB does not pad
func AesEcbEnc(plaintext, key []byte) []byte {
	blockSize := 16
	block, _ := aes.NewCipher([]byte(key))

	buffer := make([]byte, blockSize)
	ciphertext := make([]byte, 0)

	for i := 0; i < len(plaintext)/blockSize; i++ {
		block.Encrypt(buffer, plaintext[blockSize*i:blockSize*(i+1)])
		ciphertext = append(ciphertext, buffer...)
	}

	return ciphertext
}

// Challenge 11
func AesEncOracle(plaintext []byte) []byte {
	// seed rand and get random number of bytes to add
	r.Seed(time.Now().UnixMicro())
	bytes := []int{5, 6, 7, 8, 9, 10}
	r.Shuffle(len(bytes), func(i, j int) {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	})
	numBytes := bytes[0]

	// prepend and append some bytes
	plaintext = append(plaintext, getBytes(numBytes)...)
	buf := make([]byte, numBytes)
	buf = append(buf, plaintext...)
	copy(buf, getBytes(numBytes))

	// randomly choose ECB or CBC mode and encrypt
	i := r.Intn(2)
	key := genAesKey()
	var ciphertext []byte
	if i == 0 {
		ciphertext = AesEcbEnc(buf, key)
	} else {
		iv := getBytes(16)
		ciphertext = ImplementCbcEnc(buf, key, iv)
	}
	fmt.Println(i)
	// fmt.Println(ciphertext)
	return ciphertext
}

func DeterminEcbOrCbc(plaintext []byte) {
	ciphertext := AesEncOracle(plaintext)
	extraBytes := len(ciphertext) - len(plaintext)
	if extraBytes > 15 {
		fmt.Println("cbc")
	} else {
		fmt.Println("ecb")
	}
	// cLen := len(ciphertext) - extraBytes
	// fmt.Println(cLen)

}

func genAesKey() []byte {
	key := make([]byte, 16)
	rand.Read(key)
	return key
}

func getBytes(num int) []byte {
	bytes := make([]byte, num)
	rand.Read(bytes)
	return bytes
}
