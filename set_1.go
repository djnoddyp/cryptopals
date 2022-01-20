package main

import (
	"bytes"
	"crypto/aes"
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"
)

// Set 1 Challenge 1
func HexToBase64(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b64.StdEncoding.EncodeToString(b)
}

// Set 1 Challenge 2
func FixedXor(a, b string) string {
	d1, _ := hex.DecodeString(a)
	d2, _ := hex.DecodeString(b)

	res := make([]byte, hex.DecodedLen(len(a)))
	for i, e := range d1 {
		res[i] = e ^ d2[i]
	}

	return hex.EncodeToString(res)
}

// Set 1 Challenge 3
func DecipherSingleByteXor(ciphertext string) []CharScore {
	decoded, _ := hex.DecodeString(ciphertext)
	res := make([]byte, hex.DecodedLen(len(ciphertext)))
	scores := make([]CharScore, 1)

	ascii := make([]byte, 256)
	for i := range ascii {
		ascii[i] = byte(i)
	}

	for _, ce := range ascii[32:127] {
		for di, de := range decoded {
			res[di] = de ^ ce
		}
		currentScore := scoreSample(res)
		plain := make([]byte, len(res))
		copy(plain, res)
		scores = append(scores, CharScore{string(ce), currentScore, string(plain), false})
		sort.Sort(ByScore(scores))
	}
	return scores[0:3]
}

// Set 1 Challenge 4
func DetectSingleCharXor(filename string) []CharScore {
	content, _ := ioutil.ReadFile(filename)
	lines := strings.Split(string(content), "\n")
	finalScores := make([]CharScore, 1)

	for _, e := range lines {
		finalScores = append(finalScores, DecipherSingleByteXor(e)...)
	}
	sort.Sort(ByScore(finalScores))
	return finalScores[0:5]
}

// Challenge 5
func RepeatingKeyXor(plaintext string) string {
	bytes := []byte(plaintext)
	ciphertext := make([]byte, len(bytes))

	key := strings.Repeat("ICE", len(plaintext)/3+1)
	keyBytes := []byte(strings.TrimRightFunc(key, func(r rune) bool {
		return len(key) == len(plaintext)
	}))

	for i, e := range bytes {
		ciphertext[i] = e ^ keyBytes[i]
	}
	return hex.EncodeToString(ciphertext)
}

// Challenge 6
func BreakRepeatingKeyXor() {
	const filename = "1_6.txt"
	content, _ := ioutil.ReadFile(filename)

	ciphertext := make([]byte, b64.StdEncoding.DecodedLen(len(content)))
	l, _ := b64.RawStdEncoding.Decode(ciphertext, content)
	ciphertext = ciphertext[:l]

	scores := make([]EditScore, 0)

	// find keysize by trying sizes 2-40 and scoring them
	// by edit distance (shortest wins)
	// Contrary to cryptopals it seems necessary to average out the
	// distance from multiple (4+) samples to get accurate results
	for keySize := 2; keySize <= 40; keySize++ {
		a := ciphertext[:keySize]
		b := ciphertext[keySize : keySize*2]
		c := ciphertext[keySize*2 : keySize*3]
		d := ciphertext[keySize*3 : keySize*4]
		e := ciphertext[keySize*4 : keySize*5]
		f := ciphertext[keySize*5 : keySize*6]
		g := ciphertext[keySize*6 : keySize*7]
		h := ciphertext[keySize*7 : keySize*8]
		i := ciphertext[keySize*8 : keySize*9]
		j := ciphertext[keySize*9 : keySize*10]
		editDist1 := float32(findEditDistance(a, b)) / float32(keySize)
		editDist2 := float32(findEditDistance(c, d)) / float32(keySize)
		editDist3 := float32(findEditDistance(e, f)) / float32(keySize)
		editDist4 := float32(findEditDistance(g, h)) / float32(keySize)
		editDist5 := float32(findEditDistance(i, j)) / float32(keySize)
		scores = append(scores, EditScore{
			keysize: keySize,
			score: float32((editDist1 + editDist2 + editDist3 +
				editDist4 + editDist5)) / float32(5),
		})
	}
	sort.Sort(ByEditScore(scores))
	fmt.Println(scores)

	// break ciphertext into blocks of keysize length
	keysize := 29
	blocks := make([][]byte, len(ciphertext)/keysize)
	index := 0
	for i := keysize; i <= len(ciphertext); i += keysize {
		blocks[index] = ciphertext[keysize*index : i]
		index++
	}

	// transpose blocks
	for i := 0; i < keysize; i++ {
		block := make([]byte, len(ciphertext)/keysize)
		for j, e := range blocks {
			block[j] = e[i]
		}
		doDecipher(block)
		fmt.Println()
	}

	key := strings.Repeat("Terminator X: Bring the noise", len(ciphertext))
	keyBytes := []byte(strings.TrimRightFunc(key, func(r rune) bool {
		return len(key) == len(ciphertext)
	}))

	plaintext := make([]byte, len(ciphertext))
	for i, e := range ciphertext {
		plaintext[i] = e ^ keyBytes[i]
	}
	fmt.Println(string(plaintext))
}

// Challenge 7
func AesEcbMode(ciphertext []byte) {
	const key = "YELLOW SUBMARINE"

	// const filename = "1_7.txt"
	// content, _ := ioutil.ReadFile(filename)

	// ciphertext := make([]byte, b64.StdEncoding.DecodedLen(len(content)))
	// l, _ := b64.RawStdEncoding.Decode(ciphertext, content)
	// ciphertext = ciphertext[:l]

	// Obtain new block using key (AES-128)
	block, _ := aes.NewCipher([]byte(key))

	buffer := make([]byte, len(ciphertext))
	plaintext := make([]byte, len(ciphertext))

	// decrypt ciphertext one 128 bit block at a time
	keyLen := len(key)
	for i := 0; i < len(ciphertext)/keyLen; i++ {
		block.Decrypt(buffer, ciphertext[keyLen*i:keyLen*(i+1)])
		plaintext = append(plaintext, buffer...)
	}

	fmt.Println(string(plaintext))
}

// Challenge 8
func DetectAesECb() {
	const filename = "1_8.txt"
	content, _ := ioutil.ReadFile(filename)
	bunch := bytes.Split(content, []byte("\n"))

	for _, e := range bunch {
		ciphertext, _ := hex.DecodeString(string(e))
		if len(ciphertext) > 0 {
			if isEcb(ciphertext[:160]) {
				fmt.Printf("### we have a winner ###\n\nciphertext: %s \n\nhex: %s", ciphertext, hex.EncodeToString(ciphertext))
			}
		}
	}

}

// AES with ECB mode is weak because it is stateless and deterministic,
// the same 16 bytes of plaintext will always produce the same 16 bytes of ciphertext
func isEcb(sample []byte) bool {
	result := false
	// check each 16 byte block against every other (except itself) for equality
	for i := 0; i < 10; i++ {
		this := sample[i*16 : (i+1)*16]
		for j := 0; j < 10; j++ {
			other := sample[j*16 : (j+1)*16]
			if i != j && bytes.Equal(this, other) {
				return true
			}
		}
	}
	return result
}

func doDecipher(block []byte) {
	res := make([]byte, len(block))
	scores := make([]CharScore, 0)

	ascii := make([]byte, 256)
	for i := range ascii {
		ascii[i] = byte(i)
	}

	for _, ce := range ascii[32:127] {
		for di, de := range block {
			res[di] = ce ^ de
		}
		currentScore := scoreSample(res)
		plain := make([]byte, len(res))
		copy(plain, res)
		scores = append(scores, CharScore{string(ce), currentScore, string(plain), checkHasLetters(plain)})
		sort.Sort(ByScore(scores))
	}
}

func findEditDistance(a, b []byte) int {
	first := a
	second := b

	if len(a) > len(b) {
		second = make([]byte, len(a))
		copy(second, b)
	} else if len(b) > len(a) {
		first = make([]byte, len(b))
		copy(first, a)
	}

	bits := ""
	var xor_result byte
	for i, e := range first {
		xor_result = e ^ second[i]
		bits += fmt.Sprintf("%b", xor_result)
	}
	return strings.Count(bits, "1")
}

func checkHasLetters(sample []byte) bool {
	result := true
	for _, e := range sample {
		if int(e) < 32 ||
			int(e) > 126 &&
				int(e) != 10 {
			result = false
		}
	}
	return result
}

type EditScore struct {
	keysize int
	score   float32
}

type ByEditScore []EditScore

func (s ByEditScore) Less(i, j int) bool { return s[i].score < s[j].score }
func (s ByEditScore) Len() int           { return len(s) }
func (s ByEditScore) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type CharScore struct {
	char       string
	score      int
	plaintext  string
	hasLetters bool
}

type ByScore []CharScore

func (s ByScore) Less(i, j int) bool { return s[i].score > s[j].score }
func (s ByScore) Len() int           { return len(s) }
func (s ByScore) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func scoreSample(sample []byte) int {
	lower := strings.ToLower(string(sample))
	// num_the := strings.Count(lower, "the ")
	// num_and := strings.Count(lower, "and ")
	// num_it := strings.Count(lower, "it ")
	// num_comma := strings.Count(lower, ", ")
	// num_stop := strings.Count(lower, ". ")
	// num_to := strings.Count(lower, "to ")
	// num_be := strings.Count(lower, " be ")
	// num_of := strings.Count(lower, " of ")
	// num_A := strings.Count(lower, "a ")
	// num_for := strings.Count(lower, "for ")
	// num_have := strings.Count(lower, " have ")
	// num_in := strings.Count(lower, " in ")
	num_e := strings.Count(lower, string('e'))
	num_t := strings.Count(lower, string('t'))
	num_a := strings.Count(lower, string('a'))
	num_o := strings.Count(lower, string('o'))
	num_i := strings.Count(lower, string('i'))
	num_n := strings.Count(lower, string('n'))
	num_s := strings.Count(lower, string('s'))
	num_h := strings.Count(lower, string('h'))
	num_r := strings.Count(lower, string('f'))
	num_d := strings.Count(lower, string('d'))
	num_l := strings.Count(lower, string('l'))
	num_u := strings.Count(lower, string('u'))
	num_space := strings.Count(lower, string(' '))

	// return num_the +
	// 	num_and + num_it + num_comma + num_stop + num_to +
	// 	num_be + num_of + num_A + num_have + num_for + num_in
	return num_e*13 +
		num_t*12 + num_a*11 + num_o*10 + num_i*9 + num_n*8 +
		num_s*7 + num_h*6 + num_r*5 + num_d*4 + num_l*3 + num_u*2 + num_space
}
