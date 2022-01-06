package main

import (
	b64 "encoding/base64"
	"encoding/hex"
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

	for _, ce := range ascii_chars {
		for di, de := range decoded {
			res[di] = de ^ ce
		}
		current_score := scoreSample(res)
		plain := make([]byte, len(res))
		copy(plain, res)
		scores = append(scores, CharScore{string(ce), current_score, plain})
		sort.Sort(ByScore(scores))
	}
	return scores[0:3]
}

// Set 1 Challenge 4
func DetectSingleCharXor(filename string) []CharScore {
	content, _ := ioutil.ReadFile(filename)
	lines := strings.Split(string(content), "\n")
	final_scores := make([]CharScore, 1)

	for _, e := range lines {
		final_scores = append(final_scores, DecipherSingleByteXor(e)...)
	}
	sort.Sort(ByScore(final_scores))
	return final_scores[0:5]
}

// Challenge 5
func RepeatingKeyXor(plaintext string) string {
	bytes := []byte(plaintext)
	ciphertext := make([]byte, len(bytes))

	key := strings.Repeat("ICE", len(plaintext)/3+1)
	key_bytes := []byte(strings.TrimRightFunc(key, func(r rune) bool {
		return len(key) == len(plaintext)
	}))

	for i, e := range bytes {
		ciphertext[i] = e ^ key_bytes[i]
	}
	return hex.EncodeToString(ciphertext)
}

type CharScore struct {
	char      string
	score     int
	plaintext []byte
}

type ByScore []CharScore

func (s ByScore) Less(i, j int) bool { return s[i].score > s[j].score }
func (s ByScore) Len() int           { return len(s) }
func (s ByScore) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func scoreSample(sample []byte) int {
	num_e := strings.Count(string(sample), string('e'))
	num_t := strings.Count(string(sample), string('t'))
	num_a := strings.Count(string(sample), string('a'))
	num_o := strings.Count(string(sample), string('o'))
	num_i := strings.Count(string(sample), string('i'))
	num_s := strings.Count(string(sample), string('s'))

	return num_e*6 + num_t*5 + num_a*4 + num_o*3 + num_i*2 + num_s
}

var ascii_chars = []byte{' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
	'+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<',
	'=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
	's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'}
