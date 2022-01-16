package main

import (
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

	for _, ce := range ascii_chars {
		for di, de := range decoded {
			res[di] = de ^ ce
		}
		current_score := scoreSample(res)
		plain := make([]byte, len(res))
		copy(plain, res)
		scores = append(scores, CharScore{string(ce), current_score, string(plain), false})
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
	for key_size := 2; key_size <= 40; key_size++ {
		a := ciphertext[:key_size]
		b := ciphertext[key_size : key_size*2]
		c := ciphertext[key_size*2 : key_size*3]
		d := ciphertext[key_size*3 : key_size*4]
		e := ciphertext[key_size*4 : key_size*5]
		f := ciphertext[key_size*5 : key_size*6]
		g := ciphertext[key_size*6 : key_size*7]
		h := ciphertext[key_size*7 : key_size*8]
		i := ciphertext[key_size*8 : key_size*9]
		j := ciphertext[key_size*9 : key_size*10]
		edit_dist_1 := float32(findEditDistance(a, b)) / float32(key_size)
		edit_dist_2 := float32(findEditDistance(c, d)) / float32(key_size)
		edit_dist_3 := float32(findEditDistance(e, f)) / float32(key_size)
		edit_dist_4 := float32(findEditDistance(g, h)) / float32(key_size)
		edit_dist_5 := float32(findEditDistance(i, j)) / float32(key_size)
		scores = append(scores, EditScore{
			keysize: key_size,
			score: float32((edit_dist_1 + edit_dist_2 + edit_dist_3 +
				edit_dist_4 + edit_dist_5)) / float32(5),
		})
	}
	sort.Sort(ByEditScore(scores))
	fmt.Println(scores)

	// break ciphertext into blocks into keysize length
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
	key_bytes := []byte(strings.TrimRightFunc(key, func(r rune) bool {
		return len(key) == len(ciphertext)
	}))

	plaintext := make([]byte, len(ciphertext))
	for i, e := range ciphertext {
		plaintext[i] = e ^ key_bytes[i]
	}
	fmt.Println(string(plaintext))
}

// Challenge 7
func AesEcbMode() {
	const key = "YELLOW SUBMARINE"

	const filename = "1_7.txt"
	content, _ := ioutil.ReadFile(filename)

	ciphertext := make([]byte, b64.StdEncoding.DecodedLen(len(content)))
	l, _ := b64.RawStdEncoding.Decode(ciphertext, content)
	ciphertext = ciphertext[:l]

	// Obtain new block using key (AES-128)
	block, _ := aes.NewCipher([]byte(key))

	buffer := make([]byte, len(ciphertext))
	plaintext := make([]byte, len(ciphertext))

	// decrypt ciphertext one 128 bit block at a time
	key_len := len(key)
	for i := 0; i < len(ciphertext)/key_len; i++ {
		block.Decrypt(buffer, ciphertext[key_len*i:key_len*(i+1)])
		plaintext = append(plaintext, buffer...)
	}

	fmt.Println(string(plaintext))
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
		current_score := scoreSample(res)
		plain := make([]byte, len(res))
		copy(plain, res)
		scores = append(scores, CharScore{string(ce), current_score, string(plain), checkHasLetters(plain)})
		sort.Sort(ByScore(scores))
	}
	// fmt.Println(scores)
	// fmt.Println(s[0].char, s[0].score)
	// for _, e := range scores[:3] {
	// fmt.Printf("char=%s \nscore=%d\nplain=%s\nhasLetters=%v \n\n", e.char, e.score, e.plaintext[:80], e.has_letters)
	// fmt.Printf("char=%s \nscore=%d \n\n", e.char, e.score)
	// }
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
	char        string
	score       int
	plaintext   string
	has_letters bool
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
	return num_e*2 +
		num_t*2 + num_a*2 + num_o + num_i + num_n +
		num_s + num_h + num_r + num_d + num_l + num_u + num_space
}

var ascii_chars = []byte{' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
	'+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<',
	'=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
	's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'}
