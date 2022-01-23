package main

func main() {
	// start := time.Now()
	// fmt.Println(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))

	// fmt.Println(fixedXor("1c0111001f010100061a024b53535009181c",
	// 	"686974207468652062756c6c277320657965"))

	// scores := decipherSingleByteXor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	// scores := DetectSingleCharXor("1_4.txt")
	// fmt.Println("***** Top 5 score results *****")
	// for i := 0; i < 5; i++ {
	// 	fmt.Printf("%d: key=%s score=%d plaintext=%s \n", i+1, scores[i].char, scores[i].score, scores[i].plaintext)
	// }

	// fmt.Println(RepeatingKeyXor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"))

	// fmt.Println(FindEditDistance("this is a test", "wokka wokka!!!"))

	// BreakRepeatingKeyXor()
	// ImplementPkcs7Padding([]byte("Issssssssssssss"), 16)
	// c := ImplementCbcEnc([]byte("ttttttttttttiiiiiiiiiiiiiiiittttttttttttttttssssssssssssssss"))
	// c := ImplementCbcEnc([]byte("ttttttttttttttttiiiiiiiiiiiiiiiittttttttsssss"))
	// // AesEcbMode(c)
	// fmt.Println(string(ImplementCbcDec(c)))

	// AesEncOracle([]byte("titstitstitstitsdickdickdickdick"))

	// fmt.Printf("\nExecution time: %v", time.Since(start))

	DeterminEcbOrCbc([]byte("aaaaaaaabbbbbbbbc"))
}
