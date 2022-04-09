package main

import (
	"encoding/hex"
	"fmt"
	"math"
)

const MAX_KEY_LEN int = 13

// number of occurrences of each char in a given block of text
type BlockCounters [256]uint
type BlockFrequencies [256]float64

// a stream (for key of len L) is an array of L block counters
// occurences at position 0,...,(L-1)
type StreamCounters []BlockCounters
type StreamFrequencies []BlockFrequencies

func sumArr(arr []uint) uint {
	var res uint = 0
	for _, x := range arr {
		res += x
	}
	return res
}

func sumArrSquared(arr []float64) float64 {
	var res float64 = 0.0
	for _, x := range arr {
		res += math.Pow(x, 2)
	}
	return res
}

func avgArr(arr []float64) float64 {
	var sum float64 = 0.0
	for _, x := range arr {
		sum += x
	}
	return sum / float64(len(arr))
}

func xorArr(arr []byte, k byte) []byte {
	res := make([]byte, len(arr))
	for i, b := range arr {
		res[i] = b ^ k
	}
	return res
}

// We start with an array of StreamCounters, one for every possible
// key lenght L=1,...,MAX_KEY_LEN.
// Then we count the occurences of each char in each stream
// and get the frequency
func getStreamFrequencies(ct []byte) [MAX_KEY_LEN]StreamFrequencies {
	var vec [MAX_KEY_LEN]StreamCounters
	for L := 1; L <= MAX_KEY_LEN; L++ {
		vec[L-1] = make([]BlockCounters, L)
	}
	for i, b := range ct {
		// increment the counter for byte 'b' in every stream
		for L := 1; L <= MAX_KEY_LEN; L++ {
			vec[L-1][i%L][b]++
		}

	}
	var freq [MAX_KEY_LEN]StreamFrequencies
	for L := 1; L <= MAX_KEY_LEN; L++ {
		freq[L-1] = make([]BlockFrequencies, L)
		for i, blk := range vec[L-1] {
			tot := sumArr(blk[:])
			for j := 0; j < len(blk); j++ {
				freq[L-1][i][j] = float64(vec[L-1][i][j]) / float64(tot)
			}
		}

	}
	return freq
}

// valid plaintext can only be:
// upper- and lower-case letters, punctuation, and spaces, but no numbers
func tryKey(ct_stream []byte, candidate_key byte) bool {
	candidate_pt := xorArr(ct_stream, candidate_key)
	for _, b := range candidate_pt {
		if !(b == 0x20 || // space
			b == 0x2C || // ,
			b == 0x2E || // .
			(b >= 0x41 && b <= 0x5A) || // upper chars
			(b >= 0x61 && b <= 0x7A)) { // lower chars
			return false
		}
	}
	return true
}

func findKey(ct_stream []byte) (byte, bool) {
	for k := 0; k <= 255; k++ {
		if tryKey(ct_stream, byte(k)) {
			return byte(k), true
		}
	}
	return 0x00, false
}

func main() {
	hex_ciphertext := "F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B" +
		"9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C" +
		"963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B" +
		"9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850" +
		"D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56" +
		"C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D" +
		"963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D" +
		"963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4A" +
		"DF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85F" +
		"CE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35B" +
		"C831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B" +
		"9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859" +
		"D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1E" +
		"DB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49" +
		"DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44D" +
		"DF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31E" +
		"D87AB1D021A255DF71B1C436BF479A7AF0C13AA14794"

	ct, err := hex.DecodeString(hex_ciphertext)
	if err != nil {
		panic(err)
	}

	// Get the sum of the frquencies squared for each possible key len
	freq := getStreamFrequencies(ct)
	var sums [MAX_KEY_LEN]float64
	for L := 1; L <= MAX_KEY_LEN; L++ {
		var s = make([]float64, L)
		for i := 0; i < L; i++ {
			s[i] = sumArrSquared(freq[L-1][i][:])
		}
		sums[L-1] = avgArr(s)
	}

	// Find best value --> candidate key len
	var keylen uint = 0
	var max_sum float64 = 0.0
	for i, sum := range sums {
		if sum > max_sum {
			keylen = uint(i + 1)
			max_sum = sum
		}
	}

	fmt.Printf("Candidate key len is %d\n", keylen)

	// Build ciphertext streams
	var ct_streams [][]byte = make([][]byte, keylen)
	for i, b := range ct {
		ct_streams[i%int(keylen)] = append(ct_streams[i%int(keylen)], b)
	}

	// Find key
	key := make([]byte, keylen)
	for i := 0; i < int(keylen); i++ {
		fmt.Printf("Searching key (byte at index %d)...\n", i)
		var found bool
		key[i], found = findKey(ct_streams[i])
		if !found {
			fmt.Println("  ---> NOT FOUND!")
		}
	}

	// Decrypt
	fmt.Println("Decrypting...")
	plaintext := make([]byte, len(ct))
	for i := 0; i < len(ct); i++ {
		plaintext[i] = ct[i] ^ key[i%int(keylen)]
	}

	// Result:
	/* Cryptography is the practice and study of techniques for, among other things, secure communication in the
	   presence of attackers. Cryptography has been used for hundreds, if not thousands, of years, but traditional
	   cryptosystems were designed and evaluated in a fairly ad hoc manner. For example, the Vigenere encryption
	   scheme was thought to be secure for decades after it was invented, but we now know, and this exercise
	   demonstrates, that it can be broken very easily.
	*/
	fmt.Println(string(plaintext))
}
