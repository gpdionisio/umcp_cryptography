package main

import (
	"encoding/hex"
	"fmt"
)

func isAsciiAlphabetic(b byte) bool {
	return (b >= 0x41 && b <= 0x5A) || // upper chars
		(b >= 0x61 && b <= 0x7A) // lower chars
}

// Given (c_i, c_j, c_k) construct c_ij (= c_i xor c_j), c_ik, c_jk
// if the byte at position n is a valid ASCII char e.g. for both c_ij and c_ik
// then we infer that m_i[n] is a space => therefore key[n] = c_i[n] xor b' '
func findKey(key []byte, c1, c2, c3 []byte) {
	for b := 0; b < len(c1); b++ {
		if key[b] != 0x00 {
			continue
		}
		c12 := isAsciiAlphabetic(c1[b] ^ c2[b])
		c13 := isAsciiAlphabetic(c1[b] ^ c3[b])
		c23 := isAsciiAlphabetic(c2[b] ^ c3[b])
		if c12 && c13 {
			key[b] = c1[b] ^ 0x20
		} else if c12 && c23 {
			key[b] = c2[b] ^ 0x20
		} else if c13 && c23 {
			key[b] = c3[b] ^ 0x20
		}
	}
}

func recoverKey(ciphertexts [][]byte) []byte {
	key := make([]byte, len(ciphertexts[0]))
	for i := 0; i < len(ciphertexts)-2; i++ {
		for j := i + 1; j < len(ciphertexts)-1; j++ {
			for k := j + 1; k < len(ciphertexts); k++ {
				findKey(key, ciphertexts[i], ciphertexts[j], ciphertexts[k])
			}
		}
	}
	return key
}

func decrypt(key []byte, ciphertexts [][]byte) [][]byte {
	plaintexts := make([][]byte, len(ciphertexts))
	for i, ct := range ciphertexts {
		plaintexts[i] = make([]byte, len(ct))
		for j, b := range ct {
			plaintexts[i][j] = key[j] ^ b
		}
	}
	return plaintexts
}

func main() {
	var ciphertexts [7][]byte
	ciphertexts[0], _ = hex.DecodeString("BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E")
	ciphertexts[1], _ = hex.DecodeString("BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E")
	ciphertexts[2], _ = hex.DecodeString("A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E")
	ciphertexts[3], _ = hex.DecodeString("A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F")
	ciphertexts[4], _ = hex.DecodeString("BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E")
	ciphertexts[5], _ = hex.DecodeString("A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E")
	ciphertexts[6], _ = hex.DecodeString("BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E")

	key := recoverKey(ciphertexts[:])
	fmt.Println(key)
	plaintexts := decrypt(key, ciphertexts[:])
	for i, pt := range plaintexts {
		fmt.Printf("% x\n", pt)
		fmt.Printf("%d) %s\n", (i + 1), string(pt))
	}

	fmt.Println("Final decryptions with manual adjustments:")

	// Manual adjustments: m[0][0] is not 0xbb, it's 'I', etc...
	key[0] ^= 0xbb ^ byte('I')
	key[6] ^= byte('O') ^ byte('l')
	key[8] ^= byte('W') ^ byte('n')
	key[10] ^= 0xa7 ^ byte('i')
	key[11] ^= 0x6e ^ byte('n')
	key[17] ^= 0x85 ^ byte('e')
	key[20] ^= byte('O') ^ byte('e')
	key[29] ^= 0x80 ^ byte('n')
	plaintexts = decrypt(key, ciphertexts[:])
	for i, pt := range plaintexts {
		// 1) I am planning a secret mission
		// 2) He is the only person to trust
		// 3) The current plan is top secret
		// 4) When should we meet to do this
		// 5) I think they should follow him
		// 6) This is purer than that one is
		// 7) Not one cadet is better than I
		fmt.Printf("%d) %s\n", (i + 1), string(pt))
	}
}
