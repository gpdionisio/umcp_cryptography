package main

import (
	"encoding/hex"
	"errors"
	"fmt"

	"w3_assign/oracle"
)

const (
	HOST = "128.8.130.16"
	PORT = "49101"

	CHALLENGESTR = "9F0B13944841A832B2421B9EAF6D9836813EC9D944A5C8347A7CA69AA34D8DC0DF70E343C4000A2AE35874CE75E64C31"
)

type PaddingOracle struct {
	serv oracle.Server
}

func NewPaddingOracle(host, port string) *PaddingOracle {
	var o PaddingOracle
	err := o.serv.Connect(HOST, PORT)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to server at %s:%s\n", host, port)
	return &o
}

// Query queries the server for a given chiphertext
// returns true if response status is 1 (good padding)
// returns false if response status is 0 (bad padding)
func (o *PaddingOracle) Query(ct1, ct2 []byte) bool {
	ct := ct1
	ct = append(ct, ct2...)
	res, err := o.serv.Send(ct)
	if err != nil {
		panic(err)
	}
	switch res {
	case 0:
		return false
	case 1:
		return true
	case -1:
		panic("Malformed packet!")
	}
	panic(fmt.Errorf("invalid reply %d", res))
}

// IsValidGuess returns whether a certain byte is a possible plaintext byte
func IsValidGuess(b byte) bool {
	if b >= 0x01 && b <= 0x10 { // pad
		return true
	}
	return b >= 0x20
}

// DiscoverNextByte attacks the last unknown byte of plaintext block M_(j+1).
// given ciphertext blocks C_j and C_(j+1), and vector [B_1, ..., B_k]
// of already discovered bytes of M_(j+1) in reversed order (B_1 is the
// last byte of M_(j+1), B_2 is the byte at index N-2, etc ..., B_k
// is the byte at index N-k).
// Represent (k+1) as the byte 'pad', and construct the block D_g as
// D_g := [   C_j[0],
//            C_j[1],
//            ...,
//            C_j[N-k-3],
//            C_j[N-k-2],
//            C_j[N-k-1] ^ pad ^ g,
//            C_j[N-k] ^ pad ^ B_k,
//            C_j[N-k+1] ^ pad ^ B_(k-1),
//            ...,
//            C_j[N-1] ^ pad ^ B_1   ]
//
// Submit the ciphertext D_g || C_(j+1) to check for valid padding
// if valid --> g is the next byte. Otherwise increment it and try again.
func (o *PaddingOracle) DiscoverNextByte(prevblk,
	thisblk,
	discovered []byte,
	startg byte) (byte, bool) {
	nextIdx := 16 - len(discovered) - 1
	fmt.Printf("Discovering byte at index %d...\n", nextIdx)
	pad := byte(len(discovered) + 1)
	forgedct := make([]byte, 16)

	// prepare new block
	copy(forgedct, prevblk)
	for i := nextIdx + 1; i < 16; i++ {
		forgedct[i] = forgedct[i] ^ discovered[16-i-1] ^ pad
	}

	// try guesses for g
	for g := startg; g < 0x7B; g++ {
		if !IsValidGuess(g) {
			continue
		}
		fmt.Printf("Guessing 0x%02x\r", g)
		forgedct[nextIdx] = prevblk[nextIdx] ^ g ^ pad
		if o.Query(forgedct, thisblk) {
			fmt.Printf("  ---> Found 0x%02x\n", g)
			return g, true
		}
	}

	// failed to find
	return 0x00, false
}

// DecryptBlk recovers all the plaintext bytes of given ciphertext block
func (o *PaddingOracle) DecryptBlk(prevblk, thisblk []byte) ([]byte, error) {
	fmt.Printf("Decrypt %v - %v\n", prevblk, thisblk)
	var pt []byte
	startg := byte(0x00)
	for {
		if g, ok := o.DiscoverNextByte(prevblk, thisblk, pt, startg); ok {
			pt = append(pt, g)
			startg = byte(0x00)
			fmt.Printf("  ---> Current plaintext: '%s'\n\n", string(reversed(pt)))
		} else {
			// remove the previous guess (if any) and retry. otherwise error
			if len(pt) > 0 {
				startg = pt[len(pt)-1] + 1
				pt = pt[:len(pt)-1]
			} else {
				return []byte{}, errors.New("attack failed")
			}
		}
		if len(pt) == 16 {
			break
		}
	}
	return reversed(pt), nil
}

// Decrypt tries to decrypt the given ciphertext with a padding oracle attack
func (o *PaddingOracle) Decrypt(ct []byte) ([]byte, error) {
	// check len
	if len(ct)%16 != 0 {
		return []byte{}, fmt.Errorf("invalid ciphertext length %d "+
			"(not multiple of block length 16.)",
			len(ct))
	}

	// split in blocks
	pt := make([]byte, len(ct)-16)

	// decrypt
	for blk := 1; blk < (len(ct) / 16); blk++ {
		ptblk, err := o.DecryptBlk(ct[blk*16-16:blk*16], ct[blk*16:blk*16+16])
		if err != nil {
			return []byte{}, err
		}
		copy(pt[blk*16-16:blk*16], ptblk)
	}
	return pt, nil
}

// Disconnect closes the connection to the padding oracle
func (o *PaddingOracle) Disconnect() {
	err := o.serv.Disconnect()
	if err != nil {
		panic(err)
	}
	fmt.Println("Disconnected from padding oracle")
}

func main() {
	// Decode ciphertext string to bytes
	ct, err := hex.DecodeString(CHALLENGESTR)
	if err != nil {
		panic(err)
	}

	// Connect to Oracle server
	po := NewPaddingOracle(HOST, PORT)
	defer po.Disconnect()

	// try to decrypt ciphertext
	pt, err := po.Decrypt(ct)
	if err != nil {
		panic(err)
	}
	// Yay! You get an A. =)
	fmt.Printf("Result: %s\n", string(pt))
}

func reversed(arr []byte) []byte {
	r := make([]byte, len(arr))
	for i := len(arr) - 1; i >= 0; i-- {
		r[len(arr)-1-i] = arr[i]
	}
	return r
}
