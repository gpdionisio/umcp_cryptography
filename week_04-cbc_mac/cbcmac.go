package main

import (
	"fmt"
	"w4_assign/oracle"
)

const (
	HOST = "128.8.130.16" //nolint
	MAC_ORACLE_PORT = "49102" //nolint
	VRFY_ORACLE_PORT = "49103" //nolint

	CHALLENGETAG = "I, the server, hereby agree that I will pay $100 to this student"
)

type MacOracle struct {
	oracle.Server
}

func NewMacOracle(host, macPort, vrfyPort string) *MacOracle {
	var o MacOracle
	err := o.Connect(host, macPort, vrfyPort)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to server at %s:[%s/%s]\n",
		host, macPort, vrfyPort)
	return &o
}

func (o *MacOracle) Disconnect() {
	err := o.Server.Disconnect()
	if err != nil {
		panic(err)
	}
	fmt.Println("Disconnected from mac oracle")
}

// Mac queries the server for the tag of a given message
func (o *MacOracle) Mac(mess []byte) []byte {
	res, err := o.Server.Mac(mess)
	if err != nil {
		panic(err)
	}
	return res
}

// Vrfy queries the server to check if a given (mess, tag)-pair is valid
func (o *MacOracle) Vrfy(mess, tag []byte) bool {
	res, err := o.Server.Vrfy(mess, tag)
	if err != nil {
		panic(err)
	}
	return res == 1
}

func main() {
	o := NewMacOracle(HOST, MAC_ORACLE_PORT, VRFY_ORACLE_PORT)
	defer o.Disconnect()

	// divide challenge text in (4) blocks
	challenge := []byte(CHALLENGETAG)
	if len(challenge)%16 != 0 {
		panic(fmt.Sprintf("Challenge not padded. Len=%d", len(challenge)))
	}
	nBlocks := len(challenge) / 16 // 4
	blocks := make([][]byte, nBlocks)
	for i := 0; i < nBlocks; i++ {
		blocks[i] = challenge[i*16 : i*16+16]
	}

	// mac the first two blocks
	var buf [32]byte
	for i := 0; i < 32; i++ {
		buf[i] = blocks[i/16][i%16]
	}
	tag := o.Mac(buf[:])

	// xor the tag with the third block
	for i := range blocks[2] {
		blocks[2][i] ^= tag[i]
	}

	// send the other two blocks after xoring the first with the tag
	for i := 0; i < 16; i++ {
		buf[i] = blocks[2][i] ^ tag[i]
		buf[16+i] = blocks[3][i]
	}
	tag = o.Mac(buf[:])

	// check the tag against full challenge
	fmt.Println(o.Vrfy(challenge, tag))
}
