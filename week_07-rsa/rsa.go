package main

import (
	"fmt"
	"math/big"
	"w7_assign/oracle"
)

// The scheme works as follows: the public key is a standard RSA public key
// (N, e), and the private key is the usual (N, d), where N is a 128-byte
// (1024-bit) integer. To sign a message m of length exactly 63 bytes,
// set [M = 0x00 m 0x00 m] and then compute the signature M^d mod N.
// If m is shorter than 63 bytes, 0-bytes are first preprended to make its
// length exactly 63 bytes.

const (
	HOST = "128.8.130.16" //nolint
	SIGN_ORACLE_PORT = "49104" //nolint
	VRFY_ORACLE_PORT = "49105" //nolint

	// Public key
	N_HEX = "a99263f5cd9a6c3d93411fbf682859a07b5e41c38abade2a551798e6c8af5af0"+ //nolint
            "8dee5c7420c99f0f3372e8f2bfc4d0c85115b45a0abc540349bf08b251a80b85"+
            "975214248dffe57095248d1c7e375125c1da25227926c99a5ba4432dfcfdae3"+
            "00b795f1764af043e7c1a8e070f5229a4cbc6c5680ff2cd6fa1d62d39faf3d41d"
	e_HEX = "10001" //nolint

	// Challenge text
	M = "Crypto is hard --- even schemes that look complex can be broken" //nolint


)

type RsaOracle struct {
	oracle.Server
}

func NewMacOracle(host, macPort, vrfyPort string) *RsaOracle {
	var o RsaOracle
	err := o.Connect(host, macPort, vrfyPort)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to server at %s:[%s/%s]\n",
		host, macPort, vrfyPort)
	return &o
}

func (o *RsaOracle) Disconnect() {
	err := o.Server.Disconnect()
	if err != nil {
		panic(err)
	}
	fmt.Println("Disconnected from rsa oracle")
}

func main() {
	o := NewMacOracle(HOST, SIGN_ORACLE_PORT, VRFY_ORACLE_PORT)
	defer o.Disconnect()

	N := new(big.Int)
	N.SetString(N_HEX, 16)
	e := new(big.Int)
	e.SetString(e_HEX, 16)
	chall := new(big.Int).SetBytes([]byte(M))

	fmt.Printf("N = %s\n", N.Text(10))
	fmt.Printf("e = %s\n", e.Text(10))
	fmt.Printf("chall = %s\n", chall.Text(10))

	// try oracle
	m := big.NewInt(5)
	sig := o.Sign(m)
	if o.Vrfy(m, sig) == 1 &&
	   o.Vrfy(big.NewInt(6), sig) == 0 &&
	   o.Vrfy(m, big.NewInt(5)) == 0 &&
	   int(o.Sign(chall).Int64()) == -3 {
		fmt.Println("Oracle working and ready to go!")
	}

	One := big.NewInt(1)
	Two := big.NewInt(2)

	// Idea:
	// Sig(1) = (2^512 + 1)^d (mod N)
	sig1 := o.Sign(One)
	x := new(big.Int).Exp(sig1, e, N)
	pow2 := new(big.Int).Exp(Two, big.NewInt(512), N)
	pow2.Mod(pow2.Add(pow2, One), N)
	if x.Cmp(pow2) != 0 {
		panic("sig1 != (2^512 + 1)^d (mod N)")
	}
	// Sig(2) = (2^512 + 1)^d 2^d (mod N)
	sig2 := o.Sign(Two)
	x = new(big.Int).Exp(sig2, e, N)
	pow2 = new(big.Int).Exp(Two, big.NewInt(513), N)
	pow2.Mod(pow2.Add(pow2, Two), N)
	if x.Cmp(pow2) != 0 {
		panic("sig2 != (2^512 + 1)^d 2^d (mod N)")
	}
	// Sig(1)^{-1} * Sig(2) = 2^d (mod N)
	inv := new(big.Int).ModInverse(sig1, N)
	twoToD := new(big.Int).Mul(inv, sig2)
	twoToD.Mod(twoToD, N)
	y := new(big.Int).Exp(twoToD, e, N)
	if y.Cmp(Two) != 0 {
		panic("(sig1)^{-1} * sig2 != 2^d (mod N)")
	}
	// Sig(m/2) = Sig(1) * (m/2)^d
	m2 := new(big.Int).Div(chall, Two)
	sig3 := o.Sign(m2)
	prod := new(big.Int).Mul(inv, sig3)
	prod.Mod(prod, N)
	y.Exp(prod, e, N)
	if y.Cmp(m2) != 0 {
		panic("(sig1)^{-1} * sig3 != (m/2)^d (mod N)")
	}
	// Sig(m/2) * 2^d = Sign(m)
	final := new(big.Int).Mul(sig3, twoToD)
	final.Mod(final, N)
	fmt.Println(o.Vrfy(chall, final))
}
