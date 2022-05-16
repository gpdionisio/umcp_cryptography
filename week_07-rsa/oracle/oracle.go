package oracle

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

const (
	MAX_PACKET_LEN = 8192 //nolint
	NOT_BINARY_STR_ERR = -1 //nolint
	MISSING_DELIMITER_ERR = -2 //nolint
	ORIGINAL_MSG_ERR = -3 //nolint
)

type Server struct {
	signSock, vrfySock net.Conn
}

// Connect establishes a connection to the server
func (s *Server) Connect(host, portSign, portVrfy string) error {
	var err error
	s.signSock, err = net.Dial("tcp", host+":"+portSign)
	if err != nil {
		return err
	}
	s.vrfySock, err = net.Dial("tcp", host+":"+portVrfy)
	return err
}

// Disconnect drops the connection
func (s *Server) Disconnect() error {
	err := s.signSock.Close()
	if err != nil {
		return err
	}
	return s.vrfySock.Close()
}

// convert byte data to binary string, represented as bytes
func convToBinStr(m *big.Int) []byte {
	s := m.Text(2)
	return []byte(s)
}

func readSock(sock net.Conn) *big.Int {
	resp := make([]byte, MAX_PACKET_LEN)
	_, err := sock.Read(resp)
	if err != nil {
		panic(fmt.Errorf("error reading: %v", err))
	}
	res := strings.ReplaceAll(string(resp), string(0x00), "")
	i := new(big.Int)
	_, ok := i.SetString(res, 2)
	if !ok {
		// try base two
		_, ok := i.SetString(res, 10)
		if !ok {
			panic(fmt.Errorf("error converting to int: %v", err))
		}
	}
	return i
}

// Sends message (to sign) with following packet structure
// < message || null-terminator("X") >
// Returns signature
func (s *Server) Sign(mess *big.Int) *big.Int {
	messBuf := convToBinStr(mess)
	mlength := len(messBuf)
	buf := make([]byte, len(messBuf)+1)
	copy(buf[0:mlength], messBuf)
	buf[mlength] = byte('X')

	// send data
	_, err := s.signSock.Write(buf)
	if err != nil {
		panic(fmt.Errorf("error writing: %v", err))
	}

	// receive response
	i := readSock(s.signSock)
	if int(i.Int64()) == NOT_BINARY_STR_ERR {
		fmt.Println("[ERR] Message is not a valid binary string")
	}
	if int(i.Int64()) == ORIGINAL_MSG_ERR {
		fmt.Println("[ERR] You cannot request a signature on the original message!")
	}
	return i
}

// Sends message (to verify) with following packet structure
// < message | ":" | signature >
// Returns int check
func (s *Server) Vrfy(mess, sig *big.Int) int {
	messBuf := convToBinStr(mess)
	sigBuf := convToBinStr(sig)
	mlength := len(messBuf)
	slength := len(sigBuf)
	buf := make([]byte, mlength+slength+2)
	buf[0] = byte(mlength)
	copy(buf[0:mlength], messBuf)
	buf[mlength] = byte(':')
	copy(buf[mlength+1:mlength+1+slength], sigBuf)
	buf[mlength+slength+1] = byte('X')

	// send data
	_, err := s.vrfySock.Write(buf)
	if err != nil {
		panic(fmt.Errorf("error writing: %v", err))
	}

	// receive response
	i := int(readSock(s.vrfySock).Int64())
	if i == NOT_BINARY_STR_ERR {
		fmt.Println("[ERR] Message is not a valid binary string")
	}
	if i == MISSING_DELIMITER_ERR {
		fmt.Println("[ERR] Missing delimiter between message and signature")
	}
	return i
}
