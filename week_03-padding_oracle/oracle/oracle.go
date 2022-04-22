package oracle

import (
	"fmt"
	"net"
	"strconv"
)

type Server struct {
	conn net.Conn
}

// Connect establishes a connection to the server
func (s *Server) Connect(host, port string) error {
	var err error
	s.conn, err = net.Dial("tcp", host+":"+port)
	return err
}

// Disconnect drops the connection
func (s *Server) Disconnect() error {
	return s.conn.Close()
}

// Sends ciphertext with following packet structure
// < num_blocks(1) || ciphertext(16*num_blocks) || null-terminator(1) >
// Returns the replied int
// (1 for correct padding, 0 for incorrect padding, and -1 for malformed)
func (s *Server) Send(ctext []byte) (int, error) {
	lenct := len(ctext)
	if lenct%16 != 0 {
		return -1, fmt.Errorf("invalid ciphertext length %d "+
			"(not multiple of block length 16.)",
			lenct)
	}
	buf := make([]byte, lenct+2)
	buf[0] = byte(lenct / 16)
	copy(buf[1:len(ctext)+1], ctext)
	buf[len(ctext)+1] = 0x00

	// send data
	_, err := s.conn.Write(buf)
	if err != nil {
		return -1, fmt.Errorf("error writing: %v", err)
	}

	// receive response
	resp := make([]byte, 2)
	_, err = s.conn.Read(resp)
	if err != nil {
		return -1, fmt.Errorf("error reading: %v", err)
	}
	res, err := strconv.Atoi(string(resp[0]))
	if err != nil {
		return -1, fmt.Errorf("error converting: %v", err)
	}
	return res, nil
}
