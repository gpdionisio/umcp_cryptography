package oracle

import (
	"fmt"
	"net"
	"strconv"
)

type Server struct {
	macSock, vrfySock net.Conn
}

// Connect establishes a connection to the server
func (s *Server) Connect(host, portMac, portVrfy string) error {
	var err error
	s.macSock, err = net.Dial("tcp", host+":"+portMac)
	if err != nil {
		return err
	}
	s.vrfySock, err = net.Dial("tcp", host+":"+portVrfy)
	return err
}

// Disconnect drops the connection
func (s *Server) Disconnect() error {
	err := s.macSock.Close()
	if err != nil {
		return err
	}
	return s.vrfySock.Close()
}

// Sends message (to mac) with following packet structure
// < mlength(1) || message(mlength) || null-terminator(1) >
// Returns tag
func (s *Server) Mac(mess []byte) ([]byte, error) {
	mlength := len(mess)
	if mlength != 32 {
		return []byte{}, fmt.Errorf("invalid message length %d "+
			"(this oracle macs 2 blocks = 32 bytes)",
			mlength)
	}
	buf := make([]byte, mlength+2)
	buf[0] = byte(mlength)
	copy(buf[1:mlength+1], mess)
	buf[mlength+1] = 0x00

	// send data
	_, err := s.macSock.Write(buf)
	if err != nil {
		return []byte{}, fmt.Errorf("error writing: %v", err)
	}

	// receive response
	resp := make([]byte, 16)
	l, err := s.macSock.Read(resp)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading: %v", err)
	}
	if l != 16 {
		return []byte{}, fmt.Errorf("invalid reply len: %d", l)
	}
	return resp, nil
}

// Sends message (to verify) with following packet structure
// < mlength(1) || message(mlength) || tag(16) || null-terminator(1) >
// Returns tag
func (s *Server) Vrfy(mess, tag []byte) (int, error) {
	mlength := len(mess)
	if mlength%16 != 0 {
		return -1, fmt.Errorf("invalid message length %d "+
			"(must be a multiple of the block size 16)",
			mlength)
	}
	if len(tag) != 16 {
		return -1, fmt.Errorf("invalid tag length %d "+
			"(must be exactlt one block = 16 bytes)",
			len(tag))
	}
	buf := make([]byte, mlength+2+16)
	buf[0] = byte(mlength)
	copy(buf[1:mlength+1], mess)
	copy(buf[mlength+1:mlength+1+16], tag)
	buf[mlength+1+16] = 0x00

	// send data
	_, err := s.vrfySock.Write(buf)
	if err != nil {
		return -1, fmt.Errorf("error writing: %v", err)
	}

	// receive response
	resp := make([]byte, 2)
	_, err = s.vrfySock.Read(resp)
	if err != nil {
		return -1, fmt.Errorf("error reading: %v", err)
	}
	res, err := strconv.Atoi(string(resp[0]))
	if err != nil {
		return -1, fmt.Errorf("error converting: %v", err)
	}
	return res, nil
}
