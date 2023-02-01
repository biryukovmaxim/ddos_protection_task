package challenge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	requestTypeSize = 1
	hashSize        = 32
	nonceSize       = 8
)

type Verifier interface {
	CreateChallenge(socket string) ([]byte, error)
	CheckSolution(addr net.UDPAddr, hash []byte, nonce uint64) (bool, error)
}

type Server struct {
	verifier Verifier
}

func NewServer(verifier Verifier) *Server {
	return &Server{verifier: verifier}
}

func (s *Server) ProcessRequest(addr net.UDPAddr, frame []byte) ([]byte, error) {
	socket := addr.String()
	reqType, reqI, err := DecodePacket(frame)
	if err != nil {
		return nil, err
	}

	switch reqType {
	case RequestChallengeType:
		challenge, err := s.verifier.CreateChallenge(socket)
		if err != nil {
			return nil, err
		}
		return encodeChallenge(challenge, addr), nil
	case SolutionType:
		req := reqI.(Solution)
		solution, err := s.verifier.CheckSolution(addr, req.Hash, req.Nonce)
		if err != nil {
			return nil, err
		}
		return encodeSolutionCheck(solution), nil
	default:
		return nil, fmt.Errorf("unknown request type, %d", reqType)
	}
}

func DecodePacket(buf []byte) (RequestType, any, error) {
	if len(buf) == 0 {
		return 0, nil, fmt.Errorf("empty buf")
	}
	reader := bytes.NewReader(buf)
	typeByte, _ := reader.ReadByte()
	switch typeByte {
	case RequestChallengeType:
		return RequestChallengeType, nil, nil
	case SolutionType:
		body := buf[requestTypeSize:]
		if len(body) < hashSize+nonceSize {
			return 0, nil, fmt.Errorf("bad request")
		}
		hash := make([]byte, hashSize)
		_, _ = reader.Read(hash)
		nonceBts := make([]byte, 8)
		_, _ = reader.Read(nonceBts)
		nonce := binary.BigEndian.Uint64(nonceBts)
		return SolutionType, Solution{
			Hash:  hash,
			Nonce: nonce,
		}, nil
	default:
		return 0, nil, fmt.Errorf("unknown request type")
	}
}

func encodeChallenge(challenge []byte, addr net.UDPAddr) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 15))

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(addr.Port))

	buf.WriteByte(SendChallengeType)
	buf.Write(challenge)
	buf.Write(addr.IP[12:16])
	buf.Write(portBytes)

	return buf.Bytes()
}

func encodeSolutionCheck(successful bool) []byte {
	var body byte
	if successful {
		body = 1
	} else {
		body = 0
	}
	return []byte{ConfirmationType, body}
}
