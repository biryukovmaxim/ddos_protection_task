package challenge

import (
	"encoding/binary"
	"fmt"
)

const (
	requestTypeSize = 1
	hashSize        = 32
	nonceSize       = 8
)

type Verifier interface {
	CreateChallenge(socket string) ([]byte, error)
	CheckSolution(socket string, hash []byte, nonce uint64) (bool, error)
}

type Server struct {
	verifier Verifier
}

func NewServer(verifier Verifier) *Server {
	return &Server{verifier: verifier}
}

func (s *Server) ProcessRequest(socket string, frame []byte) ([]byte, error) {
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
		return encodeChallenge(challenge), nil
	case SolutionType:
		req := reqI.(Solution)
		solution, err := s.verifier.CheckSolution(socket, req.Hash, req.Nonce)
		if err != nil {
			return nil, err
		}
		return encodeSolutionCheck(solution), nil
	default:
		return nil, fmt.Errorf("unknown request type, %d", reqType)
	}
}

func encodeChallenge(challenge []byte) []byte {
	return append([]byte{SendChallengeType}, challenge...)
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

func DecodePacket(buf []byte) (RequestType, any, error) {
	if len(buf) == 0 {
		return 0, nil, fmt.Errorf("empty buf")
	}
	switch buf[0] {
	case RequestChallengeType:
		return RequestChallengeType, nil, nil
	case SolutionType:
		body := buf[requestTypeSize:]
		if len(body) != hashSize+nonceSize {
			return 0, nil, fmt.Errorf("bad request")
		}
		hash := body[:hashSize+1]
		nonce := binary.BigEndian.Uint64(body[hashSize+1:])
		return SolutionType, Solution{
			Hash:  hash,
			Nonce: nonce,
		}, nil
	default:
		return 0, nil, fmt.Errorf("unknown request type")
	}
}
