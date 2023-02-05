package verifier

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"net"

	"ddos_protection_task/pkg/hashcash"

	"github.com/orcaman/concurrent-map/v2"
)

type Whitelist interface {
	Insert(addr *net.TCPAddr) error
}

type Service struct {
	randSize   int
	difficulty int
	hashFunc   crypto.Hash
	challenges cmap.ConcurrentMap[string, []byte]
	wl         Whitelist
}

func NewService(randSize int, difficlty int, hashFunc crypto.Hash, wl Whitelist) *Service {
	return &Service{randSize: randSize, difficulty: difficlty, hashFunc: hashFunc, wl: wl, challenges: cmap.New[[]byte]()}
}

func (s *Service) CreateChallenge(socket string) ([]byte, error) {
	challenge := make([]byte, s.randSize)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	s.challenges.Set(socket, challenge)

	return challenge, nil
}

func (s *Service) CheckSolution(addr net.UDPAddr, hash []byte, nonce uint64) (bool, error) {
	challenge, exist := s.challenges.Get(addr.String())
	if !exist {
		return false, fmt.Errorf("challenge for %q not found", addr.String())
	}
	hk := hashcash.NewHashcash(challenge, addr.String(), s.difficulty, s.hashFunc)
	successful := hk.Verify(hash, nonce)
	if !successful {
		return false, nil
	}
	tcp := &net.TCPAddr{
		IP:   addr.IP,
		Port: addr.Port,
		Zone: addr.Zone,
	}
	if err := s.wl.Insert(tcp); err != nil {
		return false, err
	}

	s.challenges.Remove(addr.String())

	return true, nil
}
