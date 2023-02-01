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
	var (
		successful  bool
		notFound    bool
		insertedErr error
	)

	s.challenges.RemoveCb(addr.String(), func(key string, challenge []byte, exists bool) bool {
		if !exists {
			notFound = true
			return false
		}
		hk := hashcash.NewHashcash(challenge, addr.String(), s.difficulty, s.hashFunc)
		successful = hk.Verify(hash, nonce)
		tcp := &net.TCPAddr{
			IP:   addr.IP,
			Port: addr.Port,
			Zone: addr.Zone,
		}
		insertedErr = s.wl.Insert(tcp)
		if insertedErr != nil {
			return false
		}
		return successful
	})
	if notFound {
		return false, fmt.Errorf("challenge for %q not found", addr.String())
	}
	if insertedErr != nil {
		return false, insertedErr
	}
	return successful, nil
}
