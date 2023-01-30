package verifier

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"ddos_protection_task/pkg/hashcash"

	"github.com/orcaman/concurrent-map/v2"
)

type Whitelist interface {
	Insert(interface{}, interface{}) error
}

type Service struct {
	randSize   int
	difficulty int
	hashFunc   crypto.Hash
	challenges cmap.ConcurrentMap[string, []byte]
	wl         Whitelist
}

func NewService(randSize int, difficlty int, hashFunc crypto.Hash, wl Whitelist) *Service {
	return &Service{randSize: randSize, difficulty: difficlty, hashFunc: hashFunc, wl: wl}
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

func (s *Service) CheckSolution(socket string, hash []byte, nonce uint64) (bool, error) {
	var (
		successful  bool
		notFound    bool
		insertedErr error
	)

	s.challenges.RemoveCb(socket, func(key string, challenge []byte, exists bool) bool {
		if !exists {
			notFound = true
			return false
		}
		hk := hashcash.NewHashcash(challenge, socket, s.difficulty, s.hashFunc)
		successful = hk.Verify(hash, nonce)

		insertedErr = s.wl.Insert(socket, struct{}{})
		if insertedErr != nil {
			return false
		}
		return successful
	})
	if notFound {
		return false, fmt.Errorf("challenge for %q not found", socket)
	}
	if insertedErr != nil {
		return false, insertedErr
	}
	return successful, nil
}
