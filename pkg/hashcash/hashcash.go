package hashcash

import (
	"bytes"
	"crypto"
	"encoding/binary"

	log "github.com/sirupsen/logrus"
)

type Hashcash struct {
	Challenge  []byte
	UniqID     *[6]byte
	Difficulty int
	HashFunc   crypto.Hash
}

func (h *Hashcash) Compute() ([]byte, uint64, error) {
	log.Debug("start computing hash")
	var nonce uint64
	for {
		// Concatenate the challenge, address and nonce
		data1 := append(h.Challenge, h.UniqID[:]...)
		data2 := binary.BigEndian.AppendUint64(data1, nonce)
		// Generate the Hash of the data
		hash := h.HashFunc.New()
		hash.Write(data2)
		hashValue := hash.Sum(nil)

		// Check if the hash meets the difficulty
		if CheckDifficulty(hashValue, h.Difficulty) {
			log.Debug("finish computing hash")
			log.Debugf("uniq before nonce: %+v", h.UniqID[:])

			log.Debugf("%+v", data2)
			return hashValue, nonce, nil
		}
		nonce++
	}
}

func (h *Hashcash) Verify(hashValue []byte, nonce uint64) bool {
	// Concatenate the challenge, recipient, sender, message, and nonce
	data := append(h.Challenge, h.UniqID[:]...)
	log.Debugf("data before nonce: %+v", data)

	data = binary.BigEndian.AppendUint64(data, nonce)
	log.Debugf("after: %+v", data)
	// Generate the Hash of the data
	hash := h.HashFunc.New()
	hash.Write(data)
	newHashValue := hash.Sum(nil)

	// Compare the stored hash with the newly generated hash
	if !bytes.Equal(hashValue, newHashValue) {
		return false
	}

	// Check if the hash meets the difficulty
	if !CheckDifficulty(newHashValue, h.Difficulty) {
		return false
	}
	return true
}

func NewHashcash(challenge []byte, uniq *[6]byte, difficulty int, hashFunc crypto.Hash) *Hashcash {
	return &Hashcash{
		Challenge:  challenge,
		UniqID:     uniq,
		Difficulty: difficulty,
		HashFunc:   hashFunc,
	}
}

func CheckDifficulty(hash []byte, difficulty int) bool {
	for i := 0; i < len(hash); i++ {
		for j := 7; j >= 0; j-- {
			if (hash[i]>>uint(j))&1 != 0 {
				return difficulty <= 8*i+7-j
			}
		}
	}
	return true
}
