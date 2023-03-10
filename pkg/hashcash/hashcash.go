package hashcash

import (
	"bytes"
	"crypto"
	"math/bits"
	"strconv"

	log "github.com/sirupsen/logrus"
)

type Hashcash struct {
	Challenge  []byte
	UniqID     string
	Difficulty int
	HashFunc   crypto.Hash
}

func (h *Hashcash) Compute() ([]byte, uint64, error) {
	log.Debug("start computing hash")
	var nonce uint64
	for {
		// Concatenate the challenge, address, and nonce
		data := append(h.Challenge, []byte(h.UniqID+strconv.FormatUint(nonce, 10))...)

		// Generate the Hash of the data
		hash := h.HashFunc.New()
		hash.Write(data)
		hashValue := hash.Sum(nil)

		// Check if the hash meets the difficulty
		if CheckDifficulty(hashValue, h.Difficulty) {
			log.Debug("finish computing hash")
			return hashValue, nonce, nil
		}
		nonce++
	}
}

func (h *Hashcash) Verify(hashValue []byte, nonce uint64) bool {
	// Concatenate the challenge, recipient, sender, message, and nonce
	data := append(h.Challenge, []byte(h.UniqID+strconv.FormatUint(nonce, 10))...)

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

func NewHashcash(challenge []byte, uniq string, difficulty int, hashFunc crypto.Hash) *Hashcash {
	return &Hashcash{
		Challenge:  challenge,
		UniqID:     uniq,
		Difficulty: difficulty,
		HashFunc:   hashFunc,
	}
}

func CheckDifficulty(hash []byte, difficulty int) bool {
	var zeroes int
	for _, b := range hash {
		z := bits.LeadingZeros8(b)
		zeroes += z
		if z != 8 || zeroes >= difficulty {
			break
		}
	}
	return zeroes > difficulty
}
