package hashcash

import (
	"bytes"
	"crypto"
	"strconv"
)

type Data struct {
	Recipient string
	Sender    string
	Message   string
}

type Hashcash struct {
	Challenge  []byte
	Data       Data
	Difficulty int
	HashFunc   crypto.Hash
}

func (h *Hashcash) Compute() ([]byte, int, error) {
	var nonce int
	for {
		// Concatenate the challenge, recipient, sender, message, and nonce
		data := append(h.Challenge, []byte(h.Data.Recipient+h.Data.Sender+h.Data.Message+strconv.Itoa(nonce))...)

		// Generate the Hash of the data
		hash := h.HashFunc.New()
		hash.Write(data)
		hashValue := hash.Sum(nil)

		// Check if the hash meets the difficulty
		if CheckDifficulty(hashValue, h.Difficulty) {
			return hashValue, nonce, nil
		}
		nonce++
	}
}

func (h *Hashcash) Verify(hashValue []byte, nonce int) bool {
	// Concatenate the challenge, recipient, sender, message, and nonce
	data := append(h.Challenge, []byte(h.Data.Recipient+h.Data.Sender+h.Data.Message+strconv.Itoa(nonce))...)

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

func NewHashcash(challenge []byte, data Data, difficulty int, hashFunc crypto.Hash) *Hashcash {
	return &Hashcash{
		Challenge:  challenge,
		Data:       data,
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
