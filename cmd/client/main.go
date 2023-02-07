package main

import (
	"bufio"
	"crypto"
	_ "crypto/sha256"
	"os"

	"ddos_protection_task/pkg/challenge"
	"ddos_protection_task/pkg/hashcash"

	log "github.com/sirupsen/logrus"
)

var (
	destination      = os.Getenv("DEST")
	challengeAddress = os.Getenv("CHALLENGE_ADDRESS")
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
	log.SetLevel(log.DebugLevel)
}

func main() {
	challengeResolveFn := func(challengeBts []byte, myAddress *[6]byte) (hash []byte, nonce uint64, err error) {
		return hashcash.NewHashcash(challengeBts, myAddress, challenge.Difficulty, crypto.SHA256).Compute()
	}
	client := challenge.NewClient(nil, challengeResolveFn)
	conn, err := client.Connect(challengeAddress, destination)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	log.Debug("client connected")
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.WithError(err).Fatal("reading message")
		return
	}
	log.Infof("get message: %s", message)
}
