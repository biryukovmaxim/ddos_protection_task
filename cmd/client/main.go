package main

import (
	"bufio"
	"crypto"
	_ "crypto/sha256"
	"fmt"
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
		//TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp: true,
	})
	log.SetLevel(log.DebugLevel)
}

func main() {
	challengeResolveFn := func(challengeBts []byte, myAddress string) (hash []byte, nonce uint64, err error) {
		return hashcash.NewHashcash(challengeBts, myAddress, challenge.Difficulty, crypto.SHA256).Compute()
	}
	client := challenge.NewClient(nil, challengeResolveFn)
	conn, err := client.Connect(challengeAddress, destination)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	addr := conn.LocalAddr()
	fmt.Println(addr)
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(message)
}
