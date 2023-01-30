package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	outgoingPort = os.Getenv("OUT_PORT")
	destination  = os.Getenv("DEST")
)

func main() {
	port, err := strconv.Atoi(outgoingPort)
	if err != nil {
		panic(err)
	}
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   nil,
			Port: port,
			Zone: "",
		},
	}
	conn, err := dialer.Dial("tcp", destination)
	if err != nil {
		fmt.Println(err)
		return
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
