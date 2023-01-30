package main

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

func main() {
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP:   nil,
			Port: 43720,
			Zone: "",
		},
	}
	conn, err := dialer.Dial("tcp", "localhost:5051")
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
