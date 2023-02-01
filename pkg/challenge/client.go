package challenge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type Client struct {
	localAddr          *net.UDPAddr
	conn               *net.UDPConn
	challengeResolveFn func(challenge []byte, myAddress string) (hash []byte, nonce uint64, err error)
}

func NewClient(localAddr *net.UDPAddr, challengeResolveFn func(challenge []byte, myAddress string) (hash []byte, nonce uint64, err error)) *Client {
	return &Client{localAddr: localAddr, challengeResolveFn: challengeResolveFn}
}

func (c *Client) requestChallenge() ([]byte, *net.TCPAddr, error) {
	_, err := c.conn.Write(encodeRequestChallenge())
	if err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 1024)
	_, err = c.conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	reader := bytes.NewReader(buf)
	_, _ = reader.ReadByte()

	challenge := make([]byte, ChallengeSize)
	_, _ = reader.Read(challenge)

	ip := make(net.IP, 4)
	_, _ = reader.Read(ip)
	portBts := make([]byte, 2)
	_, _ = reader.Read(portBts)

	port := binary.BigEndian.Uint16(portBts)
	address := &net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}
	return challenge, address, nil
}

func (c *Client) sendAndCheckSolution(hash []byte, nonce uint64) (success bool, err error) {
	_, err = c.conn.Write(encodeSolution(hash, nonce))
	if err != nil {
		return false, err
	}
	buf := make([]byte, 1024)
	_, err = c.conn.Read(buf)
	if err != nil {
		return false, err
	}
	return buf[1] > 0, nil
}

func (c *Client) Connect(challengeServerAddress, address string) (*net.TCPConn, error) {
	//var err error
	udpServer, err := net.ResolveUDPAddr("udp", challengeServerAddress)
	if err != nil {
		return nil, err
	}

	c.conn, err = net.DialUDP("udp", c.localAddr, udpServer)
	if err != nil {
		return nil, err
	}
	defer c.conn.Close()
	challenge, myAddress, err := c.requestChallenge()
	if err != nil {
		return nil, err
	}

	hash, nonce, err := c.challengeResolveFn(challenge, myAddress.String())
	if err != nil {
		return nil, err
	}
	successful, err := c.sendAndCheckSolution(hash, nonce)
	if err != nil {
		return nil, err
	}
	if !successful {
		return nil, fmt.Errorf("solution is not successful")
	}
	c.conn.Close()
	var conn net.Conn
	for i := 0; i < 20; i++ {
		dialer := net.Dialer{
			Timeout:   3 * time.Second,
			LocalAddr: myAddress,
		}
		time.Sleep(1 * time.Second)
		fmt.Printf("calling tcp from address %s\n", myAddress.String())
		conn, err = dialer.Dial("tcp", address)
		if err != nil {
			continue
		}
		return conn.(*net.TCPConn), nil
	}

	return conn.(*net.TCPConn), nil
}

func encodeRequestChallenge() []byte {
	return []byte{RequestChallengeType}
}
func encodeSolution(hash []byte, nonce uint64) []byte {
	buf := make([]byte, 0, 1+32+8)
	buf = append(buf, SolutionType)
	buf = append(buf, hash...)
	return binary.BigEndian.AppendUint64(buf, nonce)
}
