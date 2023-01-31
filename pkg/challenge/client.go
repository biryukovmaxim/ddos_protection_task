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

func (c *Client) requestChallenge() ([]byte, string, error) {
	_, err := c.conn.Write(encodeRequestChallenge())
	if err != nil {
		return nil, "", err
	}
	buf := make([]byte, 1024)
	_, err = c.conn.Read(buf)
	if err != nil {
		return nil, "", err
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
	address := (&net.TCPAddr{
		IP:   ip,
		Port: int(port),
	}).String()
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

	hash, nonce, err := c.challengeResolveFn(challenge, myAddress)
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

	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, err
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
