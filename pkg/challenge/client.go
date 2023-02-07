package challenge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

type Client struct {
	localAddr          *net.UDPAddr
	conn               *net.UDPConn
	challengeResolveFn func(challenge []byte, myAddress *[6]byte) (hash []byte, nonce uint64, err error)
}

func NewClient(localAddr *net.UDPAddr, challengeResolveFn func(challenge []byte, myAddress *[6]byte) (hash []byte, nonce uint64, err error)) *Client {
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

	ip := make(net.IP, 4)
	_, _ = reader.Read(ip)
	portBts := make([]byte, 2)
	_, _ = reader.Read(portBts)
	port := binary.BigEndian.Uint16(portBts)

	challenge := make([]byte, ChallengeSize)
	_, _ = reader.Read(challenge)

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

	hash, nonce, err := c.challengeResolveFn(challenge, Convert(myAddress))
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

	dialer := net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: myAddress,
	}
	log.Infof("calling tcp from address %s", myAddress.String())
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
	b := binary.BigEndian.AppendUint64(buf, nonce)
	return b
}

func Convert(addr *net.TCPAddr) *[6]byte {
	var buf []byte
	if len(addr.IP) == 16 {
		buf = addr.IP[12:] // there are 16 bytes, we need only last 4 in case of ipv4
	} else {
		buf = addr.IP[:]
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(addr.Port))
	fixed := (*[6]byte)(buf)

	return fixed
}
