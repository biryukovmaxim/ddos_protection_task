package challenge

import (
	"bufio"
	"encoding/binary"
	"io"
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

	reader := bufio.NewReader(c.conn)
	_, err = reader.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	challenge := make([]byte, ChallengeSize)
	_, err = reader.Read(challenge)
	if err != nil {
		return nil, nil, err
	}
	ip := make(net.IP, 4)
	_, err = reader.Read(ip)
	if err != nil {
		return nil, nil, err
	}
	portBts := make([]byte, 2)
	_, err = reader.Read(portBts)
	if err != nil {
		return nil, nil, err
	}
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
	n := 0
	buf := make([]byte, 2)
	for n < 2 {
		newN, err := c.conn.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		n += newN
	}

	return buf[1] > 0, nil
}

func (c *Client) Connect(challengeServerAddress, address string) (*net.TCPConn, error) {
	var err error
	//_, err := net.ResolveUDPAddr("udp", challengeServerAddress)
	//if err != nil {
	//	return nil, err
	//}
	//
	//c.conn, err = net.DialUDP("udp", c.localAddr, udpServer)
	//if err != nil {
	//	return nil, err
	//}
	//defer c.conn.Close()
	//challenge, myAddress, err := c.requestChallenge()
	//if err != nil {
	//	return nil, err
	//}
	//
	//hash, nonce, err := c.challengeResolveFn(challenge, myAddress.String())
	//if err != nil {
	//	return nil, err
	//}
	//successful, err := c.sendAndCheckSolution(hash, nonce)
	//if err != nil {
	//	return nil, err
	//}
	//if !successful {
	//	return nil, fmt.Errorf("solution is not successful")
	//}
	//c.conn.Close()

	dialer := net.Dialer{
		Timeout: 3 * time.Second,
		//LocalAddr: myAddress,
	}
	//log.Infof("calling tcp from address %s", myAddress.String())
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
