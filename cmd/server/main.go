package main

import (
	"crypto"
	_ "crypto/sha256"
	"fmt"
	"math/rand"
	"net"
	"sync"

	"ddos_protection_task/bpf/xdp_firewall"
	"ddos_protection_task/internal/bpf_map_adapter"
	"ddos_protection_task/internal/verifier"
	"ddos_protection_task/pkg/challenge"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

var Quotes = []string{
	"All saints who remember to keep and do these sayings, " +
		"walking in obedience to the commandments, " +
		"shall receive health in their navel and marrow to their bones",

	"And shall find wisdom and great treasures of knowledge, even hidden treasures",

	"And shall run and not be weary, and shall walk and not faint",

	"And I, the Lord, give unto them a promise, " +
		"that the destroying angel shall pass by them, " +
		"as the children of Israel, and not slay them",
}

func init() {
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
	log.SetLevel(log.DebugLevel)
}

type FirewallEbpfProgram interface {
	Whitelist() (*ebpf.Map, error)
	Program() (*ebpf.Program, error)
	Close() error
}

func main() {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		log.WithError(err).Panicf("lookup network iface %q", "lo")
	}
	inerfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Panic("getting net interfaces")
	}
	log.Debugf("%+v", inerfaces)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Panic("set rlimit")
	}
	var (
		firewall FirewallEbpfProgram
	)
	firewall, err = xdp_firewall.NewFirewallProgram()
	if err != nil {
		log.WithError(err).Panicf("loading bpf program")
	}
	defer firewall.Close()

	whitelist, err := firewall.Whitelist()
	if err != nil {
		log.WithError(err).Panicf("loading whitelist map")
	}
	defer whitelist.Close()
	program, err := firewall.Program()
	if err != nil {
		log.WithError(err).Panicf("loading program")
	}
	defer program.Close()
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Index,
	})
	if err != nil {
		log.WithError(err).Panicf("link program")
	}
	defer l.Close()

	listener, err := net.Listen("tcp", "localhost:5051")
	if err != nil {
		log.WithError(err).Panicf("start listeing")
	}
	defer listener.Close()

	//go debugMap(whitelist)
	whitelistAdapter := bpf_map_adapter.NewAdapter(whitelist)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	log.Info("start listening incoming tcp conns")
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.WithError(err).Warn("accepting incoming conn")
				continue
			}
			go handleRequest(conn, whitelistAdapter)
		}
	}()

	vf := verifier.NewService(challenge.ChallengeSize, challenge.Difficulty, crypto.SHA256, whitelistAdapter)
	server := challenge.NewServer(vf)
	udpServer, err := net.ListenPacket("udp", ":1053")
	if err != nil {
		log.Panic(err)
	}
	defer udpServer.Close()
	log.Info("start listening incoming udp frames")
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf := make([]byte, 1024)
			_, addrI, err := udpServer.ReadFrom(buf)
			if err != nil {
				continue
			}
			addr := addrI.(*net.UDPAddr)
			func(buf []byte, addr net.UDPAddr) {
				// todo addr overrided by process request
				addr2, _ := net.ResolveUDPAddr("udp4", addr.String())
				resp, err := server.ProcessRequest(addr, buf)
				if err != nil {
					log.WithError(err).Error("processing udp request")
					return
				}
				_, err = udpServer.WriteTo(resp, addr2)
				if err != nil {
					log.WithError(err).Error("sending udp response")
				}
			}(buf, *addr)
		}
	}()
	wg.Wait()
}

func handleRequest(conn net.Conn, p *bpf_map_adapter.Adapter) {
	defer conn.Close()
	defer func(p *bpf_map_adapter.Adapter, addr *net.TCPAddr) {
		err := p.Delete(addr)
		if err != nil {
			log.WithError(err).Error("delete from whitelist map")
		}
	}(p, conn.RemoteAddr().(*net.TCPAddr))

	log.Debug("new tcp connection")
	remoteAddr := conn.RemoteAddr().String()
	log.Debug(remoteAddr)
	fmt.Fprintln(conn, Quotes[rand.Intn(4)])
}

//
//func debugMap(p *ebpf.Map) {
//	for {
//		iterator := p.Iterate()
//		var (
//			key   [8]byte
//			value uint32
//		)
//
//		for iterator.Next(&key, &value) {
//			reader := bytes.NewReader(key[:])
//			ip := make([]byte, 4)
//			reader.Read(ip)
//			portBts := make([]byte, 2)
//			reader.Read(portBts)
//			lport := binary.LittleEndian.Uint16(portBts)
//
//			log.Debugf("ip: %s, leport: %d, value: %d", net.IP(ip).String(), lport, value)
//
//		}
//		time.Sleep(1 * time.Second)
//	}
//}
