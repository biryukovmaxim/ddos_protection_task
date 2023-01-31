package main

import (
	_ "crypto"
	_ "crypto/sha256"
	"fmt"
	"net"
	"os"
	_ "sync"

	_ "ddos_protection_task/internal/verifier"
	_ "ddos_protection_task/pkg/challenge"

	goebpf "github.com/cilium/ebpf"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var (
	pathToElf = os.Getenv("ELF_PATH")
)

func init() {
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
	log.SetLevel(log.DebugLevel)
}

func main() {
	//inerfaces, err := net.Interfaces()
	//if err != nil {
	//	log.WithError(err).Fatal("getting net interfaces")
	//}
	//log.Debugf("%+v", inerfaces)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.WithError(err).Error("set rlimit")
	}
	collection, err := goebpf.LoadCollection(pathToElf)
	if err != nil {
		panic(err)
	}
	collection.Close()
	//xdp := bpf.XDPProgram("outer_firewall")
	//if err := xdp.Load(); err != nil {
	//	log.Fatalf("xdp.Load(): %v", err)
	//}
	//whitelist := bpf.GetMapByName("WHITE_LIST")
	//defer whitelist.Close()
	//// Attach to interface
	//if err := xdp.Attach("lo"); err != nil {
	//	log.Fatalf("xdp.Attach(): %v", err)
	//}
	//defer xdp.Detach()

	//listener, err := net.Listen("tcp", "localhost:5051")
	//if err != nil {
	//	log.WithError(err).Fatalf("start listeing")
	//}
	//defer listener.Close()
	//
	//wg := &sync.WaitGroup{}
	//wg.Add(1)
	//log.Info("start listening incoming tcp conns")
	//go func() {
	//	defer wg.Done()
	//	for {
	//		conn, err := listener.Accept()
	//		if err != nil {
	//			log.WithError(err).Warn("accepting incoming conn")
	//			continue
	//		}
	//		go handleRequest(conn)
	//	}
	//}()
	//
	//vf := verifier.NewService(challenge.ChallengeSize, challenge.Difficulty, crypto.SHA256, MockMap{map[interface{}]interface{}{}})
	//server := challenge.NewServer(vf)
	//udpServer, err := net.ListenPacket("udp", ":1053")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer udpServer.Close()
	//log.Info("start listening incoming udp frames")
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	for {
	//		buf := make([]byte, 1024)
	//		_, addr, err := udpServer.ReadFrom(buf)
	//		if err != nil {
	//			continue
	//		}
	//		go func(buf []byte, addr net.Addr) {
	//			resp, err := server.ProcessRequest(addr.(*net.UDPAddr), buf)
	//			if err != nil {
	//				log.WithError(err).Error("processing udp request")
	//				return
	//			}
	//			_, err = udpServer.WriteTo(resp, addr)
	//			if err != nil {
	//				log.WithError(err).Error("sending udp response")
	//			}
	//
	//		}(buf, addr)
	//	}
	//}()
	//wg.Wait()
}

func handleRequest(conn net.Conn) {
	defer conn.Close()
	log.Debug("new tcp connection")
	remoteAddr := conn.RemoteAddr().String()
	log.Debug(remoteAddr)
	fmt.Fprintln(conn, "Hello, World!")
}

type MockMap struct {
	storage map[interface{}]interface{}
}

func (m MockMap) Insert(i interface{}, i2 interface{}) error {
	m.storage[i] = i2
	return nil
}
