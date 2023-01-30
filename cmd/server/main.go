package main

import (
	"fmt"
	"net"
	"os"

	"github.com/dropbox/goebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var pathToElf = os.Getenv("ELF_PATH")

func init() {
	log.SetFormatter(&log.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
	log.SetLevel(log.DebugLevel)
}

func main() {
	inerfaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Fatal("getting net interfaces")
	}
	log.Debugf("%+v", inerfaces)
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.WithError(err).Error("set rlimit")
	}
	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.LoadElf(pathToElf); err != nil {
		log.WithError(err).Error("load elf")
	}
	xdp := bpf.GetProgramByName("outer_firewall")
	if err := xdp.Load(); err != nil {
		log.Fatalf("xdp.Load(): %v", err)
	}
	// Attach to interface
	if err := xdp.Attach("lo"); err != nil {
		log.Fatalf("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()
	listener, err := net.Listen("tcp", ":5051")
	if err != nil {
		log.WithError(err).Fatalf("start listeing")
	}
	defer listener.Close()
	log.Info("start listening incoming conns")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.WithError(err).Warn("accepting incoming conn")
			continue
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()
	log.Debug("new connection")
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	interfaceName, ipnet, _ := net.ParseCIDR(remoteAddr.IP.String() + "/32")
	log.Debug("Incoming connection from ", remoteAddr, "on interface, ipnet ", interfaceName, " ", ipnet)
	fmt.Fprintln(conn, "Hello, World!")
}
