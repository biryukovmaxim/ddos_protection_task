package bpf_map_adapter

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
)

type Adapter struct {
	m *ebpf.Map
}

func NewAdapter(Map *ebpf.Map) *Adapter {
	return &Adapter{m: Map}
}

func (a *Adapter) Insert(addr *net.TCPAddr) error {
	v := [4]byte{1, 0, 0, 0}

	return a.m.Put(*convert(addr), v)
}

func (a *Adapter) Delete(addr *net.TCPAddr) error {
	return a.m.Delete(*convert(addr))
}

func convert(addr *net.TCPAddr) *[8]byte {
	var buf []byte
	if len(addr.IP) == 16 {
		buf = addr.IP[12:] // there are 16 bytes, we need only last 4 in case of ipv4
	} else {
		buf = addr.IP[:]
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(addr.Port))
	buf = binary.BigEndian.AppendUint16(buf, 0)
	fixed := (*[8]byte)(buf)

	return fixed
}
