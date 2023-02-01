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
	return a.m.Put(*convert(addr), [4]byte{})
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
	buf = binary.BigEndian.AppendUint16(buf, HostToNetShort(uint16(addr.Port)))
	buf = binary.BigEndian.AppendUint16(buf, 0)
	fixed := (*[8]byte)(buf)

	return fixed
}

func HostToNetLong(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}
