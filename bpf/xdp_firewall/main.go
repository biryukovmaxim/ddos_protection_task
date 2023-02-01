// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package xdp_firewall

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp_firewall.c -- -I../headers

type FirewallProgram struct {
	bpfObjects
	isLoad bool
}

func NewFirewallProgram() (*FirewallProgram, error) {
	fp := FirewallProgram{isLoad: true}
	if err := loadBpfObjects(&fp.bpfObjects, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}
	return &fp, nil
}

func (p FirewallProgram) Program() (*ebpf.Program, error) {
	if !p.isLoad {
		return nil, fmt.Errorf("program is not loaded yet")
	}
	return p.bpfObjects.bpfPrograms.TcpFirewall, nil
}
func (p FirewallProgram) Whitelist() (*ebpf.Map, error) {
	if !p.isLoad {
		return nil, fmt.Errorf("program is not loaded yet")
	}
	return p.bpfObjects.Whitelist, nil
}
