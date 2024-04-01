package network

import (
	"net/netip"
	"sync"

	"golang.org/x/exp/slices"
)

type Network struct {
	Name     string
	prefixV4 netip.Prefix
	prefixV6 netip.Prefix

	m    sync.Mutex
	used []netip.Addr
}

func New(name string, prefixV4 string, prefixV6 string) *Network {
	network := &Network{
		Name:     name,
		m:        sync.Mutex{},
		prefixV4: netip.MustParsePrefix(prefixV4),
		used:     make([]netip.Addr, 0),
	}
	if prefixV6 != "" {
		var err error
		network.prefixV6, err = netip.ParsePrefix(prefixV6)
		if err != nil {
			panic("invalid ipv6 prefix specified")
		}
	}
	return network
}

type AddressVersion int

const (
	IPv4 AddressVersion = iota
	IPv6
)

func (n *Network) Allocate(addressVersion AddressVersion) netip.Addr {
	n.m.Lock()
	defer n.m.Unlock()

	zeroIP := netip.Addr{}
	ip := netip.Addr{}
	prefix := n.prefixV4
	if addressVersion == IPv6 {
		prefix = n.prefixV6
	}
	for ip = prefix.Addr().Next(); ip != zeroIP; ip = ip.Next() {
		if !slices.Contains(n.used, ip) {
			n.used = append(n.used, ip)
			break
		}
	}

	return ip
}

func (n *Network) Release(addr netip.Addr) {
	n.m.Lock()
	defer n.m.Unlock()

	index := slices.Index(n.used, addr)
	if index != -1 {
		slices.Delete(n.used, index, index+1)
	}
}

func (n *Network) Enabled(addressVersion AddressVersion) bool {
	zeroPrefix := netip.Prefix{}
	if addressVersion == IPv4 && n.prefixV4 != zeroPrefix {
		return true
	}
	if addressVersion == IPv6 && n.prefixV6 != zeroPrefix {
		return true
	}
	return false
}

func (n *Network) Address(addressVersion AddressVersion) netip.Addr {
	if addressVersion == IPv4 {
		return n.prefixV4.Addr()
	}
	return n.prefixV6.Addr()
}
