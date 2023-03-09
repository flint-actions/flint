// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package ipam

import (
	"fmt"
	"net/netip"
	"sync"
)

type IPAM struct {
	network netip.Prefix
	m       sync.Mutex
	used    []netip.Addr
}

func New(network string) (*IPAM, error) {
	n, err := netip.ParsePrefix(network)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipam invalid network: %w", err)
	}
	return &IPAM{
		network: n,
		used:    make([]netip.Addr, 0),
	}, nil
}

func (p *IPAM) Allocate() netip.Addr {
	p.m.Lock()
	defer p.m.Unlock()
	possibleAddrSlices := p.network.Addr().AsSlice()
	for {
		// TODO: Handle more than 254 ips
		if len(possibleAddrSlices) == 4 {
			possibleAddrSlices[3]++
		} else {
			possibleAddrSlices[15]++
		}
		addr, ok := netip.AddrFromSlice(possibleAddrSlices)
		if !ok {
			panic("could not generate addr form slice")
		}
		// check if is already used
		free := true
		for _, u := range p.used {
			if u == addr {
				free = false
				break
			}
		}
		if free {
			p.used = append(p.used, addr)
			return addr
		}
	}
}

func (p *IPAM) Release(address netip.Addr) {
	p.m.Lock()
	defer p.m.Unlock()
	for i, addr := range p.used {
		if addr == address {
			p.used = append(p.used[:i], p.used[i+1:]...)
			return
		}
	}
}
