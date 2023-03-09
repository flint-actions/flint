// Copyright 2023 Tobias Kohlbau
// SPDX-License-Identifier: Apache-2.0

package ipam_test

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/tobiaskohlbau/flint/pkg/ipam"
)

func TestAllocate(t *testing.T) {
	pool, err := ipam.New("10.0.0.0/24")
	if err != nil {
		t.Errorf("should parse valid ip")
	}

	for i := 1; i <= 254; i++ {
		expect, err := netip.ParseAddr("10.0.0." + strconv.Itoa(i))
		if err != nil {
			t.Errorf("got unexpected error: %v", err)
		}
		got := pool.Allocate()
		if got != expect {
			t.Errorf("got %s expect %s", got, expect)
		}
	}

	pool, err = ipam.New("fe80::/64")
	if err != nil {
		t.Errorf("should parse valid network")
	}

	for i := 1; i <= 254; i++ {
		expect, err := netip.ParseAddr("fe80::" + strconv.FormatInt(int64(i), 16))
		if err != nil {
			t.Errorf("got unexpected error: %v", err)
		}
		got := pool.Allocate()
		if got != expect {
			t.Errorf("got %s expect %s", got, expect)
		}
	}
}
