//go:build !linux

// SPDX-License-Identifier: MIT

package netroutes

import (
	"errors"
	"net/netip"
)

func KernelPrefixes() ([]netip.Prefix, error) {
	return nil, errors.New("Linux route inventory unavailable")
}
