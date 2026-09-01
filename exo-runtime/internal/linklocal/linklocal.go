// Package linklocal derives the exact IPv6 link-local identity belonging to a
// configured EUI-48 address.
package linklocal

import (
	"errors"
	"net"
)

// FromMAC returns the canonical modified-EUI-64 link-local address for value.
func FromMAC(value string) (string, error) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return "", errors.New("MAC must be a canonical EUI-48 address")
	}
	address := make(net.IP, net.IPv6len)
	address[0], address[1] = 0xfe, 0x80
	address[8] = mac[0] ^ 0x02
	address[9], address[10], address[11] = mac[1], mac[2], 0xff
	address[12], address[13], address[14], address[15] = 0xfe, mac[3], mac[4], mac[5]
	return address.String(), nil
}
