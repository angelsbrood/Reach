// Package relay owns the exact, bounded L2 discovery bridge required by the
// selected two-guest Lima VZ topology.
package relay

import (
	"bytes"
	"encoding/binary"
	"net"
)

const MaxFrameSize = 2048

var (
	discoveryMAC = []byte{0x33, 0x33, 0xe0, 0xa1, 0xde, 0x89}
	discoveryIP  = []byte{0xff, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe0, 0xa1, 0xde, 0x89}
)

// ForwardFrame accepts only an unextended IPv6 UDP discovery frame emitted by
// this node for the frozen EXO multicast group and port. The returned frame is
// an independent copy whose Ethernet destination is the exact peer MAC.
func ForwardFrame(frame []byte, ownMAC, peerMAC net.HardwareAddr, discoveryPort uint16) ([]byte, bool) {
	if len(frame) < 62 || len(frame) > MaxFrameSize || len(ownMAC) != 6 || len(peerMAC) != 6 {
		return nil, false
	}
	if !bytes.Equal(frame[0:6], discoveryMAC) || !bytes.Equal(frame[6:12], ownMAC) {
		return nil, false
	}
	if frame[12] != 0x86 || frame[13] != 0xdd || frame[14]>>4 != 6 || frame[20] != 17 {
		return nil, false
	}
	if !bytes.Equal(frame[38:54], discoveryIP) || binary.BigEndian.Uint16(frame[56:58]) != discoveryPort {
		return nil, false
	}
	payloadLength := int(binary.BigEndian.Uint16(frame[18:20]))
	udpLength := int(binary.BigEndian.Uint16(frame[58:60]))
	if payloadLength < 8 || udpLength < 8 || udpLength > payloadLength || 54+payloadLength > len(frame) || 54+udpLength > len(frame) {
		return nil, false
	}
	forwarded := append([]byte(nil), frame...)
	copy(forwarded[0:6], peerMAC)
	return forwarded, true
}
