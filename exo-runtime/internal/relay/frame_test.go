package relay

import (
	"encoding/binary"
	"net"
	"testing"
)

func validFrame(own net.HardwareAddr, port uint16) []byte {
	frame := make([]byte, 62)
	copy(frame[0:6], discoveryMAC)
	copy(frame[6:12], own)
	frame[12], frame[13], frame[14], frame[20] = 0x86, 0xdd, 0x60, 17
	binary.BigEndian.PutUint16(frame[18:20], 8)
	copy(frame[38:54], discoveryIP)
	binary.BigEndian.PutUint16(frame[54:56], 40000)
	binary.BigEndian.PutUint16(frame[56:58], port)
	binary.BigEndian.PutUint16(frame[58:60], 8)
	return frame
}

func TestForwardFrameRewritesOnlyDestination(t *testing.T) {
	own, _ := net.ParseMAC("52:55:55:00:00:02")
	peer, _ := net.ParseMAC("52:55:55:00:00:03")
	input := validFrame(own, 52413)
	original := append([]byte(nil), input...)
	output, ok := ForwardFrame(input, own, peer, 52413)
	if !ok {
		t.Fatal("valid discovery frame refused")
	}
	if string(input) != string(original) {
		t.Fatal("input frame was mutated")
	}
	if string(output[:6]) != string(peer) || string(output[6:]) != string(input[6:]) {
		t.Fatal("forwarded frame changed bytes beyond the destination MAC")
	}
}

func TestForwardFrameRefusesEveryAuthorityDrift(t *testing.T) {
	own, _ := net.ParseMAC("52:55:55:00:00:02")
	peer, _ := net.ParseMAC("52:55:55:00:00:03")
	tests := map[string]func([]byte) []byte{
		"short":           func(frame []byte) []byte { return frame[:61] },
		"oversize":        func(frame []byte) []byte { return append(frame, make([]byte, MaxFrameSize-len(frame)+1)...) },
		"destination MAC": func(frame []byte) []byte { frame[5] ^= 1; return frame },
		"source MAC":      func(frame []byte) []byte { frame[11] ^= 1; return frame },
		"ether type":      func(frame []byte) []byte { frame[13] = 0; return frame },
		"IP version":      func(frame []byte) []byte { frame[14] = 0x40; return frame },
		"next header":     func(frame []byte) []byte { frame[20] = 6; return frame },
		"group IP":        func(frame []byte) []byte { frame[53] ^= 1; return frame },
		"port":            func(frame []byte) []byte { frame[57] ^= 1; return frame },
		"payload length":  func(frame []byte) []byte { binary.BigEndian.PutUint16(frame[18:20], 7); return frame },
		"UDP length":      func(frame []byte) []byte { binary.BigEndian.PutUint16(frame[58:60], 9); return frame },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := ForwardFrame(mutate(validFrame(own, 52413)), own, peer, 52413); ok {
				t.Fatal("drifted frame was forwarded")
			}
		})
	}
}
