// SPDX-License-Identifier: MIT

package netroutes

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

func routeMessage(prefix netip.Prefix) []byte {
	attribute := make([]byte, align4(routeAttrLength+4))
	binary.NativeEndian.PutUint16(attribute[0:2], routeAttrLength+4)
	binary.NativeEndian.PutUint16(attribute[2:4], rtaDestination)
	address := prefix.Addr().As4()
	copy(attribute[4:8], address[:])
	payload := make([]byte, routeMessageLength+len(attribute))
	payload[0] = addressFamilyIPv4
	payload[1] = byte(prefix.Bits())
	copy(payload[routeMessageLength:], attribute)
	message := make([]byte, align4(netlinkHeaderLength+len(payload)))
	binary.NativeEndian.PutUint32(message[0:4], uint32(netlinkHeaderLength+len(payload)))
	binary.NativeEndian.PutUint16(message[4:6], rtmNewRoute)
	binary.NativeEndian.PutUint16(message[6:8], 2)
	binary.NativeEndian.PutUint32(message[8:12], routeDumpSequence)
	copy(message[netlinkHeaderLength:], payload)
	return message
}

func doneMessage() []byte {
	message := make([]byte, netlinkHeaderLength)
	binary.NativeEndian.PutUint32(message[0:4], netlinkHeaderLength)
	binary.NativeEndian.PutUint16(message[4:6], nlmsgDone)
	binary.NativeEndian.PutUint32(message[8:12], routeDumpSequence)
	return message
}

func TestParseNetlinkRouteDump(t *testing.T) {
	fixture := append(routeMessage(netip.MustParsePrefix("192.0.2.0/24")), routeMessage(netip.MustParsePrefix("10.0.0.0/8"))...)
	fixture = append(fixture, routeMessage(netip.MustParsePrefix("10.0.0.0/8"))...)
	fixture = append(fixture, doneMessage()...)
	got, err := ParseNetlinkRouteDump(fixture, routeDumpSequence, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[10.0.0.0/8 192.0.2.0/24]" {
		t.Fatalf("routes = %v", got)
	}
}

func TestParseNetlinkRouteDumpSkipsDefaultAndIPv6(t *testing.T) {
	defaultMessage := routeMessage(netip.MustParsePrefix("0.0.0.0/0"))
	defaultMessage[netlinkHeaderLength] = addressFamilyIPv4
	ipv6 := routeMessage(netip.MustParsePrefix("192.0.2.0/24"))
	ipv6[netlinkHeaderLength] = 10
	fixture := append(defaultMessage, ipv6...)
	fixture = append(fixture, doneMessage()...)
	got, err := ParseNetlinkRouteDump(fixture, routeDumpSequence, 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestParseNetlinkRouteDumpRejectsMalformed(t *testing.T) {
	valid := append(routeMessage(netip.MustParsePrefix("192.0.2.0/24")), doneMessage()...)
	for _, fixture := range [][]byte{{1}, make([]byte, netlinkHeaderLength), routeMessage(netip.MustParsePrefix("192.0.2.0/24")), append(valid, 1)} {
		if _, err := ParseNetlinkRouteDump(fixture, routeDumpSequence, 0); err == nil {
			t.Fatal("accepted malformed route dump")
		}
	}
}

func TestParseNetlinkRouteDumpRejectsInterruptedWrongSourceAndWrongSequence(t *testing.T) {
	base := append(routeMessage(netip.MustParsePrefix("192.0.2.0/24")), doneMessage()...)
	interrupted := append([]byte(nil), base...)
	binary.NativeEndian.PutUint16(interrupted[6:8], nlmFDumpInterrupted)
	wrongSequence := append([]byte(nil), base...)
	binary.NativeEndian.PutUint32(wrongSequence[8:12], routeDumpSequence+1)
	wrongSource := append([]byte(nil), base...)
	binary.NativeEndian.PutUint32(wrongSource[12:16], 7)
	for _, fixture := range [][]byte{interrupted, wrongSequence, wrongSource} {
		if _, err := ParseNetlinkRouteDump(fixture, routeDumpSequence, 0); err == nil {
			t.Fatal("accepted interrupted or unattributed route dump")
		}
	}
}

func TestParseNetlinkRouteDumpRejectsOverrunAndError(t *testing.T) {
	for _, messageType := range []uint16{nlmsgOverrun, nlmsgError} {
		fixture := make([]byte, netlinkHeaderLength)
		binary.NativeEndian.PutUint32(fixture[0:4], netlinkHeaderLength)
		binary.NativeEndian.PutUint16(fixture[4:6], messageType)
		binary.NativeEndian.PutUint32(fixture[8:12], routeDumpSequence)
		if _, err := ParseNetlinkRouteDump(fixture, routeDumpSequence, 0); err == nil {
			t.Fatalf("accepted netlink message type %d", messageType)
		}
	}
}
