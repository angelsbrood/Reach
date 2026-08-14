//go:build linux

// SPDX-License-Identifier: MIT

package netroutes

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKernelPrefixesLive(t *testing.T) {
	if os.Getenv("REACH_RELAY_LINUX_REAL") != "1" {
		t.Skip("set REACH_RELAY_LINUX_REAL=1 on Linux to inspect the live kernel dump")
	}
	prefixes, err := KernelPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) == 0 {
		t.Fatal("live kernel route dump contained no non-default IPv4 prefixes")
	}
}

func receiverFor(chunks [][]byte, flags []int, senders []unix.Sockaddr) routeReceiver {
	index := 0
	return func(buffer []byte) (int, int, unix.Sockaddr, error) {
		if index >= len(chunks) {
			return 0, 0, nil, errors.New("fixture exhausted")
		}
		chunk := chunks[index]
		copy(buffer, chunk)
		flag := 0
		if index < len(flags) {
			flag = flags[index]
		}
		var sender unix.Sockaddr = &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
		if index < len(senders) {
			sender = senders[index]
		}
		index++
		return len(chunk), flag, sender, nil
	}
}

func TestReceiveRouteDumpAcceptsKernelMultipartResponse(t *testing.T) {
	first := routeMessage(netip.MustParsePrefix("192.0.2.0/24"))
	second := doneMessage()
	dump, err := receiveRouteDump(0, receiverFor([][]byte{first, second}, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := ParseNetlinkRouteDump(dump, routeDumpSequence, 0)
	if err != nil || len(routes) != 1 || routes[0].String() != "192.0.2.0/24" {
		t.Fatalf("routes=%v err=%v", routes, err)
	}
}

func TestReceiveRouteDumpRejectsTruncationAndNonKernelSender(t *testing.T) {
	route := routeMessage(netip.MustParsePrefix("192.0.2.0/24"))
	if _, err := receiveRouteDump(0, receiverFor([][]byte{route}, []int{unix.MSG_TRUNC}, nil)); err == nil {
		t.Fatal("accepted truncated netlink response")
	}
	if _, err := receiveRouteDump(0, receiverFor([][]byte{route}, nil, []unix.Sockaddr{&unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 42}})); err == nil {
		t.Fatal("accepted non-kernel sender")
	}
	if _, err := receiveRouteDump(0, receiverFor([][]byte{route}, nil, []unix.Sockaddr{&unix.SockaddrInet4{}})); err == nil {
		t.Fatal("accepted non-netlink sender")
	}
}
