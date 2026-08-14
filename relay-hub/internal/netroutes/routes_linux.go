//go:build linux

// SPDX-License-Identifier: MIT

package netroutes

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/sys/unix"
)

const maximumRouteDumpBytes = 16 * 1024 * 1024

type routeReceiver func([]byte) (int, int, unix.Sockaddr, error)

func KernelPrefixes() ([]netip.Prefix, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	localAddress, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	local, ok := localAddress.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		return nil, errors.New("invalid netlink route socket identity")
	}
	request := make([]byte, netlinkHeaderLength+routeMessageLength)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], routeDumpSequence)
	binary.NativeEndian.PutUint32(request[12:16], local.Pid)
	request[netlinkHeaderLength] = unix.AF_INET
	if err = unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	dump, err := receiveRouteDump(local.Pid, func(buffer []byte) (int, int, unix.Sockaddr, error) {
		count, _, flags, from, receiveErr := unix.Recvmsg(fd, buffer, nil, 0)
		return count, flags, from, receiveErr
	})
	if err != nil {
		return nil, err
	}
	return ParseNetlinkRouteDump(dump, routeDumpSequence, local.Pid)
}

func receiveRouteDump(expectedPortID uint32, receive routeReceiver) ([]byte, error) {
	var dump []byte
	buffer := make([]byte, 64*1024)
	for {
		count, flags, from, err := receive(buffer)
		if err != nil {
			return nil, err
		}
		if count <= 0 || count > len(buffer) {
			return nil, errors.New("invalid netlink route response length")
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, errors.New("truncated netlink route response")
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 {
			return nil, errors.New("netlink route response was not from kernel")
		}
		chunk := append([]byte(nil), buffer[:count]...)
		terminal, err := inspectNetlinkChunk(chunk, routeDumpSequence, expectedPortID)
		if err != nil {
			return nil, err
		}
		if len(dump)+len(chunk) > maximumRouteDumpBytes {
			return nil, errors.New("netlink route response too large")
		}
		dump = append(dump, chunk...)
		if terminal {
			return dump, nil
		}
	}
}
