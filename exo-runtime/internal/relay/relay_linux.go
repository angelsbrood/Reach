//go:build linux

package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/signal"
	"syscall"

	"reach.dev/exo-runtime/internal/authority"
	"reach.dev/exo-runtime/internal/config"
)

const (
	ethernetAll  = 0x0003
	ethernetIPv6 = 0x86dd
)

func RunWithSignals(value config.Node) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return Run(ctx, value)
}

func Run(ctx context.Context, value config.Node) error {
	iface, err := net.InterfaceByName(value.NetworkInterface)
	if err != nil {
		return fmt.Errorf("load relay interface: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 || len(iface.HardwareAddr) != 6 {
		return errors.New("relay interface must be up, multicast-capable Ethernet")
	}
	if !interfaceOwnsIPv4(iface, net.ParseIP(value.PrivateAddress)) {
		return errors.New("relay interface does not own private_address")
	}
	peerMAC, err := net.ParseMAC(value.PeerMAC)
	if err != nil || len(peerMAC) != 6 || iface.HardwareAddr.String() == peerMAC.String() {
		return errors.New("relay peer MAC is invalid or equals the local interface")
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(hostToNetwork16(ethernetAll)))
	if err != nil {
		return fmt.Errorf("open relay packet socket: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: hostToNetwork16(ethernetAll), Ifindex: iface.Index}); err != nil {
		return fmt.Errorf("bind relay packet socket: %w", err)
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("bound relay receive timeout: %w", err)
	}
	target := &syscall.SockaddrLinklayer{Protocol: hostToNetwork16(ethernetIPv6), Ifindex: iface.Index, Halen: 6}
	copy(target.Addr[:], peerMAC)

	log.Printf("discovery relay started interface=%s own_mac=%s peer_mac=%s", iface.Name, iface.HardwareAddr, peerMAC)
	buffer := make([]byte, MaxFrameSize+1)
	forwardedCount := uint64(0)
	for {
		if ctx.Err() != nil {
			log.Printf("discovery relay stopped forwarded_frames=%d", forwardedCount)
			return nil
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("receive relay frame: %w", err)
		}
		frame, ok := ForwardFrame(buffer[:n], iface.HardwareAddr, peerMAC, authority.ProviderDiscoverPort)
		if !ok {
			continue
		}
		if err := syscall.Sendto(fd, frame, 0, target); err != nil {
			return fmt.Errorf("send relay frame: %w", err)
		}
		forwardedCount++
		if forwardedCount == 1 || forwardedCount%10 == 0 {
			log.Printf("discovery relay forwarded_frames=%d", forwardedCount)
		}
	}
}

func interfaceOwnsIPv4(iface *net.Interface, expected net.IP) bool {
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.Equal(expected) {
			return true
		}
	}
	return false
}

func hostToNetwork16(value uint16) uint16 {
	return value<<8 | value>>8
}
