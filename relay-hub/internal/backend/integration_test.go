// SPDX-License-Identifier: MIT

package backend

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/router"
	"systems.reach/relay-hub/internal/testutil"
)

type integrationNode struct {
	tun    *tuntest.ChannelTUN
	device *device.Device
}

func newIntegrationNode() *integrationNode {
	t := tuntest.NewChannelTUN()
	return &integrationNode{
		tun:    t,
		device: device.NewDevice(t.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "")),
	}
}

func (n *integrationNode) configure(privateKey, hubPublicKey, endpoint string, allowed []string) error {
	var source strings.Builder
	fmt.Fprintf(&source, "private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nendpoint=%s\nreplace_allowed_ips=true\npersistent_keepalive_interval=1\n", keyHex(privateKey), keyHex(hubPublicKey), endpoint)
	for _, address := range allowed {
		fmt.Fprintf(&source, "allowed_ip=%s\n", address)
	}
	source.WriteByte('\n')
	if err := n.device.IpcSetOperation(strings.NewReader(source.String())); err != nil {
		return err
	}
	return n.device.Up()
}

func (n *integrationNode) updateAllowed(hubPublicKey, endpoint string, allowed []string) error {
	var source strings.Builder
	fmt.Fprintf(&source, "public_key=%s\nendpoint=%s\nreplace_allowed_ips=true\n", keyHex(hubPublicKey), endpoint)
	for _, address := range allowed {
		fmt.Fprintf(&source, "allowed_ip=%s\n", address)
	}
	source.WriteByte('\n')
	return n.device.IpcSetOperation(strings.NewReader(source.String()))
}

func keyHex(value string) string {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

func integrationPacket(source, destination net.IP, payload string) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], source.To4())
	copy(p[16:20], destination.To4())
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 40001)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

func receivePacket(channel <-chan []byte, timeout time.Duration) ([]byte, error) {
	select {
	case packet := <-channel:
		return packet, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("packet timed out after %s", timeout)
	}
}

func unusedUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func installSnapshot(t *testing.T, r *router.Router, spec config.Specification) {
	t.Helper()
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := router.SnapshotFor(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Install(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = r.Reopen(); err != nil {
		t.Fatal(err)
	}
}

func expectPacket(t *testing.T, node *integrationNode, expected []byte) {
	t.Helper()
	actual, err := receivePacket(node.tun.Inbound, 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("packet mismatch: got %x want %x", actual, expected)
	}
}

func TestRealThreePeerForwardingAndPeerDiff(t *testing.T) {
	if os.Getenv("REACH_RELAY_REAL") != "1" {
		t.Skip("set REACH_RELAY_REAL=1 to bind disposable wildcard UDP listeners")
	}

	spec := testutil.Spec(1, 1)
	spec.ListenPort = unusedUDPPort(t)
	hubPublic := spec.PublicKey
	hostPrivate, _ := testutil.Key(40)
	devicePrivate, _ := testutil.Key(80)
	extraPrivate, extraPublic := testutil.Key(111)

	r := router.New()
	initialSnapshot, err := router.SnapshotFor(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Install(initialSnapshot); err != nil {
		t.Fatal(err)
	}
	if err = r.Reopen(); err != nil {
		t.Fatal(err)
	}
	hub := NewWireGuard(r)
	if err = hub.ConfigureInitial(spec); err != nil {
		t.Fatal(err)
	}
	host := newIntegrationNode()
	devicePeer := newIntegrationNode()
	var extraPeer *integrationNode
	t.Cleanup(func() {
		if extraPeer != nil {
			extraPeer.device.Close()
		}
		devicePeer.device.Close()
		host.device.Close()
		_ = hub.Close()
		_ = r.Close()
	})

	endpoint := fmt.Sprintf("127.0.0.1:%d", spec.ListenPort)
	if err = host.configure(hostPrivate, hubPublic, endpoint, []string{"10.87.0.2/32"}); err != nil {
		t.Fatal(err)
	}
	if err = devicePeer.configure(devicePrivate, hubPublic, endpoint, []string{"10.87.0.1/32"}); err != nil {
		t.Fatal(err)
	}

	deviceToHost := integrationPacket(net.IPv4(10, 87, 0, 2), net.IPv4(10, 87, 0, 1), "device-to-host")
	devicePeer.tun.Outbound <- deviceToHost
	expectPacket(t, host, deviceToHost)
	hostToDevice := integrationPacket(net.IPv4(10, 87, 0, 1), net.IPv4(10, 87, 0, 2), "host-to-device")
	host.tun.Outbound <- hostToDevice
	expectPacket(t, devicePeer, hostToDevice)

	before, err := hub.Runtime()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range spec.Peers() {
		if before[peer.PublicKey].LastHandshake.IsZero() {
			t.Fatal("missing initial peer handshake")
		}
	}

	second := spec
	second.Generation = 2
	second.Devices = append([]config.Peer(nil), spec.Devices...)
	second.Devices = append(second.Devices, config.Peer{PublicKey: extraPublic, Address: "10.87.0.3/32"})
	if err = r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	if err = hub.ApplyManifest(second.Peers()); err != nil {
		t.Fatal(err)
	}
	after, err := hub.Runtime()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range spec.Peers() {
		prior := before[peer.PublicKey]
		current := after[peer.PublicKey]
		if current.LastHandshake.IsZero() || current.LastHandshake.Before(prior.LastHandshake) || current.ReceiveBytes < prior.ReceiveBytes || current.TransmitBytes < prior.TransmitBytes {
			t.Fatalf("unchanged peer runtime was reset: before=%+v after=%+v", prior, current)
		}
	}
	secondSnapshot, _ := router.SnapshotFor(second)
	if err = r.Install(secondSnapshot); err != nil {
		t.Fatal(err)
	}
	if err = r.Reopen(); err != nil {
		t.Fatal(err)
	}

	// The device peer must remain immediately reachable without first sending
	// another packet that could teach a recreated peer its endpoint.
	host.tun.Outbound <- hostToDevice
	expectPacket(t, devicePeer, hostToDevice)

	if err = host.updateAllowed(hubPublic, endpoint, []string{"10.87.0.2/32", "10.87.0.3/32"}); err != nil {
		t.Fatal(err)
	}
	beforeStage := r.Metrics().AcceptedPackets
	stale := integrationPacket(net.IPv4(10, 87, 0, 1), net.IPv4(10, 87, 0, 3), "staged-before-route-change")
	host.tun.Outbound <- stale
	deadline := time.Now().Add(3 * time.Second)
	for {
		if r.Metrics().AcceptedPackets > beforeStage {
			current, runtimeErr := hub.Runtime()
			if runtimeErr != nil {
				t.Fatal(runtimeErr)
			}
			if current[extraPublic].TransmitBytes != 0 {
				t.Fatal("unestablished route-changing peer unexpectedly transmitted")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("staged packet never reached the hub")
		}
		time.Sleep(10 * time.Millisecond)
	}

	third := second
	third.Generation = 3
	third.Devices = append([]config.Peer(nil), second.Devices...)
	third.Devices[1].Address = "10.87.0.4/32"
	if err = r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	if err = hub.ApplyManifest(third.Peers()); err != nil {
		t.Fatal(err)
	}
	thirdSnapshot, _ := router.SnapshotFor(third)
	if err = r.Install(thirdSnapshot); err != nil {
		t.Fatal(err)
	}
	if err = r.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err = host.updateAllowed(hubPublic, endpoint, []string{"10.87.0.2/32", "10.87.0.4/32"}); err != nil {
		t.Fatal(err)
	}
	extraPeer = newIntegrationNode()
	if err = extraPeer.configure(extraPrivate, hubPublic, endpoint, []string{"10.87.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	extraToHost := integrationPacket(net.IPv4(10, 87, 0, 4), net.IPv4(10, 87, 0, 1), "new-route-to-host")
	extraPeer.tun.Outbound <- extraToHost
	expectPacket(t, host, extraToHost)
	if unexpected, err := receivePacket(extraPeer.tun.Inbound, 500*time.Millisecond); err == nil {
		t.Fatalf("staged packet survived remove/re-add: %x", unexpected)
	}
	hostToExtra := integrationPacket(net.IPv4(10, 87, 0, 1), net.IPv4(10, 87, 0, 4), "host-to-new-route")
	host.tun.Outbound <- hostToExtra
	expectPacket(t, extraPeer, hostToExtra)

	if err = hub.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: spec.ListenPort})
	if err != nil {
		t.Fatalf("hub wildcard UDP port remained bound: %v", err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
}
