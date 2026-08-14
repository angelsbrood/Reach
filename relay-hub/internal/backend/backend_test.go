package backend

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/router"
	"systems.reach/relay-hub/internal/testutil"
)

func testPacket(source, destination [4]byte) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], source[:])
	copy(p[16:20], destination[:])
	return p
}

type endpoint netip.AddrPort

func (e endpoint) ClearSrc()           {}
func (e endpoint) SrcToString() string { return "" }
func (e endpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e endpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e endpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type memoryBind struct {
	mu     sync.Mutex
	closed chan struct{}
}

func (b *memoryBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = make(chan struct{})
	fn := func(_ [][]byte, _ []int, _ []conn.Endpoint) (int, error) { <-b.closed; return 0, net.ErrClosed }
	return []conn.ReceiveFunc{fn}, port, nil
}
func (b *memoryBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != nil {
		select {
		case <-b.closed:
		default:
			close(b.closed)
		}
	}
	return nil
}
func (b *memoryBind) SetMark(uint32) error               { return nil }
func (b *memoryBind) Send([][]byte, conn.Endpoint) error { return nil }
func (b *memoryBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(s)
	return endpoint(a), e
}
func (b *memoryBind) BatchSize() int { return 1 }

func TestExactManifestDiff(t *testing.T) {
	r := router.New()
	b := NewWireGuardWithBind(r, &memoryBind{})
	first := testutil.Spec(1, 2)
	if err := b.ConfigureInitial(first); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	m, err := b.Manifest()
	if err != nil || len(m) != 3 {
		t.Fatal(m, err)
	}
	next := testutil.Spec(2, 2)
	next.Devices = next.Devices[1:]
	_, newKey := testutil.Key(111)
	next.Devices = append(next.Devices, struct {
		PublicKey string `json:"publicKey"`
		Address   string `json:"address"`
	}{newKey, "10.87.0.4/32"})
	if err := b.ApplyManifest(next.Peers()); err != nil {
		t.Fatal(err)
	}
	m, err = b.Manifest()
	if err != nil || !equalManifest(m, desiredManifest(next.Peers())) {
		t.Fatal(m, err)
	}
}

func TestExactDiffPreservesUnchangedAndRecreatesChangedRoute(t *testing.T) {
	first := testutil.Spec(1, 2)
	current := desiredManifest(first.Peers())
	next := first
	next.Generation = 2
	next.Devices = append([]config.Peer(nil), first.Devices...)
	next.Devices[0].Address = "10.87.0.4/32"
	next.Devices = next.Devices[:1]
	_, newKey := testutil.Key(111)
	next.Devices = append(next.Devices, config.Peer{PublicKey: newKey, Address: "10.87.0.5/32"})

	diff := exactDiff(current, next.Peers())
	if len(diff.removals) != 2 || len(diff.additions) != 2 {
		t.Fatalf("unexpected diff: %+v", diff)
	}
	if diff.additions[0].PublicKey != first.Devices[0].PublicKey || diff.additions[0].Address != "10.87.0.4/32" {
		t.Fatalf("route change was not remove/re-add: %+v", diff)
	}
	removals := renderRemovals(diff.removals)
	additions := renderAdditions(diff.additions)
	if strings.Contains(removals, "replace_peers") || strings.Contains(additions, "replace_peers") {
		t.Fatal("update rendered replace_peers")
	}
	unchanged, _ := config.DecodeKey(first.Host.PublicKey)
	if strings.Contains(removals+additions, fmt.Sprintf("%x", unchanged)) {
		t.Fatal("unchanged host peer was recreated")
	}
}

func TestUpdateHooksRunWithRouterClosed(t *testing.T) {
	r := router.New()
	b := NewWireGuardWithBind(r, &memoryBind{})
	first := testutil.Spec(1, 1)
	snapshot, _ := router.SnapshotFor(first)
	if err := r.Install(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfigureInitial(first); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	packet := testPacket([4]byte{10, 87, 0, 1}, [4]byte{10, 87, 0, 2})
	stages := 0
	b.hooks = applyHooks{
		afterRemovals:  func() { _, _ = r.Write([][]byte{packet}, 0); stages++ },
		afterAdditions: func() { _, _ = r.Write([][]byte{packet}, 0); stages++ },
	}
	next := testutil.Spec(2, 2)
	if err := b.ApplyManifest(next.Peers()); err != nil {
		t.Fatal(err)
	}
	if stages != 2 || r.Metrics().Drops[router.DropQuiesced] != 2 || r.Metrics().QueuedPackets != 0 {
		t.Fatalf("forwarding escaped update: stages=%d metrics=%+v", stages, r.Metrics())
	}
}

func TestFakeFailureSequence(t *testing.T) {
	f := &Fake{ApplyErrors: []error{errors.New("once"), nil}}
	s := testutil.Spec(1, 1)
	if err := f.ApplyManifest(s.Peers()); err == nil {
		t.Fatal("failure absent")
	}
	if err := f.ApplyManifest(s.Peers()); err != nil {
		t.Fatal(err)
	}
	m, _ := f.Manifest()
	if len(m) != 2 {
		t.Fatal(m)
	}
}
