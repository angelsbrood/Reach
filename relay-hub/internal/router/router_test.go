package router

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"systems.reach/relay-hub/internal/testutil"
)

func ipv4(src, dst [4]byte, size int) []byte {
	if size < 20 {
		size = 20
	}
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	return p
}

var host = [4]byte{10, 87, 0, 1}
var dev = [4]byte{10, 87, 0, 2}

func ready(t *testing.T) *Router {
	t.Helper()
	r := New()
	s, _ := SnapshotFor(testutil.Spec(1, 1))
	if err := r.Install(s); err != nil {
		t.Fatal(err)
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestForwardBothDirections(t *testing.T) {
	r := ready(t)
	defer r.Close()
	for _, p := range [][]byte{ipv4(host, dev, 64), ipv4(dev, host, 72)} {
		if n, err := r.Write([][]byte{p}, 0); err != nil || n != 1 {
			t.Fatal(n, err)
		}
		buf := [][]byte{make([]byte, 1280)}
		sizes := make([]int, 1)
		if n, err := r.Read(buf, sizes, 0); err != nil || n != 1 || sizes[0] != len(p) {
			t.Fatal(n, sizes, err)
		}
	}
}

func TestOwnershipAndShapeDrops(t *testing.T) {
	r := ready(t)
	defer r.Close()
	other := [4]byte{10, 87, 0, 3}
	cases := [][]byte{ipv4(dev, dev, 20), ipv4(other, host, 20), ipv4(host, other, 20), {1, 2, 3}}
	fragment := ipv4(dev, host, 20)
	fragment[6] = 0x20
	cases = append(cases, fragment, ipv4(dev, host, 1281))
	for _, p := range cases {
		_, _ = r.Write([][]byte{p}, 0)
	}
	m := r.Metrics()
	if m.QueuedPackets != 0 || m.Drops[DropOwnership] != 3 || m.Drops[DropMalformed] != 3 {
		t.Fatalf("%+v", m)
	}
}

func TestIndependentQueueBoundsAndRelease(t *testing.T) {
	r := ready(t)
	defer r.Close()
	small := ipv4(host, dev, 20)
	for i := 0; i < MaximumPackets; i++ {
		_, _ = r.Write([][]byte{small}, 0)
	}
	_, _ = r.Write([][]byte{small}, 0)
	m := r.Metrics()
	if m.QueuedPackets != 256 || m.QueuedBytes != 5120 || m.Drops[DropCount] != 1 {
		t.Fatalf("count %+v", m)
	}
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	m = r.Metrics()
	if m.QueuedPackets != 0 || m.QueuedBytes != 0 {
		t.Fatalf("retained %+v", m)
	}
	s, _ := SnapshotFor(testutil.Spec(1, 1))
	_ = r.Install(s)
	_ = r.Reopen()
	large := ipv4(host, dev, 1280)
	for i := 0; i < 204; i++ {
		_, _ = r.Write([][]byte{large}, 0)
	}
	_, _ = r.Write([][]byte{large}, 0)
	m = r.Metrics()
	if m.QueuedPackets != 204 || m.QueuedBytes != 261120 || m.Drops[DropBytes] != 1 {
		t.Fatalf("bytes %+v", m)
	}
}

func TestQuiescenceDropsAndSnapshotChange(t *testing.T) {
	r := ready(t)
	defer r.Close()
	initial, _ := SnapshotFor(testutil.Spec(1, 1))
	if !r.Ready(initial) {
		t.Fatal("open matching router was not ready")
	}
	_, _ = r.Write([][]byte{ipv4(host, dev, 80)}, 0)
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	if r.Ready(initial) {
		t.Fatal("quiesced router remained ready")
	}
	_, _ = r.Write([][]byte{ipv4(host, dev, 80)}, 0)
	m := r.Metrics()
	if m.QueuedPackets != 0 || m.Drops[DropQuiesced] != 1 {
		t.Fatalf("%+v", m)
	}
	next := testutil.Spec(2, 2)
	s, _ := SnapshotFor(next)
	if err := r.Install(s); err != nil {
		t.Fatal(err)
	}
	if !r.Verify(s) {
		t.Fatal("snapshot mismatch")
	}
	if r.Ready(s) {
		t.Fatal("closed candidate snapshot was ready")
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	if r.Metrics().Generation != 2 || !r.Ready(s) || r.Ready(initial) {
		t.Fatal("generation")
	}
}

func TestReadBlocksUntilReopen(t *testing.T) {
	r := ready(t)
	defer r.Close()
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := [][]byte{make([]byte, 1280)}
		sizes := make([]int, 1)
		_, _ = r.Read(buf, sizes, 0)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("read escaped quiescence")
	case <-time.After(50 * time.Millisecond):
	}
	s, _ := SnapshotFor(testutil.Spec(1, 1))
	_ = r.Install(s)
	_ = r.Reopen()
	_, _ = r.Write([][]byte{ipv4(host, dev, 20)}, 0)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("read did not resume")
	}
}

func TestQuiesceWaitsForInFlightDispatch(t *testing.T) {
	r := ready(t)
	defer r.Close()
	if _, err := r.Write([][]byte{ipv4(host, dev, 1280)}, 0); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	r.readHook = func() {
		close(entered)
		<-release
	}
	readDone := make(chan error, 1)
	go func() {
		buf := [][]byte{make([]byte, 1280)}
		sizes := make([]int, 1)
		_, err := r.Read(buf, sizes, 0)
		readDone <- err
	}()
	<-entered
	quiesced := make(chan error, 1)
	go func() { quiesced <- r.Quiesce() }()
	select {
	case err := <-quiesced:
		t.Fatalf("quiescence crossed in-flight dispatch: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if err := <-quiesced; err != nil {
		t.Fatal(err)
	}
	if metrics := r.Metrics(); metrics.InFlight != 0 || metrics.QueuedBytes != 0 || metrics.Open {
		t.Fatalf("%+v", metrics)
	}
}

func TestCloseReleasesBlockedReadAndQueue(t *testing.T) {
	r := ready(t)
	if _, err := r.Write([][]byte{ipv4(host, dev, 1280)}, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buf := [][]byte{make([]byte, 1280)}
		sizes := make([]int, 1)
		_, err := r.Read(buf, sizes, 0)
		done <- err
	}()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("blocked read ended with %v", err)
	}
	if metrics := r.Metrics(); metrics.QueuedPackets != 0 || metrics.QueuedBytes != 0 || metrics.Open {
		t.Fatalf("%+v", metrics)
	}
}
