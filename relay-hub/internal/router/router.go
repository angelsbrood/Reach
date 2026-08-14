// SPDX-License-Identifier: MIT

package router

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"systems.reach/relay-hub/internal/config"
)

const (
	MaximumPackets = 256
	MaximumBytes   = 256 * 1024
)

type Role string

const (
	Host   Role = "host"
	Device Role = "device"
)

type Owner struct {
	Role      Role
	Ordinal   int
	PublicKey string
	Address   netip.Addr
}
type Snapshot struct {
	Generation uint64
	Host       Owner
	byAddress  map[netip.Addr]Owner
}

func SnapshotFor(spec config.Specification) (Snapshot, error) {
	hostPrefix, err := netip.ParsePrefix(spec.Host.Address)
	if err != nil {
		return Snapshot{}, err
	}
	host := Owner{Role: Host, Ordinal: 1, PublicKey: spec.Host.PublicKey, Address: hostPrefix.Addr()}
	s := Snapshot{Generation: spec.Generation, Host: host, byAddress: map[netip.Addr]Owner{host.Address: host}}
	for _, p := range spec.Devices {
		prefix, err := netip.ParsePrefix(p.Address)
		if err != nil {
			return Snapshot{}, err
		}
		a := prefix.Addr().As4()
		o := Owner{Role: Device, Ordinal: int(a[3]), PublicKey: p.PublicKey, Address: prefix.Addr()}
		s.byAddress[o.Address] = o
	}
	return s, nil
}

func (s Snapshot) Equal(other Snapshot) bool {
	if s.Generation != other.Generation || s.Host != other.Host || len(s.byAddress) != len(other.byAddress) {
		return false
	}
	for a, o := range s.byAddress {
		if other.byAddress[a] != o {
			return false
		}
	}
	return true
}

type DropReason string

const (
	DropClosed    DropReason = "closed"
	DropQuiesced  DropReason = "quiesced"
	DropMalformed DropReason = "malformed"
	DropOwnership DropReason = "ownership"
	DropCount     DropReason = "packet-limit"
	DropBytes     DropReason = "byte-limit"
)

type Metrics struct {
	AcceptedPackets uint64
	QueuedPackets   int
	QueuedBytes     int
	InFlight        int
	Drops           map[DropReason]uint64
	Open            bool
	Generation      uint64
}

type packet struct{ bytes []byte }
type Router struct {
	mu          sync.Mutex
	cond        *sync.Cond
	snapshot    Snapshot
	hasSnapshot bool
	open        bool
	closed      bool
	queue       []packet
	queuedBytes int
	inFlight    int
	accepted    uint64
	drops       map[DropReason]uint64
	events      chan tun.Event
	closeOnce   sync.Once
	readHook    func()
}

func New() *Router {
	r := &Router{drops: make(map[DropReason]uint64), events: make(chan tun.Event, 1)}
	r.cond = sync.NewCond(&r.mu)
	r.events <- tun.EventUp
	return r
}

func (r *Router) File() *os.File           { return nil }
func (r *Router) Name() (string, error)    { return "reach-relay-router", nil }
func (r *Router) MTU() (int, error)        { return config.MTU, nil }
func (r *Router) BatchSize() int           { return 1 }
func (r *Router) Events() <-chan tun.Event { return r.events }

func (r *Router) Write(bufs [][]byte, offset int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	for _, b := range bufs {
		if offset < 0 || offset > len(b) {
			r.drops[DropMalformed]++
			continue
		}
		candidate := b[offset:]
		if !r.open {
			r.drops[DropQuiesced]++
			continue
		}
		if _, _, err := r.classifyLocked(candidate); err != nil {
			if errors.Is(err, errOwnership) {
				r.drops[DropOwnership]++
			} else {
				r.drops[DropMalformed]++
			}
			continue
		}
		if len(r.queue)+1 > MaximumPackets {
			r.drops[DropCount]++
			continue
		}
		if r.queuedBytes+len(candidate) > MaximumBytes {
			r.drops[DropBytes]++
			continue
		}
		copyBytes := append([]byte(nil), candidate...)
		r.queue = append(r.queue, packet{bytes: copyBytes})
		r.queuedBytes += len(copyBytes)
		r.accepted++
		r.cond.Signal()
	}
	return len(bufs), nil
}

func (r *Router) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.closed && (!r.open || len(r.queue) == 0) {
		r.cond.Wait()
	}
	if r.closed {
		return 0, os.ErrClosed
	}
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	entry := r.queue[0]
	r.queue[0].bytes = nil
	r.queue = r.queue[1:]
	r.queuedBytes -= len(entry.bytes)
	r.inFlight++
	if r.readHook != nil {
		r.readHook()
	}
	if len(bufs[0])-offset < len(entry.bytes) {
		r.inFlight--
		r.cond.Broadcast()
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][offset:], entry.bytes)
	entry.bytes = nil
	r.inFlight--
	r.cond.Broadcast()
	return 1, nil
}

func (r *Router) Quiesce() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	r.open = false
	for i := range r.queue {
		r.queue[i].bytes = nil
	}
	r.queue = nil
	r.queuedBytes = 0
	for r.inFlight != 0 && !r.closed {
		r.cond.Wait()
	}
	if r.closed {
		return os.ErrClosed
	}
	return nil
}

func (r *Router) Install(snapshot Snapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	if r.open {
		return errors.New("router snapshot install requires quiescence")
	}
	r.snapshot = snapshot
	r.hasSnapshot = true
	return nil
}

func (r *Router) Verify(snapshot Snapshot) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hasSnapshot && r.snapshot.Equal(snapshot)
}

// Ready verifies both halves of the forwarding authority: the installed
// ownership snapshot and the gate that makes that snapshot observable.
func (r *Router) Ready(snapshot Snapshot) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.open && r.hasSnapshot && r.snapshot.Equal(snapshot)
}

func (r *Router) Reopen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	if !r.hasSnapshot {
		return errors.New("router has no ownership snapshot")
	}
	r.open = true
	r.cond.Broadcast()
	return nil
}

func (r *Router) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.open = false
		for i := range r.queue {
			r.queue[i].bytes = nil
		}
		r.queue = nil
		r.queuedBytes = 0
		close(r.events)
		r.cond.Broadcast()
		r.mu.Unlock()
	})
	return nil
}

func (r *Router) Metrics() Metrics {
	r.mu.Lock()
	defer r.mu.Unlock()
	drops := make(map[DropReason]uint64, len(r.drops))
	for k, v := range r.drops {
		drops[k] = v
	}
	return Metrics{AcceptedPackets: r.accepted, QueuedPackets: len(r.queue), QueuedBytes: r.queuedBytes, InFlight: r.inFlight, Drops: drops, Open: r.open, Generation: r.snapshot.Generation}
}

var errOwnership = errors.New("ownership refused")

func (r *Router) classifyLocked(p []byte) (Owner, Owner, error) {
	if !r.hasSnapshot || len(p) < 20 || p[0]>>4 != 4 || int(p[0]&0xf)*4 != 20 {
		return Owner{}, Owner{}, errors.New("malformed IPv4")
	}
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if total != len(p) || total > config.MTU || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return Owner{}, Owner{}, errors.New("invalid IPv4 length or fragment")
	}
	var sb, db [4]byte
	copy(sb[:], p[12:16])
	copy(db[:], p[16:20])
	src := netip.AddrFrom4(sb)
	dst := netip.AddrFrom4(db)
	source, sourceOK := r.snapshot.byAddress[src]
	destination, destinationOK := r.snapshot.byAddress[dst]
	if !sourceOK || !destinationOK {
		return Owner{}, Owner{}, errOwnership
	}
	if source.Role == Host && destination.Role == Device {
		return source, destination, nil
	}
	if source.Role == Device && destination == r.snapshot.Host {
		return source, destination, nil
	}
	return Owner{}, Owner{}, errOwnership
}
