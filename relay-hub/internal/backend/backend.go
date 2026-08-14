// SPDX-License-Identifier: MIT

package backend

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/router"
)

type Manifest map[string]string // canonical base64 public key -> canonical /32
type PeerRuntime struct {
	LastHandshake time.Time
	ReceiveBytes  uint64
	TransmitBytes uint64
}

type Backend interface {
	ConfigureInitial(config.Specification) error
	ApplyManifest([]config.Peer) error
	Manifest() (Manifest, error)
	Runtime() (map[string]PeerRuntime, error)
	Close() error
}

type WireGuard struct {
	mu     sync.Mutex
	router *router.Router
	device *device.Device
	bind   conn.Bind
	hooks  applyHooks
}

type applyHooks struct {
	afterRemovals  func()
	afterAdditions func()
}

type manifestDiff struct {
	removals  []string
	additions []config.Peer
}

func NewWireGuard(r *router.Router) *WireGuard {
	return &WireGuard{router: r, bind: conn.NewDefaultBind()}
}
func NewWireGuardWithBind(r *router.Router, bind conn.Bind) *WireGuard {
	return &WireGuard{router: r, bind: bind}
}

func (w *WireGuard) ConfigureInitial(spec config.Specification) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.device != nil {
		return errors.New("backend already configured")
	}
	d := device.NewDevice(w.router, w.bind, device.NewLogger(device.LogLevelSilent, ""))
	private, _ := config.DecodeKey(spec.PrivateKey)
	var source strings.Builder
	fmt.Fprintf(&source, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", hex.EncodeToString(private), spec.ListenPort)
	for _, p := range spec.Peers() {
		appendPeer(&source, p)
	}
	source.WriteByte('\n')
	if err := d.IpcSetOperation(strings.NewReader(source.String())); err != nil {
		d.Close()
		return err
	}
	if err := d.Up(); err != nil {
		d.Close()
		return err
	}
	w.device = d
	actual, err := w.manifestLocked()
	if err != nil {
		d.Close()
		w.device = nil
		return err
	}
	if !equalManifest(actual, desiredManifest(spec.Peers())) {
		d.Close()
		w.device = nil
		return errors.New("initial peer manifest verification failed")
	}
	return nil
}

func (w *WireGuard) ApplyManifest(peers []config.Peer) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.device == nil {
		return errors.New("backend unavailable")
	}
	current, err := w.manifestLocked()
	if err != nil {
		return err
	}
	desired := desiredManifest(peers)
	diff := exactDiff(current, peers)
	if len(diff.removals) > 0 {
		if err := w.device.IpcSetOperation(strings.NewReader(renderRemovals(diff.removals))); err != nil {
			return err
		}
		observed, err := w.manifestLocked()
		if err != nil {
			return err
		}
		for _, key := range diff.removals {
			if _, exists := observed[key]; exists {
				return errors.New("removed peer remained configured")
			}
		}
	}
	call(w.hooks.afterRemovals)
	if len(diff.additions) > 0 {
		if err := w.device.IpcSetOperation(strings.NewReader(renderAdditions(diff.additions))); err != nil {
			return err
		}
	}
	call(w.hooks.afterAdditions)
	observed, err := w.manifestLocked()
	if err != nil {
		return err
	}
	if !equalManifest(observed, desired) {
		return errors.New("complete peer manifest verification failed")
	}
	return nil
}

func exactDiff(current Manifest, peers []config.Peer) manifestDiff {
	desired := desiredManifest(peers)
	var diff manifestDiff
	for key, address := range current {
		if wanted, ok := desired[key]; !ok || wanted != address {
			diff.removals = append(diff.removals, key)
		}
	}
	sort.Strings(diff.removals)
	for _, peer := range peers {
		if address, ok := current[peer.PublicKey]; !ok || address != peer.Address {
			diff.additions = append(diff.additions, peer)
		}
	}
	return diff
}

func renderRemovals(keys []string) string {
	var source strings.Builder
	for _, key := range keys {
		raw, _ := base64.StdEncoding.DecodeString(key)
		fmt.Fprintf(&source, "public_key=%s\nremove=true\n", hex.EncodeToString(raw))
	}
	source.WriteByte('\n')
	return source.String()
}

func renderAdditions(peers []config.Peer) string {
	var source strings.Builder
	for _, peer := range peers {
		appendPeer(&source, peer)
	}
	source.WriteByte('\n')
	return source.String()
}

func call(hook func()) {
	if hook != nil {
		hook()
	}
}

func appendPeer(b *strings.Builder, p config.Peer) {
	raw, _ := config.DecodeKey(p.PublicKey)
	fmt.Fprintf(b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\n", hex.EncodeToString(raw), p.Address)
}
func desiredManifest(peers []config.Peer) Manifest {
	m := make(Manifest, len(peers))
	for _, p := range peers {
		m[p.PublicKey] = p.Address
	}
	return m
}
func equalManifest(a, b Manifest) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (w *WireGuard) Manifest() (Manifest, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.manifestLocked()
}
func (w *WireGuard) manifestLocked() (Manifest, error) {
	state, err := w.stateLocked()
	if err != nil {
		return nil, err
	}
	return state.manifest, nil
}
func (w *WireGuard) Runtime() (map[string]PeerRuntime, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.stateLocked()
	if err != nil {
		return nil, err
	}
	return state.runtime, nil
}

type parsedState struct {
	manifest Manifest
	runtime  map[string]PeerRuntime
}

func (w *WireGuard) stateLocked() (parsedState, error) {
	if w.device == nil {
		return parsedState{}, errors.New("backend unavailable")
	}
	text, err := w.device.IpcGet()
	if err != nil {
		return parsedState{}, err
	}
	result := parsedState{manifest: make(Manifest), runtime: make(map[string]PeerRuntime)}
	var key string
	var address string
	var runtime PeerRuntime
	flush := func() error {
		if key == "" {
			return nil
		}
		if address == "" {
			return errors.New("peer has no route")
		}
		result.manifest[key] = address
		result.runtime[key] = runtime
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch name {
		case "public_key":
			if err := flush(); err != nil {
				return parsedState{}, err
			}
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != 32 {
				return parsedState{}, errors.New("invalid backend public key")
			}
			key = base64.StdEncoding.EncodeToString(raw)
			address = ""
			runtime = PeerRuntime{}
		case "allowed_ip":
			if key != "" {
				if address != "" {
					return parsedState{}, errors.New("peer has multiple routes")
				}
				address = value
			}
		case "last_handshake_time_sec":
			if key != "" {
				seconds, _ := strconv.ParseInt(value, 10, 64)
				if seconds > 0 {
					runtime.LastHandshake = time.Unix(seconds, 0).UTC()
				}
			}
		case "rx_bytes":
			if key != "" {
				runtime.ReceiveBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "tx_bytes":
			if key != "" {
				runtime.TransmitBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return parsedState{}, err
	}
	if err := flush(); err != nil {
		return parsedState{}, err
	}
	return result, nil
}

func (w *WireGuard) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.device == nil {
		return nil
	}
	w.device.Close()
	w.device = nil
	return nil
}

// Fake is a deterministic backend for manager tests.
type Fake struct {
	Mu           sync.Mutex
	Current      Manifest
	RuntimeState map[string]PeerRuntime
	FailInitial  error
	FailApply    error
	ApplyErrors  []error
	ApplyHook    func()
	Closed       bool
	Calls        int
}

func (f *Fake) ConfigureInitial(spec config.Specification) error {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if f.FailInitial != nil {
		return f.FailInitial
	}
	f.Current = desiredManifest(spec.Peers())
	f.Calls++
	return nil
}
func (f *Fake) ApplyManifest(peers []config.Peer) error {
	if f.ApplyHook != nil {
		f.ApplyHook()
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if len(f.ApplyErrors) > 0 {
		err := f.ApplyErrors[0]
		f.ApplyErrors = f.ApplyErrors[1:]
		if err != nil {
			return err
		}
	}
	if f.FailApply != nil {
		return f.FailApply
	}
	f.Current = desiredManifest(peers)
	f.Calls++
	return nil
}
func (f *Fake) Manifest() (Manifest, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	m := make(Manifest, len(f.Current))
	for k, v := range f.Current {
		m[k] = v
	}
	return m, nil
}
func (f *Fake) Runtime() (map[string]PeerRuntime, error) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	m := make(map[string]PeerRuntime, len(f.RuntimeState))
	for k, v := range f.RuntimeState {
		m[k] = v
	}
	return m, nil
}
func (f *Fake) Close() error { f.Mu.Lock(); defer f.Mu.Unlock(); f.Closed = true; return nil }

var _ io.Closer = (*WireGuard)(nil)
