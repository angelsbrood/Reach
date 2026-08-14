// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"systems.reach/relay-hub/internal/testutil"
)

type fakeService struct {
	mu           sync.Mutex
	applies      int
	refusals     int
	refreshes    int
	closes       int
	applyError   error
	refreshError error
	refusalError error
	hasActive    bool
}

func (f *fakeService) Apply([]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	return f.applyError
}
func (f *fakeService) RefuseUpdate() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refusals++
	return f.refusalError
}
func (f *fakeService) RefreshStatus() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	return f.refreshError
}
func (f *fakeService) HasActive() bool { return f.hasActive }
func (f *fakeService) Close() error    { f.mu.Lock(); defer f.mu.Unlock(); f.closes++; return nil }

func TestServeSignalsSerializesReloadRefreshAndClose(t *testing.T) {
	signals := make(chan os.Signal, 4)
	signals <- syscall.SIGHUP
	signals <- syscall.SIGUSR1
	signals <- syscall.SIGTERM
	service := &fakeService{}
	reads := 0
	if err := serveSignals(signals, func() ([]byte, error) { reads++; return []byte("candidate"), nil }, service, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || service.applies != 1 || service.refreshes != 1 || service.refusals != 0 || service.closes != 1 {
		t.Fatalf("reads=%d service=%+v", reads, service)
	}
}

func TestServeSignalsRefusesInvalidUpdateAndKeepsServing(t *testing.T) {
	signals := make(chan os.Signal, 3)
	signals <- syscall.SIGHUP
	signals <- syscall.SIGUSR1
	signals <- syscall.SIGINT
	service := &fakeService{}
	logs := []string{}
	want := errors.New("invalid operator files")
	if err := serveSignals(signals, func() ([]byte, error) { return nil, want }, service, func(value string) { logs = append(logs, value) }); err != nil {
		t.Fatal(err)
	}
	if service.applies != 0 || service.refusals != 1 || service.refreshes != 1 || service.closes != 1 || len(logs) != 1 || logs[0] != "relay hub update refused" {
		t.Fatalf("service=%+v logs=%v", service, logs)
	}
}

func TestRouteAwareDecoderReevaluatesRoutesAndRejectsPrivilegedPort(t *testing.T) {
	dir := t.TempDir()
	routesPath := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(routesPath, []byte(`{"version":1,"prefixes":["192.0.2.0/24"]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	kernel := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	decode := routeAwareDecoder(routesPath, uid, gid, func() ([]netip.Prefix, error) { return append([]netip.Prefix(nil), kernel...), nil })
	spec := testutil.Spec(1, 1)
	raw, _ := spec.CanonicalJSON()
	if _, err := decode(raw); err != nil {
		t.Fatal(err)
	}
	kernel = append(kernel, netip.MustParsePrefix(spec.RelayPrefix))
	if _, err := decode(raw); err == nil {
		t.Fatal("new kernel overlap was not reevaluated")
	}
	kernel = nil
	spec.ListenPort = 443
	raw, _ = spec.CanonicalJSON()
	if _, err := decode(raw); err == nil {
		t.Fatal("privileged port accepted")
	}
}

func TestRemoveLegacyStatusIsNarrowAndSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyStatus(path, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy status retained")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := removeLegacyStatus(path, uint32(os.Getuid())); err == nil {
		t.Fatal("unsafe legacy status removed")
	}
	if data, _ := os.ReadFile(target); string(data) != "keep" {
		t.Fatal("symlink target changed")
	}
}
