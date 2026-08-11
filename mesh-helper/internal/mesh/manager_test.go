// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"os"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu             sync.Mutex
	applied        []uint64
	failGeneration uint64
	closed         bool
}

func (backend *fakeBackend) Apply(spec Specification) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.applied = append(backend.applied, spec.Generation)
	if spec.Generation == backend.failGeneration {
		return "", errors.New("injected backend failure")
	}
	return "utun-test", nil
}

func (backend *fakeBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.closed = true
	return nil
}

func testManager(t *testing.T, paths Paths, backend Backend) *Manager {
	t.Helper()
	manager := NewManager(paths, backend)
	manager.owner = uint32(os.Getuid())
	return manager
}

func TestPendingPromotionAndIdempotentNoOp(t *testing.T) {
	paths := testPaths(t)
	spec := testSpecification(t, 1)
	writeTestSpec(t, paths.Pending, spec)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if manager.active == nil || manager.active.Generation != 1 {
		t.Fatal("pending configuration was not promoted")
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("promoted pending file remains")
	}
	writeTestSpec(t, paths.Pending, spec)
	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	if manager.active.Generation != 1 {
		t.Fatal("idempotent apply changed generation")
	}
	if !manager.status.Ready || manager.status.PublicDigest != spec.PublicDigest() {
		t.Fatal("ready status does not reflect active configuration")
	}
}

func TestGenerationOrderingAndRollback(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{failGeneration: 5}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	failed := active
	failed.Generation = 5
	writeTestSpec(t, paths.Pending, failed)
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("backend failure reported success")
	}
	if manager.active.Generation != 4 || manager.status.Generation != 4 || !manager.status.Ready {
		t.Fatal("last-known-good configuration was not restored")
	}
	backend.mu.Lock()
	applied := append([]uint64(nil), backend.applied...)
	backend.mu.Unlock()
	if len(applied) < 3 || applied[len(applied)-2] != 5 || applied[len(applied)-1] != 4 {
		t.Fatalf("apply sequence = %v", applied)
	}

	rollback := active
	rollback.Generation = 3
	writeTestSpec(t, paths.Pending, rollback)
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("generation rollback accepted")
	}
}

func TestSameGenerationDifferentDigestIsRejected(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 2)
	writeTestSpec(t, paths.Active, active)
	manager := testManager(t, paths, &fakeBackend{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Peers = append([]Peer(nil), active.Peers...)
	candidate.Peers[0].Keepalive++
	writeTestSpec(t, paths.Pending, candidate)
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("generation reuse accepted")
	}
}

func TestUnconfiguredAndSignalStyleCloseAreLegible(t *testing.T) {
	paths := testPaths(t)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if manager.status.Ready || manager.status.Error != "unconfigured" {
		t.Fatalf("status = %+v", manager.status)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if manager.status.Error != "stopped" || !backend.closed {
		t.Fatal("close did not stop backend and status")
	}
}

func TestStatusIsPrivacySafe(t *testing.T) {
	paths := testPaths(t)
	spec := testSpecification(t, 1)
	writeTestSpec(t, paths.Active, spec)
	manager := testManager(t, paths, &fakeBackend{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.Status)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{spec.PrivateKey, spec.PublicKey, spec.Peers[0].PublicKey, spec.Peers[0].AllowedIP} {
		if contains(text, secret) {
			t.Fatalf("status disclosed configuration material: %q", secret)
		}
	}
}

func TestFirstPromotionFailureClosesNonDurableInterface(t *testing.T) {
	paths := testPaths(t)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	spec := testSpecification(t, 1)
	writeTestSpec(t, paths.Pending, spec)
	if err := os.Mkdir(paths.Active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("non-durable first promotion reported success")
	}
	if manager.status.Ready || manager.status.Error != "configuration rejected" || !backend.closed {
		t.Fatalf("non-durable interface remained active: status=%+v closed=%v", manager.status, backend.closed)
	}
}

func TestConcurrentPendingRequestsPromoteOnlyOnce(t *testing.T) {
	paths := testPaths(t)
	writeTestSpec(t, paths.Pending, testSpecification(t, 6))
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)

	const requests = 8
	results := make(chan error, requests)
	var group sync.WaitGroup
	for range requests {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- manager.ApplyPending()
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 || manager.active == nil || manager.active.Generation != 6 {
		t.Fatalf("successes=%d active=%+v", successes, manager.active)
	}
	backend.mu.Lock()
	applied := append([]uint64(nil), backend.applied...)
	backend.mu.Unlock()
	if len(applied) != 1 || applied[0] != 6 {
		t.Fatalf("backend apply sequence = %v", applied)
	}
}

func contains(text, fragment string) bool {
	return len(fragment) > 0 && len(text) >= len(fragment) && stringIndex(text, fragment) >= 0
}

func stringIndex(text, fragment string) int {
	for index := 0; index+len(fragment) <= len(text); index++ {
		if text[index:index+len(fragment)] == fragment {
			return index
		}
	}
	return -1
}
