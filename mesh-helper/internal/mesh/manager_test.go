// SPDX-License-Identifier: MIT

package mesh

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu             sync.Mutex
	applied        []uint64
	failGeneration uint64
	failures       map[uint64]int
	closed         bool
}

func (backend *fakeBackend) Apply(spec Specification) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.applied = append(backend.applied, spec.Generation)
	if backend.failures[spec.Generation] > 0 {
		backend.failures[spec.Generation]--
		return "", errors.New("injected backend failure")
	}
	if spec.Generation == backend.failGeneration {
		return "", errors.New("injected backend failure")
	}
	return "utun-test", nil
}

func (backend *fakeBackend) failNext(generation uint64) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.failures == nil {
		backend.failures = make(map[uint64]int)
	}
	backend.failures[generation]++
}

func (backend *fakeBackend) appliedGenerations() []uint64 {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return append([]uint64(nil), backend.applied...)
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
	if manager.status.Error != "rollback restored" {
		t.Fatalf("status = %+v", manager.status)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed pending configuration remains after successful restoration")
	}
	applied := backend.appliedGenerations()
	if len(applied) < 3 || applied[len(applied)-2] != 5 || applied[len(applied)-1] != 4 {
		t.Fatalf("apply sequence = %v", applied)
	}

	rollback := active
	rollback.Generation = 3
	writeTestSpec(t, paths.Pending, rollback)
	before := len(backend.appliedGenerations())
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("generation rollback accepted")
	}
	if !manager.status.Ready || manager.status.Generation != 4 || manager.status.Error != "update refused" {
		t.Fatalf("ready road was not preserved after refusal: %+v", manager.status)
	}
	if len(backend.appliedGenerations()) != before {
		t.Fatal("pre-mutation refusal reapplied the backend")
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
	if !manager.status.Ready || manager.status.Generation != 2 || manager.status.Error != "update refused" {
		t.Fatalf("ready road was not preserved after digest refusal: %+v", manager.status)
	}
}

func TestInvalidPendingPreservesReadyRoadAndAnnotatesRefusal(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 2)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Pending, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := len(backend.appliedGenerations())
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("invalid pending configuration accepted")
	}
	if !manager.status.Ready || manager.status.Generation != 2 || manager.status.Error != "configuration rejected" {
		t.Fatalf("ready road was not preserved after malformed pending: %+v", manager.status)
	}
	if len(backend.appliedGenerations()) != before {
		t.Fatal("malformed pending configuration touched the backend")
	}
	if _, err := os.Stat(paths.Pending); err != nil {
		t.Fatal("malformed pending evidence was not preserved")
	}
}

func TestFailedCandidateAndFailedRestorationPublishUnavailable(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Generation = 5
	writeTestSpec(t, paths.Pending, candidate)
	backend.failNext(5)
	backend.failNext(4)
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("double backend failure reported success")
	}
	if manager.status.Ready || manager.status.Error != "interface unavailable" || manager.status.InterfaceName != "" {
		t.Fatalf("failed restoration claimed a ready road: %+v", manager.status)
	}
	if manager.status.Generation != 4 || manager.status.PublicDigest != active.PublicDigest() {
		t.Fatalf("unavailable status lost durable active context: %+v", manager.status)
	}
	if _, err := os.Stat(paths.Pending); err != nil {
		t.Fatal("failed candidate evidence was not preserved")
	}
	applied := backend.appliedGenerations()
	if applied[len(applied)-2] != 5 || applied[len(applied)-1] != 4 {
		t.Fatalf("apply sequence = %v", applied)
	}
}

func TestRenameFailureRestoresDurableActiveAndNeverPublishesCandidate(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Generation = 5
	writeTestSpec(t, paths.Pending, candidate)
	manager.rename = func(_, _ string) error {
		data, err := os.ReadFile(paths.Status)
		if err != nil {
			t.Fatal(err)
		}
		var observed Status
		if err := json.Unmarshal(data, &observed); err != nil {
			t.Fatal(err)
		}
		if observed.Generation == candidate.Generation {
			t.Fatal("non-durable candidate was published as active")
		}
		return errors.New("injected rename failure")
	}
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("rename failure reported success")
	}
	if !manager.status.Ready || manager.status.Generation != 4 || manager.status.Error != "rollback restored" {
		t.Fatalf("durable active configuration was not restored: %+v", manager.status)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("non-durable candidate remains after successful restoration")
	}
	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != 4 {
		t.Fatalf("durable active generation changed: %+v err=%v", stored, err)
	}
}

func TestRenameFailureAndFailedRestorationRetainRecoveryEvidence(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Generation = 5
	writeTestSpec(t, paths.Pending, candidate)
	manager.rename = func(_, _ string) error { return errors.New("injected rename failure") }
	backend.failNext(4)
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("rename and restoration failure reported success")
	}
	if manager.status.Ready || manager.status.Error != "interface unavailable" || manager.status.InterfaceName != "" {
		t.Fatalf("failed restoration claimed success: %+v", manager.status)
	}
	if _, err := os.Stat(paths.Pending); err != nil {
		t.Fatal("pending recovery evidence was removed")
	}
	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != 4 {
		t.Fatalf("active recovery evidence changed: %+v err=%v", stored, err)
	}
}

func TestStartupRefusalAppliesActiveExactlyOnceAndKeepsReason(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	rollback := active
	rollback.Generation = 3
	writeTestSpec(t, paths.Pending, rollback)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if !manager.status.Ready || manager.status.Generation != 4 || manager.status.Error != "update refused" {
		t.Fatalf("startup status = %+v", manager.status)
	}
	applied := backend.appliedGenerations()
	if len(applied) != 1 || applied[0] != 4 {
		t.Fatalf("startup apply sequence = %v", applied)
	}
}

func TestStartupCandidateFailureRestoresActiveExactlyOnce(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	candidate := active
	candidate.Generation = 5
	writeTestSpec(t, paths.Pending, candidate)
	backend := &fakeBackend{failGeneration: 5}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	if !manager.status.Ready || manager.status.Generation != 4 || manager.status.Error != "rollback restored" {
		t.Fatalf("startup status = %+v", manager.status)
	}
	applied := backend.appliedGenerations()
	if len(applied) != 2 || applied[0] != 5 || applied[1] != 4 {
		t.Fatalf("startup apply sequence = %v", applied)
	}
}

func TestStartupDoesNotSwallowRollbackStatusPublicationFailure(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	candidate := active
	candidate.Generation = 5
	writeTestSpec(t, paths.Pending, candidate)
	backend := &fakeBackend{failGeneration: 5}
	manager := testManager(t, paths, backend)
	manager.writeStatus = func(string, Status) error {
		return errors.New("injected status publication failure")
	}

	err := manager.Start()
	if err == nil || !contains(err.Error(), "injected status publication failure") {
		t.Fatalf("startup status publication failure = %v", err)
	}
	if manager.status.Ready {
		t.Fatalf("failed status publication mutated in-memory readiness: %+v", manager.status)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed candidate was not consumed before status publication")
	}
	applied := backend.appliedGenerations()
	if len(applied) != 2 || applied[0] != 5 || applied[1] != 4 {
		t.Fatalf("startup apply sequence = %v", applied)
	}
}

func TestStartupDoesNotCallRollbackRecoveredWhenPendingRemovalFails(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	candidate := active
	candidate.Generation = 5
	writeTestSpec(t, paths.Pending, candidate)
	backend := &fakeBackend{failGeneration: 5}
	manager := testManager(t, paths, backend)
	manager.remove = func(string) error {
		return errors.New("injected pending removal failure")
	}

	err := manager.Start()
	if err == nil || !contains(err.Error(), "injected pending removal failure") {
		t.Fatalf("startup pending removal failure = %v", err)
	}
	if manager.status.Ready || manager.status.Error == "rollback restored" {
		t.Fatalf("incomplete rollback claimed recovery: %+v", manager.status)
	}
	if _, err := os.Stat(paths.Pending); err != nil {
		t.Fatal("failed candidate evidence disappeared despite removal failure")
	}
	applied := backend.appliedGenerations()
	if len(applied) != 2 || applied[0] != 5 || applied[1] != 4 {
		t.Fatalf("startup apply sequence = %v", applied)
	}
}

func TestIdempotentReapplyClearsPriorBoundedError(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	manager := testManager(t, paths, &fakeBackend{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	rollback := active
	rollback.Generation = 3
	writeTestSpec(t, paths.Pending, rollback)
	_ = manager.ApplyPending()
	if manager.status.Error != "update refused" {
		t.Fatalf("refusal was not recorded: %+v", manager.status)
	}
	writeTestSpec(t, paths.Pending, active)
	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	if !manager.status.Ready || manager.status.Error != "" {
		t.Fatalf("successful reapply retained stale error: %+v", manager.status)
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
