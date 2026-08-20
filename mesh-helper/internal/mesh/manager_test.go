// SPDX-License-Identifier: MIT

package mesh

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	mu             sync.Mutex
	applied        []uint64
	failGeneration uint64
	failures       map[uint64]int
	closed         bool
	beforeApply    func(Specification)
}

func (backend *fakeBackend) Apply(spec Specification) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.beforeApply != nil {
		backend.beforeApply(spec)
	}
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

func TestLiveUpdatePublishesDirectReadyRelayClosedBeforeBackendMutation(t *testing.T) {
	paths := testPaths(t)
	active := testRelaySpecification(t, 1)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Generation = 2
	copyRelay := *active.Relay
	copyRelay.Endpoint = "192.0.2.11:51821"
	candidate.Relay = &copyRelay
	writeTestSpec(t, paths.Pending, candidate)
	backend.beforeApply = func(spec Specification) {
		if spec.Generation != candidate.Generation {
			return
		}
		data, err := os.ReadFile(paths.Status)
		if err != nil {
			t.Fatal(err)
		}
		var status Status
		if err := json.Unmarshal(data, &status); err != nil {
			t.Fatal(err)
		}
		if status.Ready || !status.Direct.Ready || status.Relay.Ready || status.Error != "updating" || status.Generation != active.Generation {
			t.Fatalf("pre-mutation status = %+v", status)
		}
	}
	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	if !manager.status.Ready || manager.status.Generation != 2 || !manager.status.Direct.Ready || !manager.status.Relay.Ready {
		t.Fatalf("final status = %+v", manager.status)
	}
}

func TestDirectorySyncFailureRestoresDurableAuthorityAndRetainsCandidate(t *testing.T) {
	paths := testPaths(t)
	active := testRelaySpecification(t, 4)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Generation = 5
	copyRelay := *active.Relay
	copyRelay.Endpoint = "192.0.2.11:51821"
	candidate.Relay = &copyRelay
	writeTestSpec(t, paths.Pending, candidate)
	manager.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	if err := manager.ApplyPending(); err == nil || !contains(err.Error(), "injected directory sync failure") {
		t.Fatalf("sync failure = %v", err)
	}
	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != active.Generation || stored.PublicDigest() != active.PublicDigest() {
		t.Fatalf("durable authority = %+v err=%v", stored, err)
	}
	claimed, err := readSpecification(paths.Claimed, uint32(os.Getuid()))
	if err != nil || claimed.Generation != candidate.Generation || claimed.PublicDigest() != candidate.PublicDigest() {
		t.Fatalf("retained candidate = %+v err=%v", claimed, err)
	}
	if !manager.status.Ready || manager.status.Generation != active.Generation || manager.status.Error != "rollback restored" {
		t.Fatalf("restored status = %+v", manager.status)
	}
}

func TestReadyPublicationFailureRecoversThroughSameGenerationReverification(t *testing.T) {
	paths := testPaths(t)
	active := testRelaySpecification(t, 1)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	candidate := active
	candidate.Generation = 2
	copyRelay := *active.Relay
	copyRelay.Endpoint = "192.0.2.11:51821"
	candidate.Relay = &copyRelay
	writeTestSpec(t, paths.Pending, candidate)
	realWrite := manager.writeStatus
	failed := false
	manager.writeStatus = func(path string, status Status) error {
		if status.Ready && status.Generation == candidate.Generation && !failed {
			failed = true
			return errors.New("injected candidate-ready publication failure")
		}
		return realWrite(path, status)
	}
	if err := manager.ApplyPending(); err == nil {
		t.Fatal("ready publication failure reported success")
	}
	if manager.active == nil || manager.active.Generation != candidate.Generation || manager.status.Ready || !manager.status.Direct.Ready {
		t.Fatalf("post-failure authority/status = active %+v status %+v", manager.active, manager.status)
	}
	writeTestSpec(t, paths.Pending, candidate)
	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	if !manager.status.Ready || manager.status.Generation != candidate.Generation || manager.status.PublicDigest != candidate.PublicDigest() {
		t.Fatalf("recovered status = %+v", manager.status)
	}
	applied := backend.appliedGenerations()
	if len(applied) < 3 || applied[len(applied)-2] != candidate.Generation || applied[len(applied)-1] != candidate.Generation {
		t.Fatalf("candidate was not reverified: %v", applied)
	}
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
	if _, err := os.Stat(paths.Claimed); err != nil {
		t.Fatal("malformed claimed evidence was not preserved")
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
	if _, err := os.Stat(paths.Claimed); err != nil {
		t.Fatal("failed claimed candidate evidence was not preserved")
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
	if _, err := os.Stat(paths.Claimed); err != nil {
		t.Fatal("claimed recovery evidence was removed")
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
	if _, err := os.Stat(paths.Claimed); err != nil {
		t.Fatal("failed claimed candidate disappeared despite removal failure")
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

func TestInterruptedClientCannotMakeClaimedApplyPromoteNewerPendingFile(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 1)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}

	claimedCandidate := active
	claimedCandidate.Generation = 2
	writeTestSpec(t, paths.Pending, claimedCandidate)
	backendEntered := make(chan struct{})
	releaseBackend := make(chan struct{})
	backend.beforeApply = func(spec Specification) {
		if spec.Generation == claimedCandidate.Generation {
			close(backendEntered)
			<-releaseBackend
		}
	}
	firstResult := make(chan error, 1)
	go func() { firstResult <- manager.ApplyPending() }()
	select {
	case <-backendEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("claimed candidate did not reach blocked backend")
	}

	claimed, err := readSpecification(paths.Claimed, uint32(os.Getuid()))
	if err != nil || claimed.Generation != claimedCandidate.Generation || claimed.PublicDigest() != claimedCandidate.PublicDigest() {
		t.Fatalf("claimed authority = %+v err=%v", claimed, err)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original pending path still names the claimed candidate: %v", err)
	}

	newer := active
	newer.Generation = 3
	writeTestSpec(t, paths.Pending, newer)
	close(releaseBackend)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("claimed transaction did not complete")
	}

	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != claimedCandidate.Generation || stored.PublicDigest() != claimedCandidate.PublicDigest() {
		t.Fatalf("first promotion used the wrong artifact: %+v err=%v", stored, err)
	}
	staged, err := readSpecification(paths.Pending, uint32(os.Getuid()))
	if err != nil || staged.Generation != newer.Generation || staged.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("newer pending authority was disturbed: %+v err=%v", staged, err)
	}
	if _, err := os.Stat(paths.Claimed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed claim remains: %v", err)
	}

	backend.beforeApply = nil
	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	stored, err = readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != newer.Generation || stored.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("newer pending generation did not promote independently: %+v err=%v", stored, err)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("newer pending file remains: %v", err)
	}
	if _, err := os.Stat(paths.Claimed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("newer claimed file remains: %v", err)
	}
	applied := backend.appliedGenerations()
	if len(applied) != 3 || applied[0] != 1 || applied[1] != 2 || applied[2] != 3 {
		t.Fatalf("backend apply sequence = %v", applied)
	}
}

func TestExpectedApplyFinishesSurvivingClaimBeforeAcknowledgingNewerPendingAuthority(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 11)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}

	claimed := active
	claimed.Generation = 12
	writeTestSpec(t, paths.Pending, claimed)
	realSyncClaim := manager.syncClaim
	failed := false
	manager.syncClaim = func(string) error {
		if !failed {
			failed = true
			return errors.New("injected claimed-directory sync failure")
		}
		return nil
	}
	if err := manager.ApplyPending(); err == nil || !contains(err.Error(), "injected claimed-directory sync failure") {
		t.Fatalf("pre-backend claim failure = %v", err)
	}
	retained, err := readSpecification(paths.Claimed, uint32(os.Getuid()))
	if err != nil || retained.Generation != claimed.Generation || retained.PublicDigest() != claimed.PublicDigest() {
		t.Fatalf("surviving claim = %+v err=%v", retained, err)
	}

	newer := active
	newer.Generation = 13
	writeTestSpec(t, paths.Pending, newer)
	manager.syncClaim = realSyncClaim
	applied, err := manager.ApplyExpected(newer.Generation, newer.PublicDigest())
	if err != nil {
		t.Fatal(err)
	}
	if applied.generation != newer.Generation || applied.digest != newer.PublicDigest() {
		t.Fatalf("acknowledged authority = %+v", applied)
	}
	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != newer.Generation || stored.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("durable authority = %+v err=%v", stored, err)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("requested pending authority remains: %v", err)
	}
	if _, err := os.Stat(paths.Claimed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("requested claimed authority remains: %v", err)
	}
	appliedGenerations := backend.appliedGenerations()
	if len(appliedGenerations) != 3 || appliedGenerations[0] != 11 || appliedGenerations[1] != 12 || appliedGenerations[2] != 13 {
		t.Fatalf("backend apply sequence = %v", appliedGenerations)
	}
}

func TestExpectedApplyReportsNewerAuthorityStillStagedWhenOlderClaimCannotFinish(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 11)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}

	claimed := active
	claimed.Generation = 12
	writeTestSpec(t, paths.Claimed, claimed)
	newer := active
	newer.Generation = 13
	writeTestSpec(t, paths.Pending, newer)
	backend.failNext(claimed.Generation)

	applied, err := manager.ApplyExpected(newer.Generation, newer.PublicDigest())
	if err == nil || !errors.Is(err, errRequestedAuthorityStillStaged) {
		t.Fatalf("older claim failure = %v", err)
	}
	if applied.generation != active.Generation || applied.digest != active.PublicDigest() {
		t.Fatalf("authority after rollback = %+v", applied)
	}
	staged, readErr := readSpecification(paths.Pending, uint32(os.Getuid()))
	if readErr != nil || staged.Generation != newer.Generation || staged.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("newer authority was not retained: %+v err=%v", staged, readErr)
	}
}

func TestClaimedRollbackDoesNotRemoveNewerPendingFile(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 1)
	writeTestSpec(t, paths.Active, active)
	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}

	failedCandidate := active
	failedCandidate.Generation = 2
	writeTestSpec(t, paths.Pending, failedCandidate)
	backend.failNext(failedCandidate.Generation)
	backendEntered := make(chan struct{})
	releaseBackend := make(chan struct{})
	backend.beforeApply = func(spec Specification) {
		if spec.Generation == failedCandidate.Generation {
			close(backendEntered)
			<-releaseBackend
		}
	}
	firstResult := make(chan error, 1)
	go func() { firstResult <- manager.ApplyPending() }()
	select {
	case <-backendEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("claimed candidate did not reach blocked backend")
	}

	newer := active
	newer.Generation = 3
	writeTestSpec(t, paths.Pending, newer)
	close(releaseBackend)
	select {
	case err := <-firstResult:
		if err == nil || !contains(err.Error(), "injected backend failure") {
			t.Fatalf("failed claimed transaction = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed claimed transaction did not complete")
	}

	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != active.Generation || stored.PublicDigest() != active.PublicDigest() {
		t.Fatalf("rollback authority = %+v err=%v", stored, err)
	}
	staged, err := readSpecification(paths.Pending, uint32(os.Getuid()))
	if err != nil || staged.Generation != newer.Generation || staged.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("rollback disturbed newer pending authority: %+v err=%v", staged, err)
	}
	if _, err := os.Stat(paths.Claimed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed claimed artifact remains after successful rollback: %v", err)
	}

	backend.beforeApply = nil
	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	stored, err = readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != newer.Generation || stored.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("newer generation did not apply after rollback: %+v err=%v", stored, err)
	}
	applied := backend.appliedGenerations()
	if len(applied) != 4 || applied[0] != 1 || applied[1] != 2 || applied[2] != 1 || applied[3] != 3 {
		t.Fatalf("backend apply sequence = %v", applied)
	}
}

func TestStartupResumesClaimedGenerationBeforeNewerPendingGeneration(t *testing.T) {
	paths := testPaths(t)
	active := testSpecification(t, 1)
	claimed := active
	claimed.Generation = 2
	newer := active
	newer.Generation = 3
	writeTestSpec(t, paths.Active, active)
	writeTestSpec(t, paths.Claimed, claimed)
	writeTestSpec(t, paths.Pending, newer)

	backend := &fakeBackend{}
	manager := testManager(t, paths, backend)
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	stored, err := readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != claimed.Generation || stored.PublicDigest() != claimed.PublicDigest() {
		t.Fatalf("startup promoted wrong authority: %+v err=%v", stored, err)
	}
	staged, err := readSpecification(paths.Pending, uint32(os.Getuid()))
	if err != nil || staged.Generation != newer.Generation || staged.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("startup disturbed newer pending authority: %+v err=%v", staged, err)
	}
	if _, err := os.Stat(paths.Claimed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup claim remains: %v", err)
	}

	if err := manager.ApplyPending(); err != nil {
		t.Fatal(err)
	}
	stored, err = readSpecification(paths.Active, uint32(os.Getuid()))
	if err != nil || stored.Generation != newer.Generation || stored.PublicDigest() != newer.PublicDigest() {
		t.Fatalf("newer pending generation did not follow recovered claim: %+v err=%v", stored, err)
	}
	applied := backend.appliedGenerations()
	if len(applied) != 2 || applied[0] != 2 || applied[1] != 3 {
		t.Fatalf("startup apply sequence = %v", applied)
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
