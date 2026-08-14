package manager

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"systems.reach/relay-hub/internal/backend"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/router"
	statuspkg "systems.reach/relay-hub/internal/status"
	"systems.reach/relay-hub/internal/testutil"
)

func routedPacket(source, destination [4]byte) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], source[:])
	copy(p[16:20], destination[:])
	return p
}

func setup(t *testing.T) (*Manager, *backend.Fake, *router.Router, Paths) {
	t.Helper()
	dir := t.TempDir()
	paths := Paths{Active: filepath.Join(dir, "private", "active.json"), Pending: filepath.Join(dir, "private", "pending.json"), Status: filepath.Join(dir, "public", "status.json")}
	f := &backend.Fake{}
	r := router.New()
	uid := uint32(os.Getuid())
	return New(paths, &uid, config.StaticRoutes{}, f, r), f, r, paths
}
func applySpec(t *testing.T, m *Manager, s config.Specification) error {
	t.Helper()
	b, err := s.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return m.Apply(b)
}
func readSpec(t *testing.T, path string) config.Specification {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := config.Decode(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func readStatus(t *testing.T, path string) statuspkg.Status {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s statuspkg.Status
	if err = json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInitialAndUpdateDurableBeforeReady(t *testing.T) {
	m, f, r, paths := setup(t)
	first := testutil.Spec(1, 1)
	if err := applySpec(t, m, first); err != nil {
		t.Fatal(err)
	}
	if got := readSpec(t, paths.Active); got.Generation != 1 {
		t.Fatal(got.Generation)
	}
	if !r.Metrics().Open || r.Metrics().Generation != 1 {
		t.Fatal(r.Metrics())
	}
	second := testutil.Spec(2, 2)
	if err := applySpec(t, m, second); err != nil {
		t.Fatal(err)
	}
	if got := readSpec(t, paths.Active); got.Generation != 2 {
		t.Fatal(got.Generation)
	}
	if s := readStatus(t, paths.Status); !s.Ready || s.Generation != 2 {
		t.Fatalf("%+v", s)
	}
	if f.Calls != 2 {
		t.Fatal(f.Calls)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending retained")
	}
}

func TestInitialGenerationAndFrozenFieldsRefuseBeforeMutation(t *testing.T) {
	m, f, _, _ := setup(t)
	if err := applySpec(t, m, testutil.Spec(2, 1)); err == nil {
		t.Fatal("non-one initial accepted")
	}
	if f.Calls != 0 {
		t.Fatal(f.Calls)
	}
	first := testutil.Spec(1, 1)
	if err := applySpec(t, m, first); err != nil {
		t.Fatal(err)
	}
	next := testutil.Spec(2, 1)
	next.ListenPort++
	if err := applySpec(t, m, next); err == nil {
		t.Fatal("port mutation accepted")
	}
	if f.Calls != 1 {
		t.Fatal(f.Calls)
	}
}

func TestIdempotentApplyRemovesPending(t *testing.T) {
	m, f, _, paths := setup(t)
	s := testutil.Spec(1, 1)
	if err := applySpec(t, m, s); err != nil {
		t.Fatal(err)
	}
	if err := applySpec(t, m, s); err != nil {
		t.Fatal(err)
	}
	if f.Calls != 1 {
		t.Fatal(f.Calls)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending retained")
	}
}

func TestCandidateFailureRestoresPriorAuthority(t *testing.T) {
	m, f, r, paths := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	f.ApplyErrors = []error{errors.New("candidate failed"), nil}
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("failure hidden")
	}
	if got := readSpec(t, paths.Active); got.Generation != 1 {
		t.Fatal(got.Generation)
	}
	if !r.Metrics().Open || r.Metrics().Generation != 1 {
		t.Fatal(r.Metrics())
	}
	s := readStatus(t, paths.Status)
	if !s.Ready || s.Generation != 1 || s.Error != "rollback restored" {
		t.Fatalf("%+v", s)
	}
}

func TestPromotionFailureRestoresDurablePriorAuthority(t *testing.T) {
	m, f, r, paths := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	m.promoteSpec = func(string, string) error { return errors.New("promotion failed") }
	f.ApplyErrors = []error{nil, nil}
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("promotion failure hidden")
	}
	if got := readSpec(t, paths.Active); got.Generation != 1 {
		t.Fatal(got.Generation)
	}
	if !r.Metrics().Open || r.Metrics().Generation != 1 {
		t.Fatal(r.Metrics())
	}
	if s := readStatus(t, paths.Status); !s.Ready || s.Generation != 1 || s.Error != "rollback restored" {
		t.Fatalf("%+v", s)
	}
}

func TestRollbackFailureStaysClosedAndUnready(t *testing.T) {
	m, f, r, paths := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	m.promoteSpec = func(string, string) error { return errors.New("promotion failed") }
	f.ApplyErrors = []error{nil, errors.New("rollback failed")}
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("rollback failure hidden")
	}
	if r.Metrics().Open {
		t.Fatal("forwarding reopened after failed rollback")
	}
	if got := readSpec(t, paths.Active); got.Generation != 1 {
		t.Fatal(got.Generation)
	}
	if s := readStatus(t, paths.Status); s.Ready || s.Generation != 1 || s.Error != "backend unavailable" {
		t.Fatalf("%+v", s)
	}
}

func TestPreMutationStatusFailureLeavesPeersAndNoPending(t *testing.T) {
	m, f, _, paths := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	m.writeStatus = func(_ string, s statuspkg.Status) error {
		if !s.Ready {
			return errors.New("status fail")
		}
		return nil
	}
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("status failure hidden")
	}
	if f.Calls != 1 {
		t.Fatal(f.Calls)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending retained")
	}
	if got := readSpec(t, paths.Active); got.Generation != 1 {
		t.Fatal(got.Generation)
	}
}

func TestPostPromotionStatusFailureKeepsNewAuthority(t *testing.T) {
	m, f, r, paths := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	original := m.writeStatus
	m.writeStatus = func(path string, s statuspkg.Status) error {
		if s.Ready && s.Generation == 2 {
			return errors.New("ready write failed")
		}
		return original(path, s)
	}
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("status failure hidden")
	}
	if got := readSpec(t, paths.Active); got.Generation != 2 {
		t.Fatal(got.Generation)
	}
	if f.Calls != 2 || !r.Metrics().Open || r.Metrics().Generation != 2 {
		t.Fatal(f.Calls, r.Metrics())
	}
	s := readStatus(t, paths.Status)
	if s.Ready || s.Generation != 1 {
		t.Fatalf("conservative status %+v", s)
	}
	m.writeStatus = original
	if err := applySpec(t, m, testutil.Spec(2, 2)); err != nil {
		t.Fatal(err)
	}
	if f.Calls != 2 {
		t.Fatal("status-only retry mutated peers")
	}
	if s = readStatus(t, paths.Status); !s.Ready || s.Generation != 2 {
		t.Fatalf("status-only recovery %+v", s)
	}
}

func TestSameGenerationRetryRefusesDriftAndRecoversOnlyAfterAuthorityMatches(t *testing.T) {
	m, f, r, paths := setup(t)
	spec := testutil.Spec(1, 1)
	if err := applySpec(t, m, spec); err != nil {
		t.Fatal(err)
	}
	initialCalls := f.Calls

	f.Mu.Lock()
	delete(f.Current, spec.Host.PublicKey)
	f.Mu.Unlock()
	if err := applySpec(t, m, spec); err == nil {
		t.Fatal("same-generation retry accepted backend drift")
	}
	if f.Calls != initialCalls {
		t.Fatal("readiness retry mutated backend")
	}
	if status := readStatus(t, paths.Status); status.Ready || status.Generation != 1 || status.Error != "backend unavailable" {
		t.Fatalf("backend drift status %+v", status)
	}
	if err := f.ApplyManifest(spec.Peers()); err != nil {
		t.Fatal(err)
	}
	repairedCalls := f.Calls
	if err := applySpec(t, m, spec); err != nil {
		t.Fatal(err)
	}
	if f.Calls != repairedCalls {
		t.Fatal("backend recovery retry mutated peers")
	}
	if status := readStatus(t, paths.Status); !status.Ready || status.Generation != 1 || status.Error != "" {
		t.Fatalf("backend recovery status %+v", status)
	}

	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	if err := applySpec(t, m, spec); err == nil {
		t.Fatal("same-generation retry accepted a closed router")
	}
	if status := readStatus(t, paths.Status); status.Ready || status.Generation != 1 || status.Error != "backend unavailable" {
		t.Fatalf("closed-router status %+v", status)
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := applySpec(t, m, spec); err != nil {
		t.Fatal(err)
	}
	if status := readStatus(t, paths.Status); !status.Ready || status.Generation != 1 || status.Error != "" {
		t.Fatalf("router recovery status %+v", status)
	}

	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	wrongSnapshot, err := router.SnapshotFor(testutil.Spec(2, 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(wrongSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := applySpec(t, m, spec); err == nil {
		t.Fatal("same-generation retry accepted a mismatched router snapshot")
	}
	if status := readStatus(t, paths.Status); status.Ready || status.Generation != 1 || status.Error != "backend unavailable" {
		t.Fatalf("mismatched-router status %+v", status)
	}
	if err := r.Quiesce(); err != nil {
		t.Fatal(err)
	}
	matchingSnapshot, err := router.SnapshotFor(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Install(matchingSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := r.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := applySpec(t, m, spec); err != nil {
		t.Fatal(err)
	}
	if status := readStatus(t, paths.Status); !status.Ready || status.Generation != 1 || status.Error != "" {
		t.Fatalf("snapshot recovery status %+v", status)
	}
}

func TestStartRestoresOnlyActiveAndDiscardsPending(t *testing.T) {
	m, _, _, paths := setup(t)
	first := testutil.Spec(1, 1)
	if err := applySpec(t, m, first); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	second := testutil.Spec(2, 2)
	data, _ := second.CanonicalJSON()
	if err := writeAtomically(paths.Pending, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &backend.Fake{}
	r := router.New()
	uid := uint32(os.Getuid())
	restart := New(paths, &uid, config.StaticRoutes{}, f, r)
	if err := restart.Start(); err != nil {
		t.Fatal(err)
	}
	if got := readSpec(t, paths.Active); got.Generation != 1 {
		t.Fatal(got.Generation)
	}
	if f.Calls != 1 {
		t.Fatal(f.Calls)
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("crash-left pending state was retained")
	}
	if !r.Metrics().Open || r.Metrics().Generation != 1 {
		t.Fatal(r.Metrics())
	}
}

func TestStartWithoutActiveDiscardsPendingAndStaysUnconfigured(t *testing.T) {
	m, f, r, paths := setup(t)
	data, _ := testutil.Spec(1, 1).CanonicalJSON()
	if err := writeAtomically(paths.Pending, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if f.Calls != 0 || r.Metrics().Open {
		t.Fatal(f.Calls, r.Metrics())
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unpromoted initial candidate was retained")
	}
	if s := readStatus(t, paths.Status); s.Ready || s.Error != "unconfigured" {
		t.Fatalf("%+v", s)
	}
}

func TestUpdateKeepsForwardingClosedUntilCandidateSnapshotReopens(t *testing.T) {
	m, _, r, _ := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	oldPacket := routedPacket([4]byte{10, 87, 0, 1}, [4]byte{10, 87, 0, 2})
	newPacket := routedPacket([4]byte{10, 87, 0, 1}, [4]byte{10, 87, 0, 3})
	closedStages := 0
	writeClosed := func(packet []byte) func() {
		return func() {
			_, _ = r.Write([][]byte{packet}, 0)
			closedStages++
		}
	}
	m.hooks = transactionHooks{
		afterReadyFalse: func() {
			_, _ = r.Write([][]byte{oldPacket}, 0)
			if r.Metrics().QueuedPackets != 1 {
				t.Fatal("pre-quiescence packet was not accepted")
			}
		},
		afterQuiesce:         writeClosed(oldPacket),
		afterPeerApply:       writeClosed(oldPacket),
		afterPeerVerify:      writeClosed(oldPacket),
		afterPromotion:       writeClosed(newPacket),
		afterSnapshotInstall: writeClosed(newPacket),
		afterReopen: func() {
			_, _ = r.Write([][]byte{newPacket}, 0)
		},
	}
	if err := applySpec(t, m, testutil.Spec(2, 2)); err != nil {
		t.Fatal(err)
	}
	metrics := r.Metrics()
	if closedStages != 5 || metrics.Drops[router.DropQuiesced] != 5 || metrics.QueuedPackets != 1 || metrics.QueuedBytes != len(newPacket) || !metrics.Open || metrics.Generation != 2 {
		t.Fatalf("transaction forwarding gate %+v stages=%d", metrics, closedStages)
	}
}

func TestRollbackKeepsForwardingClosedUntilPriorSnapshotReturns(t *testing.T) {
	m, f, r, _ := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	packet := routedPacket([4]byte{10, 87, 0, 1}, [4]byte{10, 87, 0, 2})
	f.ApplyErrors = []error{errors.New("candidate failed"), nil}
	f.ApplyHook = func() { _, _ = r.Write([][]byte{packet}, 0) }
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("candidate failure hidden")
	}
	metrics := r.Metrics()
	if metrics.Drops[router.DropQuiesced] != 2 || !metrics.Open || metrics.Generation != 1 || metrics.QueuedPackets != 0 {
		t.Fatalf("rollback forwarding gate %+v", metrics)
	}
}

func TestInitialStatusFailureRemovesNewPendingCandidate(t *testing.T) {
	m, f, _, paths := setup(t)
	m.writeStatus = func(string, statuspkg.Status) error { return errors.New("status unavailable") }
	if err := applySpec(t, m, testutil.Spec(1, 1)); err == nil {
		t.Fatal("status failure hidden")
	}
	if f.Calls != 0 {
		t.Fatal("backend mutated")
	}
	if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed initial candidate remained pending")
	}
}

func TestInitialBackendAndPromotionFailuresRemovePending(t *testing.T) {
	t.Run("backend", func(t *testing.T) {
		m, f, _, paths := setup(t)
		f.FailInitial = errors.New("backend failed")
		if err := applySpec(t, m, testutil.Spec(1, 1)); err == nil {
			t.Fatal("backend failure hidden")
		}
		if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed backend candidate remained pending")
		}
	})
	t.Run("promotion", func(t *testing.T) {
		m, f, _, paths := setup(t)
		m.promoteSpec = func(string, string) error { return errors.New("promotion failed") }
		if err := applySpec(t, m, testutil.Spec(1, 1)); err == nil {
			t.Fatal("promotion failure hidden")
		}
		if !f.Closed {
			t.Fatal("backend remained open")
		}
		if _, err := os.Stat(paths.Pending); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed promotion candidate remained pending")
		}
	})
}

func TestStaleTemporaryFilesDoNotBlockAtomicWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.json")
	if err := os.WriteFile(filepath.Join(dir, ".active.json.tmp-stale"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomically(path, []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "current" {
		t.Fatal(string(data), err)
	}
}

func TestConcurrentGenerationsSerializeAndStaleGenerationCannotMutate(t *testing.T) {
	m, f, r, paths := setup(t)
	if err := applySpec(t, m, testutil.Spec(1, 1)); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.ApplyHook = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	errorsByGeneration := make(chan error, 2)
	go func() { errorsByGeneration <- applySpec(t, m, testutil.Spec(2, 2)) }()
	<-entered
	go func() { errorsByGeneration <- applySpec(t, m, testutil.Spec(3, 3)) }()
	close(release)
	for range 2 {
		if err := <-errorsByGeneration; err != nil {
			t.Fatal(err)
		}
	}
	if got := readSpec(t, paths.Active); got.Generation != 3 {
		t.Fatal(got.Generation)
	}
	if !r.Metrics().Open || r.Metrics().Generation != 3 {
		t.Fatal(r.Metrics())
	}
	calls := f.Calls
	if err := applySpec(t, m, testutil.Spec(2, 2)); err == nil {
		t.Fatal("stale generation accepted")
	}
	if f.Calls != calls {
		t.Fatal("stale generation mutated backend")
	}
}
