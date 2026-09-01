package packageupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"reach.dev/exo-runtime/internal/authority"
)

type fakeService struct {
	enabled      bool
	active       bool
	stops        int
	starts       int
	reloads      int
	failReloadAt int
}

func (s *fakeService) Intent() (bool, bool, error) { return s.enabled, s.active, nil }
func (s *fakeService) Stop() error                 { s.stops++; s.active = false; return nil }
func (s *fakeService) SetEnabled(value bool) error { s.enabled = value; return nil }
func (s *fakeService) Start() error                { s.starts++; s.active = true; return nil }
func (s *fakeService) Reload() error {
	s.reloads++
	if s.failReloadAt == s.reloads {
		return errors.New("injected reload failure")
	}
	return nil
}

func TestEveryDurablePhaseRecoversToExactB(t *testing.T) {
	for _, phase := range durablePhases[:len(durablePhases)-1] {
		t.Run(phase, func(t *testing.T) {
			fixture := newFixture(t, true, true)
			before := inodeOf(t, authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node"))
			err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: phase, skipAuthorityValidation: true})
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("phase %s did not inject: %v", phase, err)
			}
			state, completion, err := readRecoveryJournal(fixture.paths)
			if err != nil {
				t.Fatal(err)
			}
			if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
				t.Fatal(err)
			}
			if err := VerifyInstalled(fixture.paths, fixture.candidate); err != nil {
				t.Fatal(err)
			}
			if transactionEvidenceExists(fixture.paths) {
				t.Fatal("transaction evidence survived settlement")
			}
			if got := inodeOf(t, authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")); got == before {
				t.Fatal("program object was patched in place")
			}
			if !fixture.service.enabled || !fixture.service.active {
				t.Fatal("enabled/active intent was not restored")
			}
		})
	}
}

func TestJournalAndGuardEdgesRecoverWithoutPreWithdrawalMutation(t *testing.T) {
	for _, edge := range []string{
		"journal-staged", "journal-published", "authenticated", "guard-published",
		"guard-reloaded", "journal-promoted", "guarded",
	} {
		t.Run(edge, func(t *testing.T) {
			fixture := newFixture(t, true, true)
			node := authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")
			before, err := os.ReadFile(node)
			if err != nil {
				t.Fatal(err)
			}
			beforeInode := inodeOf(t, node)
			err = Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: edge, skipAuthorityValidation: true})
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("edge %s did not inject: %v", edge, err)
			}
			after, err := os.ReadFile(node)
			if err != nil || string(after) != string(before) || inodeOf(t, node) != beforeInode {
				t.Fatal("installed package moved before withdrawal was established")
			}
			if fixture.service.stops != 0 {
				t.Fatal("service stop preceded durable withdrawal establishment")
			}
			if err := promoteStagedJournal(fixture.paths); err != nil {
				t.Fatal(err)
			}
			state, completion, err := readRecoveryJournal(fixture.paths)
			if err != nil {
				t.Fatal(err)
			}
			if completion || !state.WasEnabled || !state.WasActive {
				t.Fatal("pending journal did not retain exact service intent")
			}
			if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
				t.Fatal(err)
			}
			assertSettledCandidate(t, fixture)
		})
	}
}

func TestUnpublishedJournalStagingConvergesWithoutUnrecordedIntent(t *testing.T) {
	for _, edge := range []string{"journal-staging-created", "partial-journal-write"} {
		t.Run(edge, func(t *testing.T) {
			fixture := newFixture(t, true, true)
			node := authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")
			before, err := os.ReadFile(node)
			if err != nil {
				t.Fatal(err)
			}
			if edge == "journal-staging-created" {
				err = Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: edge, skipAuthorityValidation: true})
				if !errors.Is(err, ErrInjected) {
					t.Fatalf("staging edge did not inject: %v", err)
				}
			} else {
				if err := os.MkdirAll(stagedJournalRoot(fixture.paths), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(stagedJournalRoot(fixture.paths), "pending.json.tmp"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := os.Lstat(fixture.paths.GuardPath); !os.IsNotExist(err) {
				t.Fatal("unpublished staging created a guard")
			}
			if fixture.service.reloads != 0 || fixture.service.stops != 0 {
				t.Fatal("unpublished staging changed service state")
			}
			after, err := os.ReadFile(node)
			if err != nil || string(after) != string(before) {
				t.Fatal("unpublished staging changed installed bytes")
			}
			discarded, err := discardUnpublishedStaging(fixture.paths)
			if err != nil || !discarded {
				t.Fatalf("safe unpublished staging did not converge: discarded=%t err=%v", discarded, err)
			}
			if transactionEvidenceExists(fixture.paths) {
				t.Fatal("unpublished staging survived safe convergence")
			}
			if err := VerifyInstalled(fixture.paths, fixture.parent); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGuardReloadFailureLeavesRecoverablePendingIntent(t *testing.T) {
	fixture := newFixture(t, true, true)
	fixture.service.failReloadAt = 1
	node := authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")
	before, err := os.ReadFile(node)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err == nil || !strings.Contains(err.Error(), "reload") {
		t.Fatalf("guard reload failure was not retained: %v", err)
	}
	after, err := os.ReadFile(node)
	if err != nil || string(after) != string(before) || fixture.service.stops != 0 {
		t.Fatal("reload failure mutated installed bytes or stopped the service")
	}
	state, completion, err := readRecoveryJournal(fixture.paths)
	if err != nil || completion || state.Phase != "authenticated" {
		t.Fatalf("reload failure did not leave exact pending authority: state=%+v completion=%t err=%v", state, completion, err)
	}
	fixture.service.failReloadAt = 0
	if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
		t.Fatal(err)
	}
	assertSettledCandidate(t, fixture)
}

func TestRuntimeStartRefusesStagedJournalWithoutGuard(t *testing.T) {
	fixture := newFixture(t, true, true)
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	err := Execute(Request{Operation: "rollback", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: "journal-staged", skipAuthorityValidation: true})
	if !errors.Is(err, ErrInjected) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fixture.paths.GuardPath); !os.IsNotExist(err) {
		t.Fatal("guard unexpectedly preceded the durable staged journal")
	}
	if err := VerifyRuntimeAuthority(fixture.paths); err == nil || !strings.Contains(err.Error(), "staged package transaction") {
		t.Fatalf("runtime start admitted staged transaction authority: %v", err)
	}
	if err := promoteStagedJournal(fixture.paths); err != nil {
		t.Fatal(err)
	}
	state, completion, err := readRecoveryJournal(fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstalled(fixture.paths, fixture.parent); err != nil {
		t.Fatal(err)
	}
}

func TestGuardWithdrawalEdgesRecoverWithoutOrphan(t *testing.T) {
	for _, edge := range []string{"guard-removed", "guard-removal-reloaded"} {
		t.Run(edge, func(t *testing.T) {
			fixture := newFixture(t, true, true)
			err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: edge, skipAuthorityValidation: true})
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("edge %s did not inject: %v", edge, err)
			}
			if _, err := os.Lstat(fixture.paths.GuardPath); !os.IsNotExist(err) {
				t.Fatal("removed guard survived its durable withdrawal edge")
			}
			state, completion, err := readRecoveryJournal(fixture.paths)
			if err != nil || !completion {
				t.Fatalf("completion authority missing after guard withdrawal: %v", err)
			}
			if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
				t.Fatal(err)
			}
			assertSettledCandidate(t, fixture)
		})
	}
}

func TestReceiptParentDurabilityEdgesRecoverUpdateAndRollback(t *testing.T) {
	for _, edge := range []string{"receipt-created", "receipt-create-parent-synced"} {
		t.Run("update-"+edge, func(t *testing.T) {
			fixture := newFixture(t, true, true)
			err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: edge, skipAuthorityValidation: true})
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("edge %s did not inject: %v", edge, err)
			}
			state, completion, err := readRecoveryJournal(fixture.paths)
			if err != nil || completion || state.Phase != "tmpfiles" {
				t.Fatalf("receipt creation advanced before parent durability: state=%+v completion=%t err=%v", state, completion, err)
			}
			if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
				t.Fatal(err)
			}
			assertSettledCandidate(t, fixture)
		})
	}
	for _, edge := range []string{"receipt-removed", "receipt-remove-parent-synced"} {
		t.Run("rollback-"+edge, func(t *testing.T) {
			fixture := newFixture(t, true, false)
			if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
				t.Fatal(err)
			}
			err := Execute(Request{Operation: "rollback", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: edge, skipAuthorityValidation: true})
			if !errors.Is(err, ErrInjected) {
				t.Fatalf("edge %s did not inject: %v", edge, err)
			}
			state, completion, err := readRecoveryJournal(fixture.paths)
			if err != nil || completion || state.Phase != "tmpfiles" {
				t.Fatalf("receipt removal advanced before parent durability: state=%+v completion=%t err=%v", state, completion, err)
			}
			if err := recoverLoaded(fixture.paths, fixture.service, fixture.candidate, fixture.parent, state, completion, "", true); err != nil {
				t.Fatal(err)
			}
			if err := VerifyInstalled(fixture.paths, fixture.parent); err != nil {
				t.Fatal(err)
			}
			if transactionEvidenceExists(fixture.paths) {
				t.Fatal("rollback receipt recovery left transaction evidence")
			}
		})
	}
}

func TestLockDescriptorDriftFailsBeforeInstalledMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *testFixture)
	}{
		{"symlink", func(t *testing.T, fixture *testFixture) {
			target := filepath.Join(filepath.Dir(fixture.paths.LockPath), "lock-target")
			if err := os.WriteFile(target, []byte("sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, fixture.paths.LockPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"nonregular", func(t *testing.T, fixture *testFixture) {
			if err := os.Mkdir(fixture.paths.LockPath, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong-owner", func(t *testing.T, fixture *testFixture) {
			if err := os.WriteFile(fixture.paths.LockPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			fixture.paths.ExpectedOwner++
		}},
		{"wrong-mode", func(t *testing.T, fixture *testFixture) {
			if err := os.WriteFile(fixture.paths.LockPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(fixture.paths.LockPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"multiple-links", func(t *testing.T, fixture *testFixture) {
			if err := os.WriteFile(fixture.paths.LockPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(fixture.paths.LockPath, fixture.paths.LockPath+".alias"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, true, false)
			if err := os.MkdirAll(filepath.Dir(fixture.paths.LockPath), 0755); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, &fixture)
			node := authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")
			before, err := os.ReadFile(node)
			if err != nil {
				t.Fatal(err)
			}
			beforeInode := inodeOf(t, node)
			err = Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true})
			if err == nil {
				t.Fatal("invalid lock descriptor tuple was accepted")
			}
			after, readErr := os.ReadFile(node)
			if readErr != nil || string(after) != string(before) || inodeOf(t, node) != beforeInode || fixture.service.stops != 0 || fixture.service.reloads != 0 || transactionEvidenceExists(fixture.paths) {
				t.Fatal("lock drift crossed the pre-mutation boundary")
			}
		})
	}
}

func TestLockDescriptorIsExactAndCloseOnExec(t *testing.T) {
	fixture := newFixture(t, true, false)
	lock, err := acquireLock(fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseLock(lock)
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || ownerID(info) != fixture.paths.ExpectedOwner || linkCount(info) != 1 {
		t.Fatalf("lock descriptor tuple differs: info=%v err=%v", info, err)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, lock.Fd(), uintptr(syscall.F_GETFD), 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("lock descriptor is not close-on-exec: flags=%d errno=%v", flags, errno)
	}
}

func assertSettledCandidate(t *testing.T, fixture testFixture) {
	t.Helper()
	if err := VerifyInstalled(fixture.paths, fixture.candidate); err != nil {
		t.Fatal(err)
	}
	if transactionEvidenceExists(fixture.paths) {
		t.Fatal("transaction evidence survived settlement")
	}
	if !fixture.service.enabled || !fixture.service.active {
		t.Fatal("service intent was not restored")
	}
}

func TestUpdateRollbackPreservesOperatorStateAndIdentity(t *testing.T) {
	fixture := newFixture(t, false, true)
	config := authorityPath(fixture.paths.RootPrefix, "/etc/reach-exo/node.json")
	tls := authorityPath(fixture.paths.RootPrefix, "/etc/reach-exo/tls/node.pem")
	model := authorityPath(fixture.paths.RootPrefix, "/srv/reach-exo-models/model.safetensors")
	for path, value := range map[string]string{config: "config", tls: "tls", model: "model"} {
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRuntimeAuthority(fixture.paths); err != nil {
		t.Fatal(err)
	}
	if fixture.service.enabled || !fixture.service.active {
		t.Fatal("disabled but manually-active service intent changed")
	}
	if err := Execute(Request{Operation: "rollback", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInstalled(fixture.paths, fixture.parent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(authorityPath(fixture.paths.RootPrefix, "/var/lib/reach-exo/receipts")); !os.IsNotExist(err) {
		t.Fatal("B receipt survived exact-parent rollback")
	}
	for path, want := range map[string]string{config: "config", tls: "tls", model: "model"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("operator path %s changed", path)
		}
	}
}

func TestAllServiceIntentPairsSurviveUpdate(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, active := range []bool{false, true} {
			name := fmt.Sprintf("enabled-%t-active-%t", enabled, active)
			t.Run(name, func(t *testing.T) {
				fixture := newFixture(t, enabled, active)
				if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
					t.Fatal(err)
				}
				if fixture.service.enabled != enabled || fixture.service.active != active {
					t.Fatalf("service intent became enabled=%t active=%t", fixture.service.enabled, fixture.service.active)
				}
			})
		}
	}
}

func TestUpdateAndRollbackInstallImmutableProgramTrees(t *testing.T) {
	fixture := newFixture(t, true, false)
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	assertProgramTreeReadOnly(t, fixture.paths)
	if err := Execute(Request{Operation: "rollback", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	assertProgramTreeReadOnly(t, fixture.paths)
}

func TestBAccountReceiptUsesExactRemovalTuple(t *testing.T) {
	fixture := newFixture(t, true, false)
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	marker := authorityPath(fixture.paths.RootPrefix, "/var/lib/reach-exo/.bundle-created-account")
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || ownerID(info) != fixture.paths.ExpectedOwner || linkCount(info) != 1 {
		t.Fatalf("B account marker does not match removal authority: info=%v err=%v", info, err)
	}
}

func TestServiceRuntimeAuthorityDefersRootOnlyAccountReceiptContentToPreflight(t *testing.T) {
	fixture := newFixture(t, true, false)
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	marker := authorityPath(fixture.paths.RootPrefix, "/var/lib/reach-exo/.bundle-created-account")
	if err := os.WriteFile(marker, []byte("unreadable-to-service-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRuntimeAuthority(fixture.paths); err == nil {
		t.Fatal("privileged runtime preflight accepted corrupt account receipt content")
	}
	if err := VerifyServiceRuntimeAuthority(fixture.paths); err != nil {
		t.Fatalf("service runtime rejected the root-authenticated 0600 marker tuple: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := VerifyServiceRuntimeAuthority(fixture.paths); err == nil {
		t.Fatal("service runtime accepted an absent account receipt tuple")
	}
}

func TestAuthenticationAndExclusionFailBeforeMutation(t *testing.T) {
	fixture := newFixture(t, true, false)
	node := authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")
	before, err := os.ReadFile(node)
	if err != nil {
		t.Fatal(err)
	}
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths}); err == nil {
		t.Fatal("unauthenticated synthetic artifact was accepted")
	}
	after, err := os.ReadFile(node)
	if err != nil || string(after) != string(before) || transactionEvidenceExists(fixture.paths) {
		t.Fatal("authentication failure mutated installed or transaction state")
	}

	lock, err := acquireLock(fixture.paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckIdle(fixture.paths); err == nil {
		t.Fatal("concurrent configure/remove authority was admitted")
	}
	releaseLock(lock)

	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: "stopped", skipAuthorityValidation: true}); !errors.Is(err, ErrInjected) {
		t.Fatal(err)
	}
	if err := CheckIdle(fixture.paths); err == nil {
		t.Fatal("incomplete transaction admitted another operation")
	}
}

func TestInstalledManifestModeAndOwnershipDriftRefuseBeforeJournal(t *testing.T) {
	fixture := newFixture(t, true, false)
	node := authorityPath(fixture.paths.RootPrefix, "/opt/reach-exo/bin/reach-exo-node")
	if err := os.Chmod(node, 0777); err != nil {
		t.Fatal(err)
	}
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err == nil {
		t.Fatal("installed mode drift was accepted")
	}
	if transactionEvidenceExists(fixture.paths) || fixture.service.stops != 0 {
		t.Fatal("installed drift crossed the authentication boundary")
	}
}

func TestCorruptMissingAndWrongRecoveryAuthorityStaysGuarded(t *testing.T) {
	fixture := newFixture(t, true, false)
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: "program", skipAuthorityValidation: true}); !errors.Is(err, ErrInjected) {
		t.Fatal(err)
	}
	if _, _, err := readRecoveryJournal(fixture.paths); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(journalPath(fixture.paths), []byte("not-json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRecoveryJournal(fixture.paths); err == nil {
		t.Fatal("corrupt journal was accepted")
	}
	if _, err := os.Lstat(fixture.paths.GuardPath); err != nil {
		t.Fatal("corrupt recovery withdrew the service guard")
	}
	if err := os.Remove(journalPath(fixture.paths)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRecoveryJournal(fixture.paths); err == nil {
		t.Fatal("missing journal was accepted")
	}
}

func TestRecoveryJournalStrictlyRejectsAmbiguityTupleAndRelation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, testFixture, journal)
	}{
		{"trailing value", func(t *testing.T, fixture testFixture, _ journal) {
			path := journalPath(fixture.paths)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := atomicWrite(path, append(data, []byte("{}\n")...), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong tuple", func(t *testing.T, fixture testFixture, _ journal) {
			if err := os.Chmod(journalPath(fixture.paths), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"hard linked", func(t *testing.T, fixture testFixture, _ journal) {
			if err := os.Link(journalPath(fixture.paths), filepath.Join(filepath.Dir(fixture.paths.RootPrefix), "journal-alias")); err != nil {
				t.Fatal(err)
			}
		}},
		{"ambiguous entry", func(t *testing.T, fixture testFixture, _ journal) {
			if err := os.WriteFile(filepath.Join(fixture.paths.TransactionRoot, "unexpected"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"source target contradiction", func(t *testing.T, fixture testFixture, state journal) {
			state.SourceVersion = authority.BundleVersion
			if err := writeJournal(fixture.paths, journalPath(fixture.paths), state); err != nil {
				t.Fatal(err)
			}
		}},
		{"artifact relation contradiction", func(t *testing.T, fixture testFixture, state journal) {
			state.CandidateRoot = state.ParentRoot
			if err := writeJournal(fixture.paths, journalPath(fixture.paths), state); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFixture(t, true, false)
			if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, InterruptAfterPhase: "program", skipAuthorityValidation: true}); !errors.Is(err, ErrInjected) {
				t.Fatal(err)
			}
			state, _, err := readRecoveryJournal(fixture.paths)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, fixture, state)
			if _, _, err := readRecoveryJournal(fixture.paths); err == nil {
				t.Fatal("ambiguous recovery evidence was accepted")
			}
			if _, err := os.Lstat(fixture.paths.GuardPath); err != nil {
				t.Fatal("invalid recovery evidence withdrew the service guard")
			}
		})
	}
}

func TestRuntimeStartRefusesUnrecognizedTransactionBoundary(t *testing.T) {
	fixture := newFixture(t, true, false)
	if err := Execute(Request{Operation: "update", Candidate: fixture.candidate, Parent: fixture.parent, Service: fixture.service, Paths: fixture.paths, skipAuthorityValidation: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fixture.paths.TransactionRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.paths.TransactionRoot, "unknown"), []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRuntimeAuthority(fixture.paths); err == nil {
		t.Fatal("provider start crossed an unrecognized transaction boundary")
	}
}

func TestCandidateRelationAndRuntimePairTable(t *testing.T) {
	fixture := newFixture(t, true, false)
	if err := fixture.candidate.ValidateCandidate(); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Artifact){
		"equal version":    func(a *Artifact) { a.Metadata.BundleVersion = authority.ParentBundleVersion },
		"wrong parent":     func(a *Artifact) { a.Metadata.ParentBundleVersion = "0.0.9" },
		"unknown parent":   func(a *Artifact) { a.Metadata.ParentPackageSHA256 = strings.Repeat("a", 64) },
		"wrong generation": func(a *Artifact) { a.Metadata.PackageGeneration = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := *fixture.candidate
			mutate(&copy)
			if err := copy.ValidateCandidate(); err == nil {
				t.Fatal("invalid package relation succeeded")
			}
		})
	}
}

func TestPayloadRowsRejectAmplificationAndTraversal(t *testing.T) {
	for name, value := range map[string]string{
		"traversal": "kind\tmode\tbytes\tsha256\tpath\nfile\t0644\t0\t" + strings.Repeat("0", 64) + "\t../escape\n",
		"duplicate": "kind\tmode\tbytes\tsha256\tpath\nfile\t0644\t0\t" + strings.Repeat("0", 64) + "\ta\nfile\t0644\t0\t" + strings.Repeat("0", 64) + "\ta\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePayloadRows([]byte(value), ""); err == nil {
				t.Fatal("invalid payload manifest succeeded")
			}
		})
	}
}

func TestLoadArtifactAuthenticatesCompleteCandidateAndRefusesHardlinks(t *testing.T) {
	root := t.TempDir()
	artifact := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	writeBundleManifest(t, artifact.Root)
	loaded, err := LoadArtifact(artifact.Root, artifact.Archive, artifact.Digests(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := loaded.ValidateCandidate(); err != nil {
		t.Fatal(err)
	}
	update := filepath.Join(artifact.Root, "scripts", "update.sh")
	alias := filepath.Join(artifact.Root, "scripts", "update-alias")
	if err := os.Link(update, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArtifact(artifact.Root, artifact.Archive, artifact.Digests(), os.Geteuid()); err == nil {
		t.Fatal("hard-linked artifact authority succeeded")
	}
}

func TestLoadArtifactAuthenticatesManifestedInRootSymlink(t *testing.T) {
	root := t.TempDir()
	artifact := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	addPayloadSymlink(t, artifact.Root, "root/opt/reach-exo/provider/.venv/bin/python", "python3.13", true)
	writeBundleManifest(t, artifact.Root)
	refreshArtifactDigests(t, artifact)
	loaded, err := LoadArtifact(artifact.Root, artifact.Archive, artifact.Digests(), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	entry := loaded.Entries["root/opt/reach-exo/provider/.venv/bin/python"]
	if entry.Kind != "symlink" || entry.SHA256 != sha256Bytes([]byte("python3.13")) {
		t.Fatal("authenticated symlink tuple differs")
	}
}

func TestLoadArtifactRefusesEscapingSymlink(t *testing.T) {
	root := t.TempDir()
	artifact := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	addPayloadSymlink(t, artifact.Root, "root/opt/reach-exo/provider/.venv/bin/python", "../../../../../../../escape", true)
	writeBundleManifest(t, artifact.Root)
	refreshArtifactDigests(t, artifact)
	if _, err := LoadArtifact(artifact.Root, artifact.Archive, artifact.Digests(), os.Geteuid()); err == nil || !strings.Contains(err.Error(), "escapes its package") {
		t.Fatalf("escaping symlink was not categorically refused: %v", err)
	}
}

func TestLoadArtifactRefusesRootLevelDotDotSymlink(t *testing.T) {
	root := t.TempDir()
	artifact := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	addPayloadSymlink(t, artifact.Root, "escape", "..", true)
	writeBundleManifest(t, artifact.Root)
	refreshArtifactDigests(t, artifact)
	if _, err := LoadArtifact(artifact.Root, artifact.Archive, artifact.Digests(), os.Geteuid()); err == nil || !strings.Contains(err.Error(), "escapes its package") {
		t.Fatalf("root-level dot-dot symlink was not categorically refused: %v", err)
	}
}

func TestLoadArtifactBindsExtractedCandidateToExternalPayloadAuthority(t *testing.T) {
	root := t.TempDir()
	artifact := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	writeBundleManifest(t, artifact.Root)
	authorityDigests := artifact.Digests()
	node := filepath.Join(artifact.Root, "root/opt/reach-exo/bin/reach-exo-node")
	if err := os.WriteFile(node, []byte("altered-but-self-consistent"), 0755); err != nil {
		t.Fatal(err)
	}
	rewritePayloadManifest(t, artifact.Root)
	writeBundleManifest(t, artifact.Root)
	if _, err := LoadArtifact(artifact.Root, artifact.Archive, authorityDigests, os.Geteuid()); err == nil || !strings.Contains(err.Error(), "authenticated payload/metadata authority") {
		t.Fatalf("self-consistent altered root was not refused against external authority: %v", err)
	}
	paths := TestPaths(filepath.Join(root, "installed"))
	if _, err := os.Lstat(paths.LockPath); !os.IsNotExist(err) {
		t.Fatal("candidate authentication failure created the transaction lock")
	}
	if transactionEvidenceExists(paths) {
		t.Fatal("candidate authentication failure created transaction evidence")
	}
}

func TestLoadArtifactRefusesSafeUnmanifestedSymlink(t *testing.T) {
	root := t.TempDir()
	artifact := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	addPayloadSymlink(t, artifact.Root, "root/opt/reach-exo/provider/.venv/bin/python", "python3.13", false)
	writeBundleManifest(t, artifact.Root)
	if _, err := LoadArtifact(artifact.Root, artifact.Archive, artifact.Digests(), os.Geteuid()); err == nil || !strings.Contains(err.Error(), "payload manifest omits") {
		t.Fatalf("safe but unauthenticated symlink was not refused: %v", err)
	}
}

type testFixture struct {
	paths     Paths
	parent    *Artifact
	candidate *Artifact
	service   *fakeService
}

func newFixture(t *testing.T, enabled, active bool) testFixture {
	t.Helper()
	root := t.TempDir()
	paths := TestPaths(filepath.Join(root, "installed"))
	t.Cleanup(func() {
		_ = filepath.WalkDir(paths.RootPrefix, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && entry.IsDir() {
				if info, err := entry.Info(); err == nil {
					_ = os.Chmod(path, info.Mode().Perm()|0200)
				}
			}
			return nil
		})
	})
	parent := makeArtifact(t, filepath.Join(root, "A"), authority.ParentBundleVersion, false)
	candidate := makeArtifact(t, filepath.Join(root, "B"), authority.BundleVersion, true)
	for _, item := range []struct{ relative, absolute string }{
		{"root/opt/reach-exo", "/opt/reach-exo"},
		{"root/usr/lib/systemd/system/reach-exo-node.service", "/usr/lib/systemd/system/reach-exo-node.service"},
		{"root/usr/lib/systemd/system/reach-exo-relay.service", "/usr/lib/systemd/system/reach-exo-relay.service"},
		{"root/usr/lib/sysusers.d/reach-exo.conf", "/usr/lib/sysusers.d/reach-exo.conf"},
		{"root/usr/lib/tmpfiles.d/reach-exo.conf", "/usr/lib/tmpfiles.d/reach-exo.conf"},
	} {
		if err := replaceInstalledPath(paths, filepath.Join(parent.Root, filepath.FromSlash(item.relative)), authorityPath(paths.RootPrefix, item.absolute)); err != nil {
			t.Fatal(err)
		}
	}
	marker := authorityPath(paths.RootPrefix, "/var/lib/reach-exo/.bundle-created-account")
	if err := atomicWrite(marker, []byte("reach-exo-lifecycle/0.1.0\nuid=991\ngid=991\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return testFixture{paths: paths, parent: parent, candidate: candidate, service: &fakeService{enabled: enabled, active: active}}
}

func makeArtifact(t *testing.T, root, version string, candidate bool) *Artifact {
	t.Helper()
	files := map[string]string{
		"root/opt/reach-exo/bin/reach-exo-node":                    "node-" + version,
		"root/opt/reach-exo/host/reach-exo-connector-darwin-arm64": "connector-" + version,
		"root/usr/lib/systemd/system/reach-exo-node.service":       "node-unit-" + version,
		"root/usr/lib/systemd/system/reach-exo-relay.service":      "relay-unit-" + version,
		"root/usr/lib/sysusers.d/reach-exo.conf":                   "sysusers-" + version,
		"root/usr/lib/tmpfiles.d/reach-exo.conf":                   "tmpfiles-" + version,
	}
	if candidate {
		files["root/opt/reach-exo/bin/reach-exo-package"] = "package-" + version
		files["scripts/update.sh"] = "update"
		files["scripts/recover.sh"] = "recover"
		files["scripts/rollback.sh"] = "rollback"
	}
	entries := make(map[string]ManifestEntry)
	for relative, value := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if strings.Contains(relative, "/bin/") || strings.HasPrefix(relative, "scripts/") {
			mode = 0755
		}
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
		digest, err := pathDigest(path)
		if err != nil {
			t.Fatal(err)
		}
		entries[relative] = ManifestEntry{Kind: "file", Mode: mode, Bytes: int64(len(value)), SHA256: digest, Path: relative}
	}
	metadata := Metadata{
		BundleVersion: version, Architecture: authority.Architecture, EXOVersion: authority.EXOVersion,
		EXOCommit: authority.EXOCommit, EXOTree: authority.EXOTree, DerivativeSHA256: authority.DerivativeSHA256,
		ModelID: authority.ModelID, ModelSnapshot: authority.ModelSnapshot,
	}
	if candidate {
		metadata.PackageGeneration = authority.PackageGeneration
		metadata.ParentBundleVersion = authority.ParentBundleVersion
		metadata.ParentNodeSHA256 = authority.ParentNodeSHA256
		metadata.ParentConnectorSHA256 = authority.ParentConnectorSHA256
		metadata.ParentPackageSHA256 = authority.ParentPackageSHA256
		metadata.ParentPayloadManifestSHA256 = authority.ParentPayloadSHA256
		metadata.ParentMetadataSHA256 = authority.ParentMetadataSHA256
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(root, "metadata", "package.json")
	if err := os.MkdirAll(filepath.Dir(metadataPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, append(metadataBytes, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	metadataDigest, err := pathDigest(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	entries["metadata/package.json"] = ManifestEntry{Kind: "file", Mode: 0644, Bytes: int64(len(metadataBytes) + 1), SHA256: metadataDigest, Path: "metadata/package.json"}
	payload := strings.Builder{}
	payload.WriteString("kind\tmode\tbytes\tsha256\tpath\n")
	for _, key := range sortedKeys(entries) {
		entry := entries[key]
		fmt.Fprintf(&payload, "%s\t%04o\t%d\t%s\t%s\n", entry.Kind, entry.Mode, entry.Bytes, entry.SHA256, entry.Path)
	}
	if err := os.WriteFile(filepath.Join(root, "PAYLOAD-MANIFEST.tsv"), []byte(payload.String()), 0644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(filepath.Dir(root), "package-"+version+".tar.gz")
	if err := os.WriteFile(archive, []byte("archive-"+version), 0600); err != nil {
		t.Fatal(err)
	}
	archiveSHA, _ := fileSHA256(archive, 0)
	metadataSHA := sha256Bytes(append(metadataBytes, '\n'))
	payloadSHA := sha256Bytes([]byte(payload.String()))
	if !candidate {
		archiveSHA = authority.ParentPackageSHA256
		payloadSHA = authority.ParentPayloadSHA256
		metadataSHA = authority.ParentMetadataSHA256
	}
	return &Artifact{Root: root, Archive: archive, ArchiveSHA256: archiveSHA, Metadata: metadata, MetadataSHA: metadataSHA, PayloadSHA: payloadSHA, Entries: entries, authenticated: true}
}

func writeBundleManifest(t *testing.T, root string) {
	t.Helper()
	var rows []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path == filepath.Join(root, "MANIFEST.sha256") || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		digest, err := pathDigest(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rows = append(rows, digest+"  ./"+filepath.ToSlash(relative))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(rows)
	if err := os.WriteFile(filepath.Join(root, "MANIFEST.sha256"), []byte(strings.Join(rows, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func addPayloadSymlink(t *testing.T, root, relative, target string, includeInPayload bool) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if !includeInPayload {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(root, "PAYLOAD-MANIFEST.tsv")
	file, err := os.OpenFile(payload, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := fmt.Fprintf(file, "symlink\t%04o\t%d\t%s\t%s\n", info.Mode().Perm(), info.Size(), sha256Bytes([]byte(target)), relative)
	closeErr := file.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func rewritePayloadManifest(t *testing.T, root string) {
	t.Helper()
	entries := make(map[string]ManifestEntry)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "MANIFEST.sha256" || relative == "PAYLOAD-MANIFEST.tsv" {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		kind := "file"
		if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		digest, err := pathDigest(path)
		if err != nil {
			return err
		}
		entries[relative] = ManifestEntry{Kind: kind, Mode: info.Mode().Perm(), Bytes: info.Size(), SHA256: digest, Path: relative}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	payload := strings.Builder{}
	payload.WriteString("kind\tmode\tbytes\tsha256\tpath\n")
	for _, key := range sortedKeys(entries) {
		entry := entries[key]
		fmt.Fprintf(&payload, "%s\t%04o\t%d\t%s\t%s\n", entry.Kind, entry.Mode, entry.Bytes, entry.SHA256, entry.Path)
	}
	if err := os.WriteFile(filepath.Join(root, "PAYLOAD-MANIFEST.tsv"), []byte(payload.String()), 0644); err != nil {
		t.Fatal(err)
	}
}

func refreshArtifactDigests(t *testing.T, artifact *Artifact) {
	t.Helper()
	var err error
	artifact.ArchiveSHA256, err = fileSHA256(artifact.Archive, 0)
	if err != nil {
		t.Fatal(err)
	}
	artifact.PayloadSHA, err = fileSHA256(filepath.Join(artifact.Root, "PAYLOAD-MANIFEST.tsv"), maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	artifact.MetadataSHA, err = fileSHA256(filepath.Join(artifact.Root, "metadata", "package.json"), 64*1024)
	if err != nil {
		t.Fatal(err)
	}
}

func sortedKeys(entries map[string]ManifestEntry) []string {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat tuple unavailable")
	}
	return stat.Ino
}

func assertProgramTreeReadOnly(t *testing.T, paths Paths) {
	t.Helper()
	root := authorityPath(paths.RootPrefix, "/opt/reach-exo")
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0222 != 0 {
			return fmt.Errorf("program path remained writable: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
