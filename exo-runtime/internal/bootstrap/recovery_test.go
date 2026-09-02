package bootstrap

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var errInjectedTest = errors.New("injected bootstrap interruption")

func TestEveryPreparationOperationFailureSettles(t *testing.T) {
	root := testRoot(t)
	inventory, digest := testInventoryAndDigest(t, root)
	var points []string
	deps := testDependencies("hook-inventory")
	deps.hook = func(point string) error {
		points = append(points, point)
		return nil
	}
	var output bytes.Buffer
	if _, err := createWithDependencies(inventory, digest, &output, deps); err != nil {
		t.Fatal(err)
	}
	if len(points) < 50 {
		t.Fatalf("expected broad operation instrumentation, got %d points", len(points))
	}

	for index, point := range points {
		t.Run(fmt.Sprintf("%03d-%s", index, sanitizeTestName(point)), func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			injected := false
			deps := testDependencies(point)
			deps.hook = func(observed string) error {
				if observed == point && !injected {
					injected = true
					return errInjectedTest
				}
				return nil
			}
			var output bytes.Buffer
			result, err := createWithDependencies(inventory, digest, &output, deps)
			if !injected || err == nil {
				t.Fatalf("operation fault was not observed: %v", err)
			}
			complete := strings.HasPrefix(point, "after-commitment-write:") || point == "after-complete-commitment"
			if complete {
				if !errors.Is(err, ErrCommitmentCompleteOrUncertain) {
					t.Fatalf("complete commitment was misclassified: %v", err)
				}
				if _, err := verifyAt(root, result.AuthoritySHA256, testNow); err != nil {
					t.Fatal(err)
				}
			} else {
				assertNoAttributablePaths(t, root)
			}
		})
	}
}

func TestCleanupFailureIsDistinctAndRecoverable(t *testing.T) {
	root := testRoot(t)
	inventory, digest := testInventoryAndDigest(t, root)
	deps := testDependencies("cleanup-failure")
	deps.hook = func(point string) error {
		if point == "before-commitment-output" || point == "before-cleanup-rename" {
			return errInjectedTest
		}
		return nil
	}
	_, err := createWithDependencies(inventory, digest, &bytes.Buffer{}, deps)
	if !errors.Is(err, ErrUncommittedAuthorityRemains) {
		t.Fatalf("cleanup failure was not classified distinctly: %v", err)
	}
	if _, statErr := os.Stat(root); statErr != nil {
		t.Fatal("uncommitted prepared tree was not retained")
	}
	if err := recoverWithDependencies(inventory, digest, RecoverPrepared, CommitmentAbsent, true, testDependencies("cleanup-recovery")); err != nil {
		t.Fatal(err)
	}
	assertNoAttributablePaths(t, root)
}

func TestRecoveryShapesAndRefusals(t *testing.T) {
	t.Run("empty staging", func(t *testing.T) {
		root := testRoot(t)
		inventory, digest := testInventoryAndDigest(t, root)
		staging, _ := deterministicPaths(root)
		if err := os.Mkdir(staging, 0700); err != nil {
			t.Fatal(err)
		}
		if err := Recover(inventory, digest, RecoverStaging, CommitmentAbsent, true); err != nil {
			t.Fatal(err)
		}
		assertNoAttributablePaths(t, root)
	})

	t.Run("provenance staging", func(t *testing.T) {
		root := testRoot(t)
		inventory, digest := testInventoryAndDigest(t, root)
		staging, _ := deterministicPaths(root)
		if err := os.Mkdir(staging, 0700); err != nil {
			t.Fatal(err)
		}
		writePrepareForTest(t, staging, inventory, digest)
		if err := Recover(inventory, digest, RecoverStaging, CommitmentAbsent, true); err != nil {
			t.Fatal(err)
		}
		assertNoAttributablePaths(t, root)
	})

	t.Run("prepared and quarantine", func(t *testing.T) {
		created := createAuthority(t, "recover-prepared")
		if err := Recover(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentPartial, true); err != nil {
			t.Fatal(err)
		}
		assertNoAttributablePaths(t, created.inventory.AuthorityRoot)

		root := testRoot(t)
		inventory, digest := testInventoryAndDigest(t, root)
		_, quarantine := deterministicPaths(root)
		if err := os.Mkdir(quarantine, 0700); err != nil {
			t.Fatal(err)
		}
		writePrepareForTest(t, quarantine, inventory, digest)
		if err := Recover(inventory, digest, RecoverQuarantine, CommitmentPartial, true); err != nil {
			t.Fatal(err)
		}
		assertNoAttributablePaths(t, root)
	})

	for name, setup := range map[string]func(*testing.T, string, Inventory, string){
		"missing provenance": func(t *testing.T, root string, _ Inventory, _ string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(staging, "unknown"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"mismatched provenance": func(t *testing.T, root string, inventory Inventory, digest string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			writePrepareForTest(t, staging, inventory, strings.Repeat("0", len(digest)))
		},
		"widened target": func(t *testing.T, root string, inventory Inventory, digest string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			writePrepareForTest(t, staging, inventory, digest)
			if err := os.Chmod(staging, 0755); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked provenance": func(t *testing.T, root string, inventory Inventory, digest string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			writePrepareForTest(t, staging, inventory, digest)
			if err := os.Link(filepath.Join(staging, prepareName), filepath.Join(staging, "prepare-link")); err != nil {
				t.Fatal(err)
			}
		},
		"arbitrary staging object beside provenance": func(t *testing.T, root string, inventory Inventory, digest string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			writePrepareForTest(t, staging, inventory, digest)
			if err := os.WriteFile(filepath.Join(staging, "attacker-controlled"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"damaged known staging object": func(t *testing.T, root string, inventory Inventory, digest string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			writePrepareForTest(t, staging, inventory, digest)
			for _, directory := range authorityDirectoryOrder() {
				if err := os.Mkdir(filepath.Join(staging, filepath.FromSlash(directory)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(staging, "operator/authority.json"), []byte("not-json"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"oversized known staging object": func(t *testing.T, root string, inventory Inventory, digest string) {
			staging, _ := deterministicPaths(root)
			if err := os.Mkdir(staging, 0700); err != nil {
				t.Fatal(err)
			}
			writePrepareForTest(t, staging, inventory, digest)
			for _, directory := range authorityDirectoryOrder() {
				if err := os.Mkdir(filepath.Join(staging, filepath.FromSlash(directory)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(staging, "operator/authority.json"), bytes.Repeat([]byte("x"), maxManifestBytes+1), 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			setup(t, root, inventory, digest)
			if err := Recover(inventory, digest, RecoverStaging, CommitmentAbsent, true); err == nil || !strings.Contains(err.Error(), "manual disposition") {
				t.Fatalf("unsafe recovery target was accepted: %v", err)
			}
		})
	}

	t.Run("complete commitment declaration", func(t *testing.T) {
		root := testRoot(t)
		inventory, digest := testInventoryAndDigest(t, root)
		if err := Recover(inventory, digest, RecoverPrepared, CommitmentState("complete"), true); err == nil {
			t.Fatal("complete commitment state was accepted for deletion")
		}
	})

	t.Run("noncanonical inventory digest", func(t *testing.T) {
		root := testRoot(t)
		inventory, _ := testInventoryAndDigest(t, root)
		if err := Recover(inventory, strings.Repeat("0", 64), RecoverStaging, CommitmentAbsent, true); err == nil {
			t.Fatal("noncanonical inventory digest was accepted for recovery")
		}
	})

	t.Run("empty prepared target", func(t *testing.T) {
		root := testRoot(t)
		inventory, digest := testInventoryAndDigest(t, root)
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := Recover(inventory, digest, RecoverPrepared, CommitmentAbsent, true); err == nil {
			t.Fatal("empty prepared target was accepted without a cluster manifest")
		}
	})

	t.Run("prepared target with digest-only manifest", func(t *testing.T) {
		created := createAuthority(t, "digest-only-recovery-manifest")
		root := created.inventory.AuthorityRoot
		manifest := ClusterManifest{InventorySHA256: created.inventoryDigest, AuthorityRootSHA256: digestString(root)}
		data, err := marshalJSON(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, clusterManifestName), data, 0600); err != nil {
			t.Fatal(err)
		}
		fileManifest, _, err := buildFileManifest(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, fileManifestName), fileManifest, 0600); err != nil {
			t.Fatal(err)
		}
		if err := Recover(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true); err == nil || !strings.Contains(err.Error(), "manual disposition") {
			t.Fatalf("digest-only prepared manifest was accepted: %v", err)
		}
		if _, err := os.Stat(root); err != nil {
			t.Fatal("refused prepared authority was destructively changed")
		}
	})

	t.Run("arbitrary quarantine object beside provenance", func(t *testing.T) {
		root := testRoot(t)
		inventory, digest := testInventoryAndDigest(t, root)
		_, quarantine := deterministicPaths(root)
		if err := os.Mkdir(quarantine, 0700); err != nil {
			t.Fatal(err)
		}
		writePrepareForTest(t, quarantine, inventory, digest)
		if err := os.WriteFile(filepath.Join(quarantine, "attacker-controlled"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Recover(inventory, digest, RecoverQuarantine, CommitmentAbsent, true); err == nil || !strings.Contains(err.Error(), "manual disposition") {
			t.Fatalf("arbitrary quarantine object was accepted: %v", err)
		}
		if _, err := os.Stat(filepath.Join(quarantine, "attacker-controlled")); err != nil {
			t.Fatal("refused quarantine object was destructively changed")
		}
	})

	t.Run("damaged known quarantine object after manifest removal", func(t *testing.T) {
		created := createAuthority(t, "damaged-quarantine-prefix")
		deps := testDependencies("retain-quarantine-prefix")
		deps.hook = func(point string) error {
			if point == "before-remove:connector/connector.json" {
				return errInjectedTest
			}
			return nil
		}
		if err := recoverWithDependencies(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true, deps); err == nil {
			t.Fatal("recovery did not stop after both manifests were removed")
		}
		_, quarantine := deterministicPaths(created.inventory.AuthorityRoot)
		if _, err := os.Stat(filepath.Join(quarantine, clusterManifestName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cluster manifest unexpectedly survived the selected removal boundary")
		}
		workerCertificate := filepath.Join(quarantine, "worker/etc/reach-exo/tls/worker.pem")
		if err := os.WriteFile(workerCertificate, []byte("damaged"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := Recover(created.inventory, created.inventoryDigest, RecoverQuarantine, CommitmentAbsent, true); err == nil || !strings.Contains(err.Error(), "manual disposition") {
			t.Fatalf("damaged known quarantine object was accepted: %v", err)
		}
		if _, err := os.Stat(workerCertificate); err != nil {
			t.Fatal("refused damaged quarantine object was destructively changed")
		}
	})

	t.Run("conflicting quarantine", func(t *testing.T) {
		created := createAuthority(t, "quarantine-conflict")
		_, quarantine := deterministicPaths(created.inventory.AuthorityRoot)
		if err := os.Mkdir(quarantine, 0700); err != nil {
			t.Fatal(err)
		}
		if err := Recover(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true); err == nil {
			t.Fatal("conflicting quarantine was accepted")
		}
	})
}

func TestRecoveryRejectsLogicalRoleKeyReuseAfterPrivateKeyRemoval(t *testing.T) {
	created := createAuthority(t, "reachable-ca-key-reuse")
	root := created.inventory.AuthorityRoot
	ca, err := parseCertificate(readAll(t, filepath.Join(root, "operator/tls/ca.pem")))
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM := readAll(t, filepath.Join(root, "operator/tls/ca-key.pem"))
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	deps := testDependencies("retain-after-ca-private-key-removal")
	deps.hook = func(point string) error {
		if point == "after-remove:operator/tls/ca-key.pem" {
			return errInjectedTest
		}
		return nil
	}
	if err := recoverWithDependencies(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true, deps); err == nil {
		t.Fatal("recovery did not stop after CA private-key removal")
	}
	_, quarantine := deterministicPaths(root)
	if _, err := os.Stat(filepath.Join(quarantine, "operator/tls/ca-key.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CA private key unexpectedly survived the selected removal boundary")
	}

	workerPath := filepath.Join(quarantine, "worker/etc/reach-exo/tls/worker.pem")
	worker, err := parseCertificate(readAll(t, workerPath))
	if err != nil {
		t.Fatal(err)
	}
	workerTemplate := *worker
	workerDER, err := x509.CreateCertificate(newDeterministicReader("reachable-ca-key-worker"), &workerTemplate, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	workerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: workerDER})
	workerKeyPath := filepath.Join(quarantine, "worker/etc/reach-exo/tls/worker-key.pem")
	if err := os.WriteFile(workerPath, workerPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workerKeyPath, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	if err := Recover(created.inventory, created.inventoryDigest, RecoverQuarantine, CommitmentAbsent, true); err == nil || !strings.Contains(err.Error(), "manual disposition") {
		t.Fatalf("reachable quarantine reused the logical CA key for the worker role: %v", err)
	}
	if current := readAll(t, workerPath); !bytes.Equal(current, workerPEM) {
		t.Fatal("refused worker certificate was destructively changed")
	}
	if current := readAll(t, workerKeyPath); !bytes.Equal(current, caKeyPEM) {
		t.Fatal("refused worker private key was destructively changed")
	}
}

func TestRecoveryRejectsCAKeyReuseAfterLastReplicatedWitnessBoundary(t *testing.T) {
	created := createAuthority(t, "reachable-last-ca-witness-reuse")
	root := created.inventory.AuthorityRoot
	caPath := filepath.Join(root, "operator/tls/ca.pem")
	ca, err := parseCertificate(readAll(t, caPath))
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM := readAll(t, filepath.Join(root, "operator/tls/ca-key.pem"))
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	deps := testDependencies("retain-after-last-replicated-ca-witness-removal")
	deps.hook = func(point string) error {
		if point == "after-remove:worker/etc/reach-exo/tls/ca.pem" {
			return errInjectedTest
		}
		return nil
	}
	if err := recoverWithDependencies(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true, deps); err == nil {
		t.Fatal("recovery did not stop after the selected late CA-copy removal boundary")
	}
	_, quarantine := deterministicPaths(root)
	workerPath := filepath.Join(quarantine, "worker/etc/reach-exo/tls/worker.pem")
	worker, err := parseCertificate(readAll(t, workerPath))
	if err != nil {
		t.Fatal(err)
	}
	workerTemplate := *worker
	workerDER, err := x509.CreateCertificate(newDeterministicReader("reachable-last-ca-witness-worker"), &workerTemplate, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	workerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: workerDER})
	workerKeyPath := filepath.Join(quarantine, "worker/etc/reach-exo/tls/worker-key.pem")
	if err := os.WriteFile(workerPath, workerPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workerKeyPath, caKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	err = Recover(created.inventory, created.inventoryDigest, RecoverQuarantine, CommitmentAbsent, true)
	if err == nil || !strings.Contains(err.Error(), "manual disposition") || !strings.Contains(err.Error(), "reuse one public key") {
		t.Fatalf("recovery accepted CA key reuse after its last replicated certificate witness boundary: %v", err)
	}
	if current := readAll(t, workerPath); !bytes.Equal(current, workerPEM) {
		t.Fatal("refused worker certificate was destructively changed")
	}
	if current := readAll(t, workerKeyPath); !bytes.Equal(current, caKeyPEM) {
		t.Fatal("refused worker private key was destructively changed")
	}
	if _, err := os.Stat(filepath.Join(quarantine, "operator/tls/ca.pem")); err != nil {
		t.Fatal("the designated CA certificate witness did not survive while a leaf identity remained")
	}
}

func TestEveryRecoveryOperationCanResume(t *testing.T) {
	created := createAuthority(t, "recovery-hooks")
	var points []string
	deps := testDependencies("recover-collector")
	deps.hook = func(point string) error { points = append(points, point); return nil }
	if err := recoverWithDependencies(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true, deps); err != nil {
		t.Fatal(err)
	}
	if len(points) < 20 {
		t.Fatalf("recovery operation instrumentation is incomplete: %d", len(points))
	}
	for index, point := range points {
		t.Run(fmt.Sprintf("%03d-%s", index, sanitizeTestName(point)), func(t *testing.T) {
			created := createAuthority(t, "recovery-fault-"+point)
			injected := false
			deps := testDependencies(point)
			deps.hook = func(observed string) error {
				if observed == point && !injected {
					injected = true
					return errInjectedTest
				}
				return nil
			}
			err := recoverWithDependencies(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true, deps)
			if !injected || err == nil {
				t.Fatalf("recovery fault was not observed: %v", err)
			}
			root := created.inventory.AuthorityRoot
			_, quarantine := deterministicPaths(root)
			if _, statErr := os.Lstat(root); statErr == nil {
				if err := Recover(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true); err != nil {
					t.Fatal(err)
				}
			} else if _, statErr := os.Lstat(quarantine); statErr == nil {
				if err := Recover(created.inventory, created.inventoryDigest, RecoverQuarantine, CommitmentAbsent, true); err != nil {
					t.Fatal(err)
				}
			}
			assertNoAttributablePaths(t, root)
		})
	}
}

func TestBootstrapCrashHelper(t *testing.T) {
	if os.Getenv("REACH_BOOTSTRAP_CRASH_HELPER") != "1" {
		return
	}
	root := os.Getenv("REACH_BOOTSTRAP_ROOT")
	point := os.Getenv("REACH_BOOTSTRAP_POINT")
	action := os.Getenv("REACH_BOOTSTRAP_ACTION")
	inventory := validInventory(root)
	data, _ := json.Marshal(inventory)
	_, _, digest, err := DecodeInventory(data, testNow)
	if err != nil {
		os.Exit(70)
	}
	deps := testDependencies("hard-crash")
	deps.hook = func(observed string) error {
		if observed == point {
			os.Exit(86)
		}
		return nil
	}
	if action == "create" {
		var writer io.Writer = os.Stdout
		if os.Getenv("REACH_BOOTSTRAP_ONE_BYTE") == "1" {
			writer = oneByteWriter{os.Stdout}
		}
		_, _ = createWithDependencies(inventory, digest, writer, deps)
	} else {
		_ = recoverWithDependencies(inventory, digest, RecoverPrepared, CommitmentAbsent, true, deps)
	}
	os.Exit(71)
}

func TestFreshProcessHardCrashCreationAndRecoveryJoin(t *testing.T) {
	completeBytes := len(fmt.Sprintf(commitmentRecordFormat, strings.Repeat("0", 64)))
	cases := []struct {
		point      string
		oneByte    bool
		state      RecoveryTarget
		commitment CommitmentState
		verify     bool
	}{
		{"after-staging-directory", false, RecoverStaging, CommitmentAbsent, false},
		{"after-write:prepare", false, RecoverStaging, CommitmentAbsent, false},
		{"after-fsync:prepare", false, RecoverStaging, CommitmentAbsent, false},
		{"after-durable-prepare", false, RecoverStaging, CommitmentAbsent, false},
		{"after-mkdir:operator/tls", false, RecoverStaging, CommitmentAbsent, false},
		{"after-write:operator/tls/ca-key.pem", false, RecoverStaging, CommitmentAbsent, false},
		{"after-fsync:cluster-manifest", false, RecoverStaging, CommitmentAbsent, false},
		{"after-fsync:file-manifest", false, RecoverStaging, CommitmentAbsent, false},
		{"after-publication-rename", false, RecoverPrepared, CommitmentAbsent, false},
		{"after-fsync-dir:publication-parent-after-rename", false, RecoverPrepared, CommitmentAbsent, false},
		{"before-commitment-write:0", false, RecoverPrepared, CommitmentAbsent, false},
		{"after-commitment-write:1", true, RecoverPrepared, CommitmentPartial, false},
		{fmt.Sprintf("after-commitment-write:%d", completeBytes), false, RecoverPrepared, CommitmentAbsent, true},
		{"after-complete-commitment", false, RecoverPrepared, CommitmentAbsent, true},
	}
	for _, test := range cases {
		t.Run(sanitizeTestName(test.point), func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			command := exec.Command(os.Args[0], "-test.run=^TestBootstrapCrashHelper$")
			command.Env = append(os.Environ(),
				"REACH_BOOTSTRAP_CRASH_HELPER=1", "REACH_BOOTSTRAP_ACTION=create",
				"REACH_BOOTSTRAP_ROOT="+root, "REACH_BOOTSTRAP_POINT="+test.point,
			)
			if test.oneByte {
				command.Env = append(command.Env, "REACH_BOOTSTRAP_ONE_BYTE=1")
			}
			output, err := command.Output()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
				t.Fatalf("hard-crash helper did not stop at point: %v", err)
			}
			if test.verify {
				var commitment struct {
					SchemaVersion   int    `json:"schema_version"`
					AuthoritySHA256 string `json:"authority_sha256"`
				}
				if err := json.Unmarshal(output, &commitment); err != nil || commitment.SchemaVersion != 1 {
					t.Fatalf("complete external commitment was not retained: %q %v", output, err)
				}
				if _, err := verifyAt(root, commitment.AuthoritySHA256, testNow); err != nil {
					t.Fatal(err)
				}
				if err := Recover(inventory, digest, RecoverPrepared, CommitmentAbsent, true); err != nil {
					t.Fatal(err)
				}
			} else {
				if test.commitment == CommitmentAbsent && len(output) != 0 {
					t.Fatalf("unexpected commitment bytes: %q", output)
				}
				if test.commitment == CommitmentPartial && (len(output) == 0 || len(output) >= completeBytes) {
					t.Fatalf("partial output boundary differs: %d", len(output))
				}
				if err := Recover(inventory, digest, test.state, test.commitment, true); err != nil {
					t.Fatal(err)
				}
			}
			assertNoAttributablePaths(t, root)
		})
	}
}

func TestFreshProcessEveryCommitmentBoundaryRemainsRecoverable(t *testing.T) {
	completeBytes := len(fmt.Sprintf(commitmentRecordFormat, strings.Repeat("0", 64)))
	for boundary := 0; boundary < completeBytes; boundary++ {
		t.Run(fmt.Sprintf("before-byte-%03d", boundary), func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			point := fmt.Sprintf("before-commitment-write:%d", boundary)
			command := exec.Command(os.Args[0], "-test.run=^TestBootstrapCrashHelper$")
			command.Env = append(os.Environ(),
				"REACH_BOOTSTRAP_CRASH_HELPER=1", "REACH_BOOTSTRAP_ACTION=create",
				"REACH_BOOTSTRAP_ROOT="+root, "REACH_BOOTSTRAP_POINT="+point,
				"REACH_BOOTSTRAP_ONE_BYTE=1",
			)
			output, err := command.Output()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 || len(output) != boundary {
				t.Fatalf("hard-crash boundary differs: bytes=%d err=%v", len(output), err)
			}
			state := CommitmentPartial
			if boundary == 0 {
				state = CommitmentAbsent
			}
			if err := Recover(inventory, digest, RecoverPrepared, state, true); err != nil {
				t.Fatal(err)
			}
			assertNoAttributablePaths(t, root)
		})
	}
}

func TestFreshProcessHardCrashDuringRecoveryRemainsClassified(t *testing.T) {
	points := []string{
		"after-recovery-rename:prepared",
		"after-fsync-dir:recovery-parent-after-rename",
		"after-remove:FILE-MANIFEST.tsv",
		"after-remove:cluster-manifest.json",
		"after-remove:worker/etc/reach-exo/tls/ca.pem",
		"after-remove-directory:worker/etc/reach-exo/tls",
		"after-remove-prepare",
		"after-remove-quarantine",
		"after-fsync-dir:recovery-parent-final",
	}
	for _, point := range points {
		t.Run(sanitizeTestName(point), func(t *testing.T) {
			created := createAuthority(t, "recovery-crash-"+point)
			root := created.inventory.AuthorityRoot
			command := exec.Command(os.Args[0], "-test.run=^TestBootstrapCrashHelper$")
			command.Env = append(os.Environ(),
				"REACH_BOOTSTRAP_CRASH_HELPER=1", "REACH_BOOTSTRAP_ACTION=recover",
				"REACH_BOOTSTRAP_ROOT="+root, "REACH_BOOTSTRAP_POINT="+point,
			)
			_, err := command.Output()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 86 {
				t.Fatalf("hard-crash helper did not stop at point: %v", err)
			}
			_, quarantine := deterministicPaths(root)
			if _, statErr := os.Lstat(root); statErr == nil {
				if err := Recover(created.inventory, created.inventoryDigest, RecoverPrepared, CommitmentAbsent, true); err != nil {
					t.Fatal(err)
				}
			} else if _, statErr := os.Lstat(quarantine); statErr == nil {
				if err := Recover(created.inventory, created.inventoryDigest, RecoverQuarantine, CommitmentAbsent, true); err != nil {
					t.Fatal(err)
				}
			}
			assertNoAttributablePaths(t, root)
		})
	}
}

type oneByteWriter struct{ io.Writer }

func (w oneByteWriter) Write(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return w.Writer.Write(data)
}

func writePrepareForTest(t *testing.T, root string, inventory Inventory, digest string) {
	t.Helper()
	data, err := marshalJSON(PrepareRecord{SchemaVersion: SchemaVersion, InventorySHA256: digest, AuthorityRootSHA256: digestString(inventory.AuthorityRoot)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, prepareName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func sanitizeTestName(value string) string {
	replacer := strings.NewReplacer("/", "-", ":", "-", ".", "-")
	return replacer.Replace(value)
}
