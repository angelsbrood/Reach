package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryFileTupleRefusals(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "inventory.json")
	data, _ := json.Marshal(validInventory(filepath.Join(parent, "authority")))
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadInventory(path, testNow); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0620); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadInventory(path, testNow); err == nil {
		t.Fatal("group-writable inventory was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	hardlink := filepath.Join(parent, "inventory-link.json")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadInventory(path, testNow); err == nil {
		t.Fatal("multiply linked inventory was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(parent, "inventory-symlink.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadInventory(symlink, testNow); err == nil {
		t.Fatal("symlink inventory was accepted")
	}
}

func TestPublicationPathPreexistenceAliasAndModeRefusals(t *testing.T) {
	for _, target := range []RecoveryTarget{RecoverPrepared, RecoverStaging, RecoverQuarantine} {
		t.Run(string(target), func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			staging, quarantine := deterministicPaths(root)
			path := root
			if target == RecoverStaging {
				path = staging
			}
			if target == RecoverQuarantine {
				path = quarantine
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := createWithDependencies(inventory, digest, &bytes.Buffer{}, testDependencies("preexisting")); err == nil {
				t.Fatal("pre-existing attributable path was accepted")
			}
		})
	}

	t.Run("widened parent", func(t *testing.T) {
		root := testRoot(t)
		parent := filepath.Dir(root)
		if err := os.Chmod(parent, 0755); err != nil {
			t.Fatal(err)
		}
		inventory, digest := testInventoryAndDigest(t, root)
		if _, err := createWithDependencies(inventory, digest, &bytes.Buffer{}, testDependencies("wide-parent")); err == nil {
			t.Fatal("widened publication parent was accepted")
		}
	})

	t.Run("symlink parent alias", func(t *testing.T) {
		container, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		realParent := filepath.Join(container, "real")
		aliasParent := filepath.Join(container, "alias")
		if err := os.Mkdir(realParent, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realParent, aliasParent); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(aliasParent, "authority")
		inventory, digest := testInventoryAndDigest(t, root)
		if _, err := createWithDependencies(inventory, digest, &bytes.Buffer{}, testDependencies("alias-parent")); err == nil {
			t.Fatal("symlink publication alias was accepted")
		}
	})
}

func TestRootedWritesDoNotFollowInjectedDirectorySymlink(t *testing.T) {
	root := testRoot(t)
	inventory, digest := testInventoryAndDigest(t, root)
	external, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(external, 0700); err != nil {
		t.Fatal(err)
	}
	mutated := false
	deps := testDependencies("path-race")
	deps.hook = func(point string) error {
		if point == "before-write:operator/authority.json" && !mutated {
			staging, _ := deterministicPaths(root)
			if err := os.Rename(filepath.Join(staging, "operator"), filepath.Join(staging, "operator-original")); err != nil {
				return err
			}
			if err := os.Symlink(external, filepath.Join(staging, "operator")); err != nil {
				return err
			}
			mutated = true
		}
		return nil
	}
	_, err = createWithDependencies(inventory, digest, &bytes.Buffer{}, deps)
	if !mutated || !errors.Is(err, ErrUncommittedAuthorityRemains) {
		t.Fatalf("injected path race was not refused distinctly: %v", err)
	}
	if entries, readErr := os.ReadDir(external); readErr != nil || len(entries) != 0 {
		t.Fatalf("rooted write escaped to external directory: %v entries=%d", readErr, len(entries))
	}
	staging, _ := deterministicPaths(root)
	if err := os.Remove(filepath.Join(staging, "operator")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(staging, "operator-original"), filepath.Join(staging, "operator")); err != nil {
		t.Fatal(err)
	}
	if err := Recover(inventory, digest, RecoverStaging, CommitmentAbsent, true); err != nil {
		t.Fatal(err)
	}
	assertNoAttributablePaths(t, root)
}

func TestVerifierRejectsRelocationAndExtraEmptyDirectory(t *testing.T) {
	t.Run("relocation", func(t *testing.T) {
		created := createAuthority(t, "relocation")
		moved := created.inventory.AuthorityRoot + "-moved"
		if err := os.Rename(created.inventory.AuthorityRoot, moved); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyAt(moved, created.result.AuthoritySHA256, testNow); err == nil {
			t.Fatal("relocated authority was accepted")
		}
	})
	t.Run("extra empty directory", func(t *testing.T) {
		created := createAuthority(t, "empty-directory")
		if err := os.Mkdir(filepath.Join(created.inventory.AuthorityRoot, "undeclared"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyAt(created.inventory.AuthorityRoot, created.result.AuthoritySHA256, testNow); err == nil {
			t.Fatal("undeclared empty directory was accepted")
		}
	})
}
