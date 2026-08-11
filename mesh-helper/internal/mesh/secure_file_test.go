// SPDX-License-Identifier: MIT

package mesh

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSecureFileRejectsModeSymlinkAndOversize(t *testing.T) {
	owner := uint32(os.Getuid())
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(valid, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecureFile(valid, FileRule{Owner: owner, Mode: 0o600, Limit: 16}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecureFile(valid, FileRule{Owner: owner, Mode: 0o600, Limit: 16}); err == nil {
		t.Fatal("world-readable file accepted")
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecureFile(link, FileRule{Owner: owner, Mode: 0o600, Limit: 16}); err == nil {
		t.Fatal("symlink accepted")
	}
	large := filepath.Join(directory, "large.json")
	if err := os.WriteFile(large, make([]byte, 17), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecureFile(large, FileRule{Owner: owner, Mode: 0o600, Limit: 16}); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestExistingStateDirectoriesAreValidatedWithoutPermissionRepair(t *testing.T) {
	owner := uint32(os.Getuid())
	root := t.TempDir()
	paths := Paths{
		State:   filepath.Join(root, "state"),
		Private: filepath.Join(root, "state", "private"),
	}
	if err := os.Mkdir(paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.State, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ensureDirectories(paths, owner); err == nil {
		t.Fatal("unsafe existing state directory was repaired and accepted")
	}
	info, err := os.Lstat(paths.State)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("unsafe directory mode was mutated to %o", info.Mode().Perm())
	}

	target := filepath.Join(root, "target")
	link := filepath.Join(root, "linked-state")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	linked := Paths{State: link, Private: filepath.Join(link, "private")}
	if err := ensureDirectories(linked, owner); err == nil {
		t.Fatal("symlink state directory accepted")
	}
	targetInfo, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if targetInfo.Mode().Perm() != 0o700 {
		t.Fatalf("symlink target mode was mutated to %o", targetInfo.Mode().Perm())
	}
}

func TestFreshStateDirectoriesKeepDeclaredModesUnderRestrictiveUmask(t *testing.T) {
	owner := uint32(os.Getuid())
	root := t.TempDir()
	paths := Paths{
		State:   filepath.Join(root, "state"),
		Private: filepath.Join(root, "state", "private"),
	}
	previous := unix.Umask(0o077)
	defer unix.Umask(previous)

	if err := ensureDirectories(paths, owner); err != nil {
		t.Fatal(err)
	}
	state, err := os.Lstat(paths.State)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.Lstat(paths.Private)
	if err != nil {
		t.Fatal(err)
	}
	if state.Mode().Perm() != 0o755 {
		t.Fatalf("state mode = %o, want 755", state.Mode().Perm())
	}
	if private.Mode().Perm() != 0o700 {
		t.Fatalf("private mode = %o, want 700", private.Mode().Perm())
	}
}
