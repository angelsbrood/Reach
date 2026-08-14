//go:build linux

// SPDX-License-Identifier: MIT

package packaging_test

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func run(t *testing.T, environment []string, name string, arguments ...string) string {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, arguments, err, output)
	}
	return string(output)
}

func TestBuiltDebMatchesManifestAndHasNoMaintainerScripts(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "reach-relay-hub")
	if err := os.WriteFile(binary, []byte("fixture"), 0o555); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(temporary, "candidate.deb")
	run(t, []string{"SOURCE_DATE_EPOCH=1"}, "/bin/sh", filepath.Join(root, "tests/linux/build-package.sh"), root, binary, "1.0.0", "arm64", archive)

	listing := run(t, nil, "dpkg-deb", "--contents", archive)
	lines := strings.Split(strings.TrimSpace(listing), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "drwxr-xr-x root/root") || !strings.HasSuffix(lines[0], " ./") {
		t.Fatalf("package root is not root-owned mode 0755:\n%s", listing)
	}
	wanted := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(read(t, "manifest.txt")))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			t.Fatalf("bad manifest line %q", scanner.Text())
		}
		wanted["."+fields[0]] = fields[2]
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 || strings.HasSuffix(fields[len(fields)-1], "/") {
			continue
		}
		path := fields[len(fields)-1]
		mode, ok := wanted[path]
		if !ok {
			t.Fatalf("undeclared package payload %s", path)
		}
		if fields[1] != "root/root" || fields[0][1:] != permissionString(mode) {
			t.Fatalf("payload metadata mismatch for %s: %s", path, line)
		}
		seen[path] = true
	}
	if len(seen) != len(wanted) {
		missing := []string{}
		for path := range wanted {
			if !seen[path] {
				missing = append(missing, path)
			}
		}
		sort.Strings(missing)
		t.Fatalf("package omitted manifest payloads: %v", missing)
	}

	control := filepath.Join(temporary, "control")
	run(t, nil, "dpkg-deb", "--control", archive, control)
	entries, err := os.ReadDir(control)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "control" {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("unexpected control archive entries: %v", names)
	}
}

func TestPackageBuilderRequiresRouteInventory(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	copyRoot := t.TempDir()
	for _, path := range []string{
		"package/reach-relay-hub.service",
		"package/reach-relay-hub.sysusers",
		"package/reach-relay-hub.tmpfiles",
		"LICENSE", "NOTICE.md", "THIRD_PARTY_LICENSES.md",
	} {
		source := filepath.Join(root, path)
		destination := filepath.Join(copyRoot, path)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(copyRoot, "binary")
	if err := os.WriteFile(binary, []byte("fixture"), 0o555); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", filepath.Join(root, "tests/linux/build-package.sh"), copyRoot, binary, "1.0.0", "arm64", filepath.Join(copyRoot, "missing.deb"))
	command.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1")
	if err := command.Run(); err == nil {
		t.Fatal("builder accepted missing route inventory")
	}
}

func permissionString(mode string) string {
	values := map[byte]string{
		'0': "---", '4': "r--", '5': "r-x", '6': "rw-", '7': "rwx",
	}
	if len(mode) != 4 {
		return ""
	}
	return values[mode[1]] + values[mode[2]] + values[mode[3]]
}
