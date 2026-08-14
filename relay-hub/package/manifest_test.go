// SPDX-License-Identifier: MIT

package packaging_test

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPayloadManifestIsScriptlessAndComplete(t *testing.T) {
	want := strings.Join([]string{
		"/usr/lib/reach-relay-hub/reach-relay-hub root:root 0555",
		"/usr/lib/systemd/system/reach-relay-hub.service root:root 0644",
		"/usr/lib/sysusers.d/reach-relay-hub.conf root:root 0644",
		"/usr/lib/tmpfiles.d/reach-relay-hub.conf root:root 0644",
		"/usr/share/licenses/reach-relay-hub/LICENSE root:root 0444",
		"/usr/share/doc/reach-relay-hub/NOTICE.md root:root 0444",
		"/usr/share/doc/reach-relay-hub/THIRD_PARTY_LICENSES.md root:root 0444",
		"",
	}, "\n")
	if got := read(t, "manifest.txt"); got != want {
		t.Fatalf("payload manifest mismatch:\n%s", got)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sh") {
			t.Fatalf("package script present: %s", entry.Name())
		}
	}
}

func TestServiceManifestPreservesSelectedBoundary(t *testing.T) {
	service := read(t, "reach-relay-hub.service")
	for _, required := range []string{
		"User=reach-relay",
		"Group=reach-relay",
		"Restart=always",
		"RestartSec=10",
		"StateDirectory=reach-relay-hub",
		"RuntimeDirectory=reach-relay-hub",
		"UMask=0077",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
	} {
		if !strings.Contains(service, required) {
			t.Errorf("service omitted %q", required)
		}
	}
	for _, forbidden := range []string{"ExecStartPre=", "ExecStartPost=", "Environment=", "/bin/sh", "CAP_NET_ADMIN"} {
		if strings.Contains(service, forbidden) {
			t.Errorf("service contains forbidden %q", forbidden)
		}
	}
	if strings.Contains(read(t, "reach-relay-hub.tmpfiles"), "config.json") {
		t.Fatal("tmpfiles must not create operator configuration")
	}
}
