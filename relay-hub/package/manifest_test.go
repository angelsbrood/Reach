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
		"/usr/share/doc/reach-relay-hub/route-inventory.md root:root 0444",
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
		"After=network-online.target nftables.service",
		"Wants=network-online.target nftables.service",
		"Restart=on-failure",
		"RestartSec=10",
		"StartLimitIntervalSec=60",
		"StartLimitBurst=3",
		"TimeoutStopSec=15",
		"ExecReload=/usr/bin/kill -HUP $MAINPID",
		"StateDirectory=reach-relay-hub",
		"StateDirectoryMode=0700",
		"RuntimeDirectory=reach-relay-hub",
		"RuntimeDirectoryMode=0700",
		"UMask=0077",
		"NoNewPrivileges=yes",
		"PrivateDevices=yes",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		"RestrictNamespaces=yes",
		"RestrictSUIDSGID=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service",
		"SystemCallErrorNumber=EPERM",
		"MemoryMax=256M",
		"TasksMax=128",
		"LimitNOFILE=1024",
		"LimitCORE=0",
		"--routes /etc/reach-relay-hub/routes.json",
		"--status /run/reach-relay-hub/status.json",
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
	for _, name := range []string{"config.json", "routes.json"} {
		if strings.Contains(read(t, "reach-relay-hub.tmpfiles"), name) {
			t.Fatalf("tmpfiles must not create operator file %s", name)
		}
	}
	if !strings.Contains(read(t, "route-inventory.md"), "every current Linux IPv4 routing table") {
		t.Fatal("route inventory contract missing")
	}
}
