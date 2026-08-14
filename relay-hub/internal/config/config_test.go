package config_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/testutil"
)

func encoded(t *testing.T, s config.Specification) []byte {
	t.Helper()
	b, err := s.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeCanonicalAndDigestPrivacy(t *testing.T) {
	s := testutil.Spec(1, 3)
	b := encoded(t, s)
	decoded, err := config.Decode(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicDigest() != s.PublicDigest() {
		t.Fatal("digest changed")
	}
	if bytes.Contains([]byte(s.PublicDigest()), []byte(s.PrivateKey)) {
		t.Fatal("digest exposed private key")
	}
	again, _ := decoded.CanonicalJSON()
	if !bytes.Equal(b, again) {
		t.Fatal("canonical rendering changed")
	}
}

func TestStrictRefusals(t *testing.T) {
	base := testutil.Spec(1, 2)
	tests := map[string]func(*config.Specification){
		"version": func(s *config.Specification) { s.Version = 2 }, "generation": func(s *config.Specification) { s.Generation = 0 }, "port": func(s *config.Specification) { s.ListenPort = 0 }, "mtu": func(s *config.Specification) { s.MTU = 1420 }, "public prefix": func(s *config.Specification) { s.RelayPrefix = "8.8.8.0/24" }, "direct overlap": func(s *config.Specification) { s.RelayPrefix = "10.86.0.0/24" }, "host ordinal": func(s *config.Specification) { s.Host.Address = "10.87.0.2/32" }, "no devices": func(s *config.Specification) { s.Devices = nil }, "unordered": func(s *config.Specification) { s.Devices[0], s.Devices[1] = s.Devices[1], s.Devices[0] }, "duplicate key": func(s *config.Specification) { s.Devices[1].PublicKey = s.Devices[0].PublicKey }, "duplicate route": func(s *config.Specification) { s.Devices[1].Address = s.Devices[0].Address }, "hub key reuse": func(s *config.Specification) { s.Host.PublicKey = s.PublicKey },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Devices = append([]config.Peer(nil), base.Devices...)
			mutate(&s)
			raw, _ := json.Marshal(s)
			if _, err := config.Decode(raw, nil); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestJSONShapeRefusals(t *testing.T) {
	valid := string(encoded(t, testutil.Spec(1, 1)))
	cases := []string{"", valid + " true", strings.Replace(valid, "\"version\": 1", "\"version\": 1, \"version\": 1", 1), strings.Replace(valid, "\"generation\": 1", "\"generation\": 1, \"unknown\": 1", 1)}
	for _, raw := range cases {
		if _, err := config.Decode([]byte(raw), nil); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestRouteInventoryOverlap(t *testing.T) {
	s := testutil.Spec(1, 1)
	if err := s.Validate(config.StaticRoutes{netip.MustParsePrefix("10.87.0.64/26")}); err == nil {
		t.Fatal("overlap accepted")
	}
	if err := s.Validate(config.StaticRoutes{netip.MustParsePrefix("192.168.1.0/24")}); err != nil {
		t.Fatal(err)
	}
}

func TestFrozenInstanceComparison(t *testing.T) {
	a := testutil.Spec(1, 1)
	b := a
	b.Generation = 2
	b.Devices = append(b.Devices, config.Peer{PublicKey: func() string { _, k := testutil.Key(99); return k }(), Address: "10.87.0.3/32"})
	if !a.SameInstance(b) {
		t.Fatal("device update changed instance")
	}
	b.ListenPort++
	if a.SameInstance(b) {
		t.Fatal("port change accepted")
	}
}

func TestSecureFilePolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(path, encoded(t, testutil.Spec(1, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	if _, err := config.ReadSecureFile(path, config.FileRule{Owner: &uid, Mode: 0o600, Limit: config.MaximumBytes}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.ReadSecureFile(path, config.FileRule{Owner: &uid, Mode: 0o600, Limit: config.MaximumBytes}); err == nil {
		t.Fatal("unsafe mode accepted")
	}
	_ = os.Chmod(path, 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := config.ReadSecureFile(link, config.FileRule{Owner: &uid, Mode: 0o600, Limit: config.MaximumBytes}); err == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := config.ReadSecureFile(path, config.FileRule{Owner: &uid, Mode: 0o600, Limit: config.MaximumBytes}); err == nil {
		t.Fatal("hard link accepted")
	}
	info, _ := os.Lstat(path)
	if info.Sys().(*syscall.Stat_t).Nlink < 2 {
		t.Fatal("fixture")
	}
}

func TestConfigurationSizeBounds(t *testing.T) {
	if _, err := config.Decode(make([]byte, config.MaximumBytes+1), nil); err == nil {
		t.Fatal("oversized configuration accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	if _, err := config.ReadSecureFile(path, config.FileRule{Owner: &uid, Mode: 0o600, Limit: config.MaximumBytes}); err == nil {
		t.Fatal("empty configuration accepted")
	}
}

func TestCanonicalRenderingSortsDevicesNumerically(t *testing.T) {
	s := testutil.Spec(1, 1)
	_, keyTwo := testutil.Key(120)
	_, keyTen := testutil.Key(121)
	s.Devices = []config.Peer{
		{PublicKey: keyTen, Address: "10.87.0.10/32"},
		{PublicKey: keyTwo, Address: "10.87.0.2/32"},
	}
	raw, err := s.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Index(raw, []byte("10.87.0.2/32")) > bytes.Index(raw, []byte("10.87.0.10/32")) {
		t.Fatal("device order was lexicographic rather than ordinal")
	}
}
