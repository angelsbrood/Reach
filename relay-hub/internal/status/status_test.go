package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"systems.reach/relay-hub/internal/backend"
	"systems.reach/relay-hub/internal/testutil"
)

func TestStatusAttributionAndPrivacy(t *testing.T) {
	s := testutil.Spec(7, 2)
	now := time.Unix(1000, 0).UTC()
	runtime := map[string]backend.PeerRuntime{}
	for _, p := range s.Peers() {
		runtime[p.PublicKey] = backend.PeerRuntime{LastHandshake: now.Add(-25 * time.Second), ReceiveBytes: 3, TransmitBytes: 4}
	}
	value := Build(&s, true, "", runtime, now)
	if len(value.Peers) != 3 || value.Peers[0].Role != "host" || value.Peers[0].Ordinal != 1 || value.Peers[2].Ordinal != 3 || *value.Peers[1].HandshakeAgeSeconds != 25 {
		t.Fatalf("%+v", value)
	}
	raw, _ := json.Marshal(value)
	text := string(raw)
	for _, secret := range []string{s.PrivateKey, s.PublicKey, s.Host.PublicKey, s.Host.Address, s.Devices[0].PublicKey, s.Devices[0].Address, s.Devices[1].PublicKey, s.Devices[1].Address} {
		if strings.Contains(text, secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
}
func TestStatusBoundedErrorAndAtomicWrite(t *testing.T) {
	s := testutil.Spec(1, 1)
	value := Build(&s, false, "raw secret error", nil, time.Now())
	if value.Error != "relay hub unavailable" {
		t.Fatal(value.Error)
	}
	path := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".status.tmp-stale"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatal(info, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), s.PrivateKey) {
		t.Fatal("private key")
	}
}
