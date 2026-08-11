// SPDX-License-Identifier: MIT

package mesh

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/curve25519"
)

var socketSequence atomic.Uint64

func testKeypair(t *testing.T) (string, string) {
	t.Helper()
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(privateKey), base64.StdEncoding.EncodeToString(publicKey)
}

func testSpecification(t *testing.T, generation uint64) Specification {
	t.Helper()
	privateKey, publicKey := testKeypair(t)
	_, peerPublic := testKeypair(t)
	return Specification{
		Version: SpecificationVersion, Generation: generation,
		PrivateKey: privateKey, PublicKey: publicKey,
		Address: HostAddress, Port: ListenPort, MTU: InterfaceMTU,
		Peers: []Peer{{PublicKey: peerPublic, AllowedIP: "10.86.0.2/32", Keepalive: 25}},
	}
}

func encodedSpecification(t *testing.T, spec Specification) []byte {
	t.Helper()
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func testPaths(t *testing.T) Paths {
	t.Helper()
	state := filepath.Join(t.TempDir(), "Reach Mesh")
	private := filepath.Join(state, "private")
	return Paths{
		State: state, Private: private,
		Active:  filepath.Join(private, "active.json"),
		Pending: filepath.Join(private, "pending.json"),
		Lock:    filepath.Join(private, "apply.lock"),
		Status:  filepath.Join(state, "status.json"),
		Control: filepath.Join("/private/tmp", fmt.Sprintf("reach-mesh-%d-%d.sock", os.Getpid(), socketSequence.Add(1))),
	}
}

func writeTestSpec(t *testing.T, path string, spec Specification) {
	t.Helper()
	private := filepath.Dir(path)
	state := filepath.Dir(private)
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encodedSpecification(t, spec), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
