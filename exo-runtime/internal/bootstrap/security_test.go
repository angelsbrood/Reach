package bootstrap

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/mtls"
)

func TestVerifierRefusalArms(t *testing.T) {
	tests := map[string]func(*testing.T, createdAuthority) string{
		"missing file": func(t *testing.T, created createdAuthority) string {
			if err := os.Remove(filepath.Join(created.inventory.AuthorityRoot, "worker/etc/reach-exo/node.json")); err != nil {
				t.Fatal(err)
			}
			return created.result.AuthoritySHA256
		},
		"extra file": func(t *testing.T, created createdAuthority) string {
			if err := os.WriteFile(filepath.Join(created.inventory.AuthorityRoot, "extra"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
			return created.result.AuthoritySHA256
		},
		"extra secret with rebuilt commitment": func(t *testing.T, created createdAuthority) string {
			root := created.inventory.AuthorityRoot
			caKey := readAll(t, filepath.Join(root, "operator/tls/ca-key.pem"))
			if err := os.WriteFile(filepath.Join(root, "connector/tls/undeclared-ca-key.pem"), caKey, 0600); err != nil {
				t.Fatal(err)
			}
			return rebuildManifestsForTest(t, root)
		},
		"mode widened": func(t *testing.T, created createdAuthority) string {
			if err := os.Chmod(filepath.Join(created.inventory.AuthorityRoot, "connector/connector.json"), 0644); err != nil {
				t.Fatal(err)
			}
			return created.result.AuthoritySHA256
		},
		"hard linked": func(t *testing.T, created createdAuthority) string {
			path := filepath.Join(created.inventory.AuthorityRoot, "connector/connector.json")
			if err := os.Link(path, filepath.Join(created.inventory.AuthorityRoot, "connector/connector-link.json")); err != nil {
				t.Fatal(err)
			}
			return created.result.AuthoritySHA256
		},
		"symlink": func(t *testing.T, created createdAuthority) string {
			path := filepath.Join(created.inventory.AuthorityRoot, "connector/connector.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../operator/authority.json", path); err != nil {
				t.Fatal(err)
			}
			return created.result.AuthoritySHA256
		},
		"tampered config with rebuilt manifests": func(t *testing.T, created createdAuthority) string {
			path := filepath.Join(created.inventory.AuthorityRoot, "coordinator/etc/reach-exo/node.json")
			data := readAll(t, path)
			data = []byte(strings.Replace(string(data), `"expected_range": {`, `"expected_range": {`, 1))
			data = []byte(strings.Replace(string(data), `"start": 14`, `"start": 13`, 1))
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			return rebuildManifestsForTest(t, created.inventory.AuthorityRoot)
		},
		"swapped leaf key with rebuilt manifests": func(t *testing.T, created createdAuthority) string {
			root := created.inventory.AuthorityRoot
			workerKey := readAll(t, filepath.Join(root, "worker/etc/reach-exo/tls/worker-key.pem"))
			if err := os.WriteFile(filepath.Join(root, "connector/tls/connector-key.pem"), workerKey, 0600); err != nil {
				t.Fatal(err)
			}
			return rebuildManifestsForTest(t, root)
		},
		"swapped certificate with rebuilt manifests": func(t *testing.T, created createdAuthority) string {
			root := created.inventory.AuthorityRoot
			worker := readAll(t, filepath.Join(root, "worker/etc/reach-exo/tls/worker.pem"))
			if err := os.WriteFile(filepath.Join(root, "connector/tls/connector.pem"), worker, 0600); err != nil {
				t.Fatal(err)
			}
			return rebuildManifestsForTest(t, root)
		},
		"leaf reissued on CA key with rebuilt commitment": func(t *testing.T, created createdAuthority) string {
			root := created.inventory.AuthorityRoot
			caPEM := readAll(t, filepath.Join(root, "operator/tls/ca.pem"))
			ca, err := parseCertificate(caPEM)
			if err != nil {
				t.Fatal(err)
			}
			caKeyPEM := readAll(t, filepath.Join(root, "operator/tls/ca-key.pem"))
			caKey, err := parsePrivateKey(caKeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			workerPath := filepath.Join(root, "worker/etc/reach-exo/tls/worker.pem")
			worker, err := parseCertificate(readAll(t, workerPath))
			if err != nil {
				t.Fatal(err)
			}
			workerTemplate := *worker
			workerDER, err := x509.CreateCertificate(newDeterministicReader("ca-key-leaf"), &workerTemplate, ca, &caKey.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(workerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: workerDER}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "worker/etc/reach-exo/tls/worker-key.pem"), caKeyPEM, 0600); err != nil {
				t.Fatal(err)
			}
			manifest, err := readStrictJSON[ClusterManifest](filepath.Join(root, clusterManifestName), maxManifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Certificates.Worker = certificateFingerprint(workerTemplateFromDER(t, workerDER))
			return rebuildManifestFilesForTest(t, root, manifest)
		},
		"changed preparation provenance": func(t *testing.T, created createdAuthority) string {
			path := filepath.Join(created.inventory.AuthorityRoot, prepareName)
			data := readAll(t, path)
			data = []byte(strings.Replace(string(data), created.inventoryDigest, strings.Repeat("0", 64), 1))
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			return rebuildManifestsForTest(t, created.inventory.AuthorityRoot)
		},
		"changed topology": func(t *testing.T, created createdAuthority) string {
			root := created.inventory.AuthorityRoot
			manifest, err := readStrictJSON[ClusterManifest](filepath.Join(root, clusterManifestName), maxManifestBytes)
			if err != nil {
				t.Fatal(err)
			}
			manifest.Topology.Namespace = "another-cluster"
			manifest.TopologySHA256, _ = topologyDigest(manifest.Topology)
			data, _ := marshalJSON(manifest)
			if err := os.WriteFile(filepath.Join(root, clusterManifestName), data, 0600); err != nil {
				t.Fatal(err)
			}
			return rebuildFileManifestAuthority(t, root, manifest)
		},
		"unknown cluster manifest field": func(t *testing.T, created createdAuthority) string {
			root := created.inventory.AuthorityRoot
			path := filepath.Join(root, clusterManifestName)
			data := readAll(t, path)
			data = append(data[:len(data)-2], []byte(",\"unknown\":true}\n")...)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			manifest, _ := readStrictJSON[ClusterManifest](path, maxManifestBytes)
			return rebuildFileManifestAuthority(t, root, manifest)
		},
		"tampered file manifest": func(t *testing.T, created createdAuthority) string {
			path := filepath.Join(created.inventory.AuthorityRoot, fileManifestName)
			data := append(readAll(t, path), []byte("bad\n")...)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			return created.result.AuthoritySHA256
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			created := createAuthority(t, "refusal-"+name)
			expected := mutate(t, created)
			if _, err := verifyAt(created.inventory.AuthorityRoot, expected, testNow); err == nil {
				t.Fatal("tampered authority was accepted")
			}
		})
	}
}

func TestGeneratedDocumentsUseExistingStrictDecoders(t *testing.T) {
	created := createAuthority(t, "config-decoders")
	root := created.inventory.AuthorityRoot
	for _, path := range []string{"coordinator/etc/reach-exo/node.json", "worker/etc/reach-exo/node.json"} {
		if _, err := config.DecodeNode(readAll(t, filepath.Join(root, filepath.FromSlash(path)))); err != nil {
			t.Fatalf("generated %s: %v", path, err)
		}
	}
	if _, err := config.DecodeConnector(readAll(t, filepath.Join(root, "connector/connector.json"))); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedTLSRoleDirections(t *testing.T) {
	created := createAuthority(t, "tls-directions")
	root := created.inventory.AuthorityRoot
	coordinator := storedTLSFiles(root, "coordinator")
	worker := storedTLSFiles(root, "worker")
	connector := storedTLSFiles(root, "connector")

	workerServer, err := mtls.Server(worker, "reach-exo-coordinator")
	if err != nil {
		t.Fatal(err)
	}
	coordinatorClient, err := mtls.Client(coordinator, "reach-exo-worker")
	if err != nil {
		t.Fatal(err)
	}
	if clientErr, serverErr := handshake(coordinatorClient, workerServer); clientErr != nil || serverErr != nil {
		t.Fatalf("coordinator-client to worker-server failed: %v / %v", clientErr, serverErr)
	}

	coordinatorServer, err := mtls.Server(coordinator, "reach-exo-connector")
	if err != nil {
		t.Fatal(err)
	}
	connectorClient, err := mtls.Client(connector, "reach-exo-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if clientErr, serverErr := handshake(connectorClient, coordinatorServer); clientErr != nil || serverErr != nil {
		t.Fatalf("connector-client to coordinator-server failed: %v / %v", clientErr, serverErr)
	}

	workerClient, err := mtls.Client(worker, "reach-exo-gateway")
	if err != nil {
		t.Fatal(err)
	}
	coordinatorServer, _ = mtls.Server(coordinator, "reach-exo-worker")
	if clientErr, serverErr := handshake(workerClient, coordinatorServer); clientErr == nil && serverErr == nil {
		t.Fatal("server-auth-only worker identity was accepted as a client")
	}

	coordinatorServer, _ = mtls.Server(coordinator, "reach-exo-connector")
	if clientErr, serverErr := handshake(coordinatorClient, coordinatorServer); clientErr == nil && serverErr == nil {
		t.Fatal("wrong client role/name was accepted")
	}

	other := createAuthority(t, "different-ca")
	foreignConnector := storedTLSFiles(other.inventory.AuthorityRoot, "connector")
	foreignClient, _ := mtls.Client(foreignConnector, "reach-exo-gateway")
	coordinatorServer, _ = mtls.Server(coordinator, "reach-exo-connector")
	if clientErr, serverErr := handshake(foreignClient, coordinatorServer); clientErr == nil && serverErr == nil {
		t.Fatal("foreign CA was accepted")
	}

	mismatched := connector
	mismatched.PrivateKey = worker.PrivateKey
	if _, err := mtls.Client(mismatched, "reach-exo-gateway"); err == nil {
		t.Fatal("mismatched leaf key was accepted")
	}
}

func storedTLSFiles(root, role string) config.TLSFiles {
	switch role {
	case "coordinator":
		base := filepath.Join(root, "coordinator/etc/reach-exo/tls")
		return config.TLSFiles{CA: filepath.Join(base, "ca.pem"), Certificate: filepath.Join(base, "coordinator.pem"), PrivateKey: filepath.Join(base, "coordinator-key.pem")}
	case "worker":
		base := filepath.Join(root, "worker/etc/reach-exo/tls")
		return config.TLSFiles{CA: filepath.Join(base, "ca.pem"), Certificate: filepath.Join(base, "worker.pem"), PrivateKey: filepath.Join(base, "worker-key.pem")}
	default:
		base := filepath.Join(root, "connector/tls")
		return config.TLSFiles{CA: filepath.Join(base, "ca.pem"), Certificate: filepath.Join(base, "connector.pem"), PrivateKey: filepath.Join(base, "connector-key.pem")}
	}
}

func handshake(clientConfig, serverConfig *tls.Config) (error, error) {
	clientConnection, serverConnection := net.Pipe()
	deadline := time.Now().Add(time.Second)
	_ = clientConnection.SetDeadline(deadline)
	_ = serverConnection.SetDeadline(deadline)
	client := tls.Client(clientConnection, clientConfig)
	server := tls.Server(serverConnection, serverConfig)
	type result struct {
		client bool
		err    error
	}
	done := make(chan result, 2)
	go func() { done <- result{client: true, err: client.Handshake()} }()
	go func() { done <- result{client: false, err: server.Handshake()} }()
	first := <-done
	if first.err != nil {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	}
	var second result
	select {
	case second = <-done:
	case <-time.After(250 * time.Millisecond):
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		second = <-done
	}
	_ = clientConnection.Close()
	_ = serverConnection.Close()
	var clientErr, serverErr error
	for _, result := range []result{first, second} {
		if result.client {
			clientErr = result.err
		} else {
			serverErr = result.err
		}
	}
	return clientErr, serverErr
}

func rebuildManifestsForTest(t *testing.T, root string) string {
	t.Helper()
	manifest, err := readStrictJSON[ClusterManifest](filepath.Join(root, clusterManifestName), maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	return rebuildManifestFilesForTest(t, root, manifest)
}

func rebuildManifestFilesForTest(t *testing.T, root string, manifest ClusterManifest) string {
	t.Helper()
	for index := range manifest.Files {
		path := filepath.Join(root, filepath.FromSlash(manifest.Files[index].Path))
		digest, bytes, err := fileDigest(path, maxManifestBytes)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files[index].SHA256 = digest
		manifest.Files[index].Bytes = bytes
	}
	data, err := marshalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, clusterManifestName), data, 0600); err != nil {
		t.Fatal(err)
	}
	return rebuildFileManifestAuthority(t, root, manifest)
}

func workerTemplateFromDER(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func rebuildFileManifestAuthority(t *testing.T, root string, manifest ClusterManifest) string {
	t.Helper()
	data, _, err := buildFileManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, fileManifestName), data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return authorityDigest(manifest.InventorySHA256, root, manifest.Exact, manifest.TopologySHA256, manifest.Certificates, hex.EncodeToString(digest[:]))
}
