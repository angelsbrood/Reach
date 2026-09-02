package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateVerifyAndRecoveryCLI(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "authority")
	inventoryPath := filepath.Join(parent, "inventory.json")
	inventory := map[string]any{
		"schema_version": 1, "namespace": "reach-cli", "authority_root": root,
		"private_network_cidr": "10.42.0.0/29", "connector_address": "10.42.0.1",
		"gateway_mode":       "direct-gateway",
		"coordinator":        map[string]any{"name": "reach-exo-a", "address": "10.42.0.2", "interface": "eth0", "mac_address": "52:55:55:00:00:02"},
		"worker":             map[string]any{"name": "reach-exo-b", "address": "10.42.0.6", "interface": "eth0", "mac_address": "52:55:55:00:00:03"},
		"certificate_expiry": time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
	}
	data, _ := json.Marshal(inventory)
	if err := os.WriteFile(inventoryPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	var commitment bytes.Buffer
	if err := run([]string{"create", "--inventory", inventoryPath}, &commitment); err != nil {
		t.Fatal(err)
	}
	var record struct {
		SchemaVersion   int    `json:"schema_version"`
		AuthoritySHA256 string `json:"authority_sha256"`
	}
	if err := json.Unmarshal(commitment.Bytes(), &record); err != nil || record.SchemaVersion != 1 || len(record.AuthoritySHA256) != 64 {
		t.Fatalf("commitment output differs: %q %v", commitment.Bytes(), err)
	}
	var verification bytes.Buffer
	if err := run([]string{"verify", "--authority-root", root, "--expected-authority-sha256", record.AuthoritySHA256}, &verification); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verification.String(), `"valid": true`) || strings.Contains(verification.String(), "10.42") {
		t.Fatalf("verification output is not privacy-safe: %s", verification.String())
	}
	if err := run([]string{"recover", "--discard-uncommitted", "--confirm-discard-uncommitted", "--inventory", inventoryPath, "--target", "prepared", "--commitment-state", "complete"}, &bytes.Buffer{}); err == nil {
		t.Fatal("complete commitment was accepted for destructive recovery")
	}
}

func TestCLIRejectsAmbientOrIncompleteInvocation(t *testing.T) {
	for _, arguments := range [][]string{
		nil,
		{"create"},
		{"create", "--inventory", "relative.json"},
		{"verify", "--authority-root", "/tmp/x"},
		{"recover", "--discard-uncommitted"},
		{"unknown"},
	} {
		if err := run(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid invocation was accepted: %v", arguments)
		}
	}
}

func TestDirectOutputWriterRefusesZeroProgress(t *testing.T) {
	if err := writeDirect(zeroWriter{}, []byte("result\n")); err == nil {
		t.Fatal("zero-progress writer was accepted")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
