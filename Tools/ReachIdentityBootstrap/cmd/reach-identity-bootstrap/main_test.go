package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPlatformAndOperatorBeforeDispatch(t *testing.T) {
	for _, test := range []struct {
		goos, arch string
		uid, euid  int
		ok         bool
	}{{"linux", "arm64", 501, 501, true}, {"linux", "amd64", 501, 501, false}, {"darwin", "arm64", 501, 501, false}, {"windows", "arm64", 501, 501, false}, {"linux", "arm64", 0, 0, false}, {"linux", "arm64", 501, 0, false}, {"linux", "arm64", 501, 502, false}} {
		if (validatePlatform(test.goos, test.arch, test.uid, test.euid) == nil) != test.ok {
			t.Fatal("platform/operator gate differs")
		}
	}
}

func TestCLIRefusals(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"create"}, {"verify"}, {"create", "--config", "relative", "--output", "relative"}, {"create", "--unknown"}, {"verify", "--config", "/missing", "--bundle", "/missing"}} {
		var out bytes.Buffer
		if run(args, &out) == nil || out.Len() != 0 {
			t.Fatal("invalid CLI produced success")
		}
	}
}

func TestNativeCreateVerifyAndOutput(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		t.Skip("native Linux CLI")
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(parent, 0700)
	path := filepath.Join(parent, "request.json")
	output := filepath.Join(parent, "bundle")
	data := []byte(`{"schemaVersion":1,"clusterName":"Test cluster","clientName":"Test client","clientID":"12345678-1234-1234-1234-123456789abc","listen":{"address":"127.0.0.1","port":48660},"advertisedRoads":[{"address":"127.0.0.1","port":48660}],"modelID":"reach-s66-synthetic-model","exoEndpoint":"http://127.0.0.1:48663"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"create", "--config", path, "--output", output}, &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		CA      string `json:"ca_der_sha256"`
		Created bool   `json:"created"`
		Valid   bool   `json:"valid"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.Created || result.Valid {
		t.Fatal("create result differs")
	}
	args := []string{"verify", "--config", path, "--bundle", output, "--expected-ca-sha256", result.CA}
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.Valid {
		t.Fatal("verify result differs")
	}
	if err := run(args, zeroOutput{}); err == nil {
		t.Fatal("stdout failure ignored")
	}
	var short shortOutput
	if err := run(args, &short); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(short.Bytes()) {
		t.Fatal("short writes truncated JSON")
	}
}

type zeroOutput struct{}

func (zeroOutput) Write([]byte) (int, error) { return 0, nil }

type shortOutput struct{ bytes.Buffer }

func (w *shortOutput) Write(b []byte) (int, error) { return w.Buffer.Write(b[:1]) }
