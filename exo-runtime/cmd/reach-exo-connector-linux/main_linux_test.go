//go:build linux

package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageAndNotificationFailuresExit64(t *testing.T) {
	for _, args := range [][]string{nil, {"one", "two"}, {"--foreground", "/missing"}} {
		var out bytes.Buffer
		socket := ""
		if len(args) == 2 && args[0] == "--foreground" {
			socket = "@systemd"
		}
		if code := run(context.Background(), args, socket, &out); code != 64 {
			t.Fatalf("code=%d", code)
		}
	}
	var out bytes.Buffer
	if code := run(context.Background(), []string{"/missing"}, "", &out); code != 64 || !strings.Contains(out.String(), "notification") {
		t.Fatalf("code=%d output=%s", code, out.String())
	}
}

func TestConfigurationFailureExit64DoesNotLeakInput(t *testing.T) {
	for _, foreground := range []bool{false, true} {
		var out bytes.Buffer
		path := filepath.Join(t.TempDir(), "secret-name-not-to-log")
		args := []string{path}
		socket := "@unavailable"
		if foreground {
			args = []string{"--foreground", path}
			socket = ""
		}
		code := run(context.Background(), args, socket, &out)
		if code != 64 || !strings.Contains(out.String(), "configuration") || strings.Contains(out.String(), path) {
			t.Fatalf("code=%d output=%s", code, out.String())
		}
	}
}
