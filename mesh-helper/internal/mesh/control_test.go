// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlSocketRejectsNonRootPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root has no non-root peer identity to exercise")
	}
	paths := testPaths(t)
	manager := testManager(t, paths, &fakeBackend{})
	if err := manager.Start(); err != nil {
		t.Fatal(err)
	}
	server := NewControlServer(paths.Control, manager)
	if err := server.Listen(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.Serve() }()

	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: paths.Control, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("apply\n")); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(response) != "error" {
		t.Fatalf("response = %q", response)
	}
	info, err := os.Lstat(paths.Control)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
}

func TestStaleControlSocketIsReclaimedWithoutAcceptingOtherObjects(t *testing.T) {
	path := filepath.Join("/private/tmp", fmt.Sprintf("reach-mesh-stale-%d-%d.sock", os.Getpid(), socketSequence.Add(1)))
	t.Cleanup(func() { _ = os.Remove(path) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleControlSocket(path, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale socket remained: %v", err)
	}

	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleControlSocket(path, uint32(os.Getuid())); err == nil {
		t.Fatal("regular file accepted as a stale control socket")
	}
}
