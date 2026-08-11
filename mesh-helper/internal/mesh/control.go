// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type ControlServer struct {
	path     string
	manager  *Manager
	listener *net.UnixListener
	closing  sync.Once
}

func NewControlServer(path string, manager *Manager) *ControlServer {
	return &ControlServer{path: path, manager: manager}
}

func (server *ControlServer) Listen() error {
	if err := removeStaleControlSocket(server.path, 0); err != nil {
		return err
	}
	address := &net.UnixAddr{Name: server.path, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return err
	}
	if err := os.Chmod(server.path, 0o600); err != nil {
		listener.Close()
		_ = os.Remove(server.path)
		return err
	}
	server.listener = listener
	return nil
}

func removeStaleControlSocket(path string, owner uint32) error {
	var status unix.Stat_t
	if err := unix.Lstat(path, &status); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFSOCK || status.Uid != owner {
		return errors.New("unsafe existing control socket")
	}
	return unix.Unlink(path)
}

func (server *ControlServer) Serve() error {
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go server.handle(connection)
	}
}

func (server *ControlServer) handle(connection *net.UnixConn) {
	defer connection.Close()
	uid, err := peerUID(connection)
	if err != nil || uid != 0 {
		_, _ = connection.Write([]byte("error\n"))
		return
	}
	_ = connection.SetReadDeadline(nowPlusControlBudget())
	line, err := bufio.NewReaderSize(connection, 64).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "apply" {
		_, _ = connection.Write([]byte("error\n"))
		return
	}
	if err := server.manager.ApplyPending(); err != nil {
		_, _ = connection.Write([]byte("error\n"))
		return
	}
	_, _ = connection.Write([]byte("ok\n"))
}

func (server *ControlServer) Close() error {
	var err error
	server.closing.Do(func() {
		if server.listener != nil {
			err = server.listener.Close()
		}
		_ = os.Remove(server.path)
	})
	return err
}

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var credentialError error
	if err := raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			credentialError = err
			return
		}
		uid = credential.Uid
	}); err != nil {
		return 0, err
	}
	return uid, credentialError
}
