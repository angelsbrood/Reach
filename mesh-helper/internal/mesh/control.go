// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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
	line, err := bufio.NewReaderSize(io.LimitReader(connection, 129), 128).ReadString('\n')
	request, parseErr := parseApplyRequest(line)
	if err != nil || len(line) > 128 || parseErr != nil {
		_, _ = connection.Write([]byte("error\n"))
		return
	}
	applied, err := server.manager.ApplyExpected(request.generation, request.digest)
	if err != nil {
		if errors.Is(err, errRequestedAuthorityStillStaged) {
			_, _ = connection.Write([]byte(renderApplyResponse("staged", request)))
			return
		}
		_, _ = connection.Write([]byte("error\n"))
		return
	}
	if applied != request {
		_, _ = connection.Write([]byte("error\n"))
		return
	}
	_, _ = connection.Write([]byte(renderApplyResponse("ok", applied)))
}

func renderApplyRequest(authority authorityIdentity) string {
	return fmt.Sprintf("apply %d %s\n", authority.generation, authority.digest)
}

func parseApplyRequest(line string) (authorityIdentity, error) {
	if !strings.HasSuffix(line, "\n") {
		return authorityIdentity{}, errors.New("incomplete control request")
	}
	parts := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	if len(parts) != 3 || parts[0] != "apply" || !validPublicDigest(parts[2]) {
		return authorityIdentity{}, errors.New("invalid control request")
	}
	generation, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || generation == 0 {
		return authorityIdentity{}, errors.New("invalid control generation")
	}
	return authorityIdentity{generation: generation, digest: parts[2]}, nil
}

func renderApplyResponse(outcome string, authority authorityIdentity) string {
	return fmt.Sprintf("%s %d %s\n", outcome, authority.generation, authority.digest)
}

func parseApplyResponseLine(line string) (string, authorityIdentity, error) {
	if !strings.HasSuffix(line, "\n") {
		return "", authorityIdentity{}, errors.New("incomplete control response")
	}
	parts := strings.Split(strings.TrimSuffix(line, "\n"), " ")
	if len(parts) != 3 || (parts[0] != "ok" && parts[0] != "staged") || !validPublicDigest(parts[2]) {
		return "", authorityIdentity{}, errors.New("invalid control response")
	}
	generation, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || generation == 0 {
		return "", authorityIdentity{}, errors.New("invalid control generation")
	}
	return parts[0], authorityIdentity{generation: generation, digest: parts[2]}, nil
}

func validPublicDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, character := range []byte(digest) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
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
