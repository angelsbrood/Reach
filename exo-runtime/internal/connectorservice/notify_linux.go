//go:build linux

package connectorservice

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// Notifier validates systemd's pathname or Linux abstract UNIX datagram address.
// Calling the returned function sends from this process, not a notification helper.
func Notifier(address string) (func(string) error, error) {
	if strings.ContainsRune(address, 0) || address == "" || address == "@" ||
		(address[0] != '@' && (!filepath.IsAbs(address) || filepath.Clean(address) != address)) {
		return nil, &StartupError{"notification", errors.New("invalid NOTIFY_SOCKET")}
	}
	return func(message string) error {
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
		if err != nil {
			return err
		}
		defer conn.Close()
		if err = conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, err := conn.Write([]byte(message))
		if err == nil && n != len(message) {
			return errors.New("short notification write")
		}
		return err
	}, nil
}
