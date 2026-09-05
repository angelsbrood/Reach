//go:build linux

package connectorservice

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifierPathnameAndAbstract(t *testing.T) {
	for _, abstract := range []bool{false, true} {
		t.Run(fmt.Sprint(abstract), func(t *testing.T) {
			address := filepath.Join(t.TempDir(), "notify")
			if abstract {
				address = fmt.Sprintf("@reach-connector-%d-%d", os.Getpid(), time.Now().UnixNano())
			}
			socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: address, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			notify, err := Notifier(address)
			if err != nil {
				t.Fatal(err)
			}
			if err = notify("READY=1"); err != nil {
				t.Fatal(err)
			}
			_ = socket.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 128)
			n, _, err := socket.ReadFromUnix(b)
			if err != nil || string(b[:n]) != "READY=1" {
				t.Fatalf("notification n=%d err=%v", n, err)
			}
		})
	}
}

func TestNotifierRefusesInvalidOrMissingReceiver(t *testing.T) {
	for _, address := range []string{"", "@", "relative", "/tmp/../notify", "/tmp/a\x00b"} {
		if _, err := Notifier(address); err == nil {
			t.Fatalf("accepted invalid address %q", address)
		}
	}
	notify, err := Notifier(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if err = notify("READY=1"); err == nil {
		t.Fatal("notification to absent socket succeeded")
	}
}
