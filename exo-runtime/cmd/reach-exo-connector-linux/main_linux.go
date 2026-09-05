//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"reach.dev/exo-runtime/internal/connectorservice"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv("NOTIFY_SOCKET"), os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, socket string, stderr io.Writer) int {
	foreground := len(args) == 2 && args[0] == "--foreground"
	if foreground {
		args = args[1:]
	}
	if len(args) != 1 || (foreground && socket != "") {
		fmt.Fprintln(stderr, "usage: reach-exo-connector [--foreground] /absolute/path/connector.json; foreground requires no NOTIFY_SOCKET")
		return 64
	}
	if !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] {
		fmt.Fprintln(stderr, "connector startup refused: configuration")
		return 64
	}
	var notify func(string) error
	if !foreground {
		var err error
		notify, err = connectorservice.Notifier(socket)
		if err != nil {
			fmt.Fprintln(stderr, "connector startup refused: notification")
			return 64
		}
	}
	err := connectorservice.Run(ctx, args[0], notify)
	if err == nil {
		return 0
	}
	var startup *connectorservice.StartupError
	if errors.As(err, &startup) {
		fmt.Fprintln(stderr, startup)
		return 64
	}
	fmt.Fprintln(stderr, "connector runtime failed")
	return 1
}
