// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestWaitForSignalClosesExactlyOnce(t *testing.T) {
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	calls := 0
	want := errors.New("closed")
	if got := waitForSignal(signals, func() error { calls++; return want }); !errors.Is(got, want) {
		t.Fatal(got)
	}
	if calls != 1 {
		t.Fatalf("close calls = %d", calls)
	}
}
