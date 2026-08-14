// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"systems.reach/relay-hub/internal/backend"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/manager"
	"systems.reach/relay-hub/internal/router"
)

func main() {
	configPath := flag.String("config", "", "strict configuration path")
	statePath := flag.String("state", "", "private state directory")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *statePath == "" {
		fmt.Fprintln(os.Stderr, "usage: reach-relay-hub --config <path> --state <path>")
		os.Exit(2)
	}
	if err := run(*configPath, *statePath); err != nil {
		fmt.Fprintln(os.Stderr, "reach-relay-hub: unavailable")
		os.Exit(1)
	}
}

func run(configPath, statePath string) error {
	if !filepath.IsAbs(configPath) || !filepath.IsAbs(statePath) {
		return errors.New("configuration and state paths must be absolute")
	}
	var root uint32 = 0
	data, err := config.ReadSecureFile(configPath, config.FileRule{Owner: &root, Mode: 0o640, Limit: config.MaximumBytes})
	if err != nil {
		return fmt.Errorf("configuration rejected: %w", err)
	}
	routes := config.StaticRoutes{}
	r := router.New()
	b := backend.NewWireGuard(r)
	uid := uint32(os.Getuid())
	m := manager.New(manager.Paths{Active: filepath.Join(statePath, "active.json"), Pending: filepath.Join(statePath, "pending.json"), Status: filepath.Join(statePath, "status.json")}, &uid, routes, b, r)
	if err = m.Start(); err != nil {
		return err
	}
	if err = m.Apply(data); err != nil {
		_ = m.Close()
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	return waitForSignal(signals, func() error {
		signal.Stop(signals)
		return m.Close()
	})
}

func waitForSignal(signals <-chan os.Signal, closeService func() error) error {
	<-signals
	return closeService()
}
