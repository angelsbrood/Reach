// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"systems.reach/relay-hub/internal/backend"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/manager"
	"systems.reach/relay-hub/internal/netroutes"
	"systems.reach/relay-hub/internal/router"
)

type managedService interface {
	Apply([]byte) error
	RefuseUpdate() error
	RefreshStatus() error
	HasActive() bool
	Close() error
}

type logger func(string)

func main() {
	configPath := flag.String("config", "", "strict configuration path")
	routesPath := flag.String("routes", "", "strict route inventory path")
	statePath := flag.String("state", "", "private state directory")
	statusPath := flag.String("status", "", "private runtime status path")
	flag.Parse()
	if flag.NArg() != 0 || *configPath == "" || *routesPath == "" || *statePath == "" || *statusPath == "" {
		fmt.Fprintln(os.Stderr, "usage: reach-relay-hub --config <path> --routes <path> --state <path> --status <path>")
		os.Exit(2)
	}
	if err := run(*configPath, *routesPath, *statePath, *statusPath); err != nil {
		fmt.Fprintln(os.Stderr, "reach-relay-hub: unavailable")
		os.Exit(1)
	}
}

func run(configPath, routesPath, statePath, statusPath string) error {
	for _, path := range []string{configPath, routesPath, statePath, statusPath} {
		if !filepath.IsAbs(path) {
			return errors.New("operator and runtime paths must be absolute")
		}
	}
	if os.Geteuid() == 0 {
		return errors.New("relay hub service must run unprivileged")
	}
	var root uint32
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	readOperator := operatorReader(configPath, root, gid)
	decode := routeAwareDecoder(routesPath, root, gid, netroutes.KernelPrefixes)
	if err := removeLegacyStatus(filepath.Join(statePath, "status.json"), uid); err != nil {
		return err
	}
	r := router.New()
	b := backend.NewWireGuard(r)
	m := manager.NewWithDecoder(
		manager.Paths{Active: filepath.Join(statePath, "active.json"), Pending: filepath.Join(statePath, "pending.json"), Status: statusPath},
		&uid, decode, b, r,
	)
	if err := m.Start(); err != nil {
		return err
	}
	data, err := readOperator()
	if err != nil {
		if !m.HasActive() {
			_ = m.Close()
			return err
		}
		_ = m.RefuseUpdate()
	} else if err = m.Apply(data); err != nil {
		if !m.HasActive() {
			_ = m.Close()
			return err
		}
		_ = m.RefuseUpdate()
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	return serveSignals(signals, readOperator, m, func(message string) { log.Print(message) })
}

func operatorReader(path string, owner, group uint32) func() ([]byte, error) {
	return func() ([]byte, error) {
		return config.ReadSecureFile(path, config.FileRule{Owner: &owner, Group: &group, Mode: 0o640, Limit: config.MaximumBytes})
	}
}

func routeAwareDecoder(path string, owner, group uint32, kernel func() ([]netip.Prefix, error)) manager.Decoder {
	return func(data []byte) (config.Specification, error) {
		raw, err := config.ReadSecureFile(path, config.FileRule{Owner: &owner, Group: &group, Mode: 0o640, Limit: config.MaximumRouteBytes})
		if err != nil {
			return config.Specification{}, err
		}
		declared, err := config.DecodeRouteInventory(raw)
		if err != nil {
			return config.Specification{}, err
		}
		observed, err := kernel()
		if err != nil {
			return config.Specification{}, err
		}
		spec, err := config.Decode(data, config.UnionRoutes(declared, config.StaticRoutes(observed)))
		if err != nil {
			return config.Specification{}, err
		}
		if spec.ListenPort < 1024 {
			return config.Specification{}, errors.New("privileged listen port rejected")
		}
		return spec, nil
	}
}

func serveSignals(signals <-chan os.Signal, readOperator func() ([]byte, error), service managedService, writeLog logger) error {
	for signalValue := range signals {
		switch signalValue {
		case syscall.SIGHUP:
			data, err := readOperator()
			if err == nil {
				err = service.Apply(data)
			}
			if err != nil {
				if statusErr := service.RefuseUpdate(); statusErr != nil {
					writeLog("relay hub update refused; status unavailable")
				} else {
					writeLog("relay hub update refused")
				}
			}
		case syscall.SIGUSR1:
			if err := service.RefreshStatus(); err != nil {
				writeLog("relay hub status refresh unavailable")
			}
		case syscall.SIGINT, syscall.SIGTERM:
			return service.Close()
		}
	}
	return service.Close()
}

func removeLegacyStatus(path string, owner uint32) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || stat.Uid != owner || stat.Nlink != 1 || (info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o644) {
		return errors.New("historical status file is unsafe")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
