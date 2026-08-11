// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var interfacePattern = regexp.MustCompile(`^utun[0-9]+$`)

type DarwinBackend struct {
	mu             sync.Mutex
	device         *device.Device
	interfaceName  string
	routeInstalled bool
	runCommand     systemCommandRunner
}

type systemCommandRunner func(path string, arguments ...string) error

func NewDarwinBackend() *DarwinBackend {
	return &DarwinBackend{runCommand: fixedSystemCommand}
}

func (backend *DarwinBackend) Apply(spec Specification) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	created := false
	if backend.device == nil {
		tunnel, err := tun.CreateTUN("utun", spec.MTU)
		if err != nil {
			return "", err
		}
		name, err := tunnel.Name()
		if err != nil || !interfacePattern.MatchString(name) {
			_ = tunnel.Close()
			return "", errors.New("unexpected interface identity")
		}
		backend.interfaceName = name
		backend.device = device.NewDevice(
			tunnel,
			conn.NewDefaultBind(),
			device.NewLogger(device.LogLevelSilent, ""),
		)
		created = true
	}
	if err := backend.device.IpcSetOperation(strings.NewReader(spec.UAPI())); err != nil {
		if created {
			backend.discardCreatedInterface()
		}
		return "", err
	}
	if created {
		if err := configureDarwinInterface(backend.interfaceName, spec, backend.runCommand); err != nil {
			backend.discardCreatedInterface()
			return "", err
		}
		backend.routeInstalled = true
	}
	if err := backend.device.Up(); err != nil {
		if created {
			backend.discardCreatedInterface()
		}
		return "", err
	}
	return backend.interfaceName, nil
}

func (backend *DarwinBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	var routeError error
	if backend.routeInstalled {
		routeError = removeDarwinRoute(backend.runCommand)
		backend.routeInstalled = false
	}
	if backend.device != nil {
		backend.device.Close()
		backend.device = nil
		backend.interfaceName = ""
	}
	return routeError
}

func (backend *DarwinBackend) discardCreatedInterface() {
	if backend.routeInstalled {
		_ = removeDarwinRoute(backend.runCommand)
		backend.routeInstalled = false
	}
	if backend.device != nil {
		backend.device.Close()
		backend.device = nil
	}
	backend.interfaceName = ""
}

func configureDarwinInterface(interfaceName string, spec Specification, run systemCommandRunner) error {
	host := strings.TrimSuffix(spec.Address, "/24")
	commands := []struct {
		path      string
		arguments []string
	}{
		{path: "/sbin/ifconfig", arguments: []string{interfaceName, "inet", spec.Address, host, "alias"}},
		{path: "/sbin/ifconfig", arguments: []string{interfaceName, "mtu", strconv.Itoa(spec.MTU)}},
		{path: "/sbin/ifconfig", arguments: []string{interfaceName, "up"}},
		{path: "/sbin/route", arguments: []string{"-q", "-n", "add", "-inet", MeshNetwork, "-interface", interfaceName}},
	}
	for _, command := range commands {
		if err := run(command.path, command.arguments...); err != nil {
			return err
		}
	}
	return nil
}

func removeDarwinRoute(run systemCommandRunner) error {
	return run("/sbin/route", "-q", "-n", "delete", "-inet", MeshNetwork)
}

func fixedSystemCommand(path string, arguments ...string) error {
	command := exec.Command(path, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	return command.Run()
}
