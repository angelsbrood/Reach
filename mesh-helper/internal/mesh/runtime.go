// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func ServeSystem() error {
	if os.Geteuid() != 0 {
		return errors.New("root required")
	}
	if err := validateInstalledExecutable(); err != nil {
		return err
	}
	paths := SystemPaths()
	manager := NewManager(paths, NewDarwinBackend())
	if err := manager.Start(); err != nil {
		return err
	}
	control := NewControlServer(paths.Control, manager)
	if err := control.Listen(); err != nil {
		_ = manager.Close()
		return err
	}
	status := manager.status
	if status.Ready {
		fmt.Println("reach-meshd: ready")
	} else {
		fmt.Println("reach-meshd: waiting for configuration")
	}

	errorsFromControl := make(chan error, 1)
	go func() { errorsFromControl <- control.Serve() }()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-stop:
	case err := <-errorsFromControl:
		if err != nil {
			_ = control.Close()
			_ = manager.Close()
			return err
		}
	}
	signal.Stop(stop)
	_ = control.Close()
	_ = manager.Close()
	fmt.Println("reach-meshd: stopped")
	return nil
}

func validateInstalledExecutable() error {
	executable, err := os.Executable()
	if err != nil || executable != HelperPath {
		return errors.New("canonical helper path required")
	}
	var status syscall.Stat_t
	if err := syscall.Lstat(executable, &status); err != nil {
		return err
	}
	if status.Mode&syscall.S_IFMT != syscall.S_IFREG || status.Uid != 0 || status.Nlink != 1 || status.Mode&0o777 != 0o555 {
		return errors.New("unsafe helper ownership")
	}
	return nil
}
