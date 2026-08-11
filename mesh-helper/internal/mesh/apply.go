// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func ApplyFromSudo(paths Paths, input string) error {
	if os.Geteuid() != 0 {
		return errors.New("root required")
	}
	if err := validateInstalledExecutable(); err != nil {
		return err
	}
	sudoUIDText := os.Getenv("SUDO_UID")
	sudoUID64, err := strconv.ParseUint(sudoUIDText, 10, 32)
	if err != nil || sudoUID64 == 0 {
		return errors.New("valid SUDO_UID required")
	}
	sudoUID := uint32(sudoUID64)
	if err := ValidateUserStagingParent(input, sudoUID); err != nil {
		return err
	}
	data, err := ReadSecureFile(input, FileRule{Owner: sudoUID, Mode: 0o600, Limit: MaximumSpecBytes})
	if err != nil {
		return err
	}
	// Once a file has passed owner, mode, link-count, size and unchanged-file
	// checks, consume it on every semantic outcome. A rejected secret should
	// not remain parked in user state.
	defer os.Remove(input)
	spec, err := DecodeSpecification(data)
	if err != nil {
		return err
	}
	if err := EnsureRootDirectories(paths); err != nil {
		return err
	}
	lock, err := unix.Open(paths.Lock, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(lock)
	var lockStatus unix.Stat_t
	if err := unix.Fstat(lock, &lockStatus); err != nil || lockStatus.Mode&unix.S_IFMT != unix.S_IFREG || lockStatus.Uid != 0 || lockStatus.Nlink != 1 || lockStatus.Mode&0o777 != 0o600 {
		return errors.New("unsafe apply lock")
	}
	if err := unix.Flock(lock, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	if err := stageRootPending(paths, data, spec); err != nil {
		return err
	}

	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: paths.Control, Net: "unix"})
	if err != nil {
		return errors.New("mesh owner is not accepting updates; the validated pending generation remains staged")
	}
	defer connection.Close()
	_ = connection.SetDeadline(nowPlusControlBudget())
	if _, err := connection.Write([]byte("apply\n")); err != nil {
		return err
	}
	response, err := bufio.NewReaderSize(connection, 32).ReadString('\n')
	if err != nil || strings.TrimSpace(response) != "ok" {
		return fmt.Errorf("mesh owner refused generation %d", spec.Generation)
	}
	return nil
}
