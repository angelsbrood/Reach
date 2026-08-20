// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

type publicApplyOutcomeError struct {
	message string
}

func (outcome publicApplyOutcomeError) Error() string {
	return outcome.message
}

// PublicApplyOutcome returns only the bounded, privacy-safe apply outcome that
// the privileged helper may show to its invoking operator. Validation,
// filesystem, backend, and other internal errors remain deliberately opaque.
func PublicApplyOutcome(err error) (string, bool) {
	var outcome publicApplyOutcomeError
	if !errors.As(err, &outcome) {
		return "", false
	}
	return outcome.message, true
}

func publicApplyOutcome(format string, arguments ...any) error {
	return publicApplyOutcomeError{message: fmt.Sprintf(format, arguments...)}
}

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
	_ = connection.SetWriteDeadline(nowPlusControlBudget())
	expected := authorityIdentity{generation: spec.Generation, digest: spec.PublicDigest()}
	if _, err := connection.Write([]byte(renderApplyRequest(expected))); err != nil {
		return err
	}
	response, err := bufio.NewReaderSize(connection, 128).ReadString('\n')
	return applyResponse(expected, response, err)
}

func applyResponse(expected authorityIdentity, response string, readErr error) error {
	if readErr != nil {
		return publicApplyOutcome(
			"mesh owner accepted generation %d but did not report its final outcome; inspect `reachd service status` before retrying",
			expected.generation,
		)
	}
	if response == "error\n" {
		return publicApplyOutcome("mesh owner refused generation %d", expected.generation)
	}
	outcome, applied, err := parseApplyResponseLine(response)
	if err != nil {
		return publicApplyOutcome("mesh owner returned an invalid outcome for generation %d", expected.generation)
	}
	if applied != expected {
		return publicApplyOutcome(
			"mesh owner reported a different authority at generation %d than requested generation %d; inspect `reachd service status` before retrying",
			applied.generation,
			expected.generation,
		)
	}
	if outcome == "staged" {
		return publicApplyOutcome(
			"mesh generation %d remains staged because an earlier authority could not finish; inspect `reachd service status` before retrying",
			expected.generation,
		)
	}
	return nil
}
