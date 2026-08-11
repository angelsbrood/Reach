// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type FileRule struct {
	Owner uint32
	Mode  uint16
	Limit int64
}

func ReadSecureFile(path string, rule FileRule) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != rule.Owner || before.Nlink != 1 || before.Mode&0o777 != rule.Mode || before.Size <= 0 || before.Size > rule.Limit {
		return nil, errors.New("unsafe configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(file, rule.Limit+1))
	if err != nil || int64(len(data)) > rule.Limit {
		return nil, errors.New("configuration read failed")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	var named unix.Stat_t
	if err := unix.Lstat(path, &named); err != nil {
		return nil, errors.New("configuration path changed while reading")
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || int64(len(data)) != after.Size {
		return nil, errors.New("configuration changed while reading")
	}
	if after.Dev != named.Dev || after.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFREG || named.Uid != rule.Owner || named.Nlink != 1 || named.Mode&0o777 != rule.Mode {
		return nil, errors.New("configuration path changed while reading")
	}
	return data, nil
}

func ValidateDirectory(path string, owner uint32, mode uint16) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner || stat.Mode&0o777 != mode {
		return errors.New("unsafe state directory")
	}
	return nil
}

func EnsureRootDirectories(paths Paths) error {
	return ensureDirectories(paths, 0)
}

func ensureDirectories(paths Paths, owner uint32) error {
	if err := createOrValidateDirectory(paths.State, owner, 0o755); err != nil {
		return err
	}
	return createOrValidateDirectory(paths.Private, owner, 0o700)
}

// Existing privileged paths are evidence, not repair targets. In particular,
// never chmod before lstat: chmod follows a symlink and would let a planted
// state path redirect a root permission change onto an unrelated target.
func createOrValidateDirectory(path string, owner uint32, mode uint16) error {
	if err := os.Mkdir(path, os.FileMode(mode)); err == nil {
		// launchd deliberately gives the helper Umask 077. Set the declared
		// mode through the descriptor for the directory we just created so
		// the public status parent remains traversable without ever chmodding
		// a pre-existing path or following a replacement symlink.
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		var created unix.Stat_t
		if err := unix.Fstat(fd, &created); err != nil {
			return err
		}
		if created.Mode&unix.S_IFMT != unix.S_IFDIR || created.Uid != owner {
			return errors.New("unsafe newly created state directory")
		}
		if err := unix.Fchmod(fd, uint32(mode)); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := ValidateDirectory(path, owner, mode); err != nil {
		return fmt.Errorf("unsafe directory %s: %w", path, err)
	}
	return nil
}

func ValidateUserStagingParent(path string, owner uint32) error {
	parent := filepath.Dir(path)
	var stat unix.Stat_t
	if err := unix.Lstat(parent, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner || stat.Mode&0o777 != 0o700 {
		return errors.New("unsafe staging directory")
	}
	return nil
}

func WriteRootFileAtomically(path string, data []byte, mode os.FileMode) error {
	temporary := fmt.Sprintf("%s.new.%d", path, os.Getpid())
	fd, err := unix.Open(temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temporary)
	clean := false
	defer func() {
		file.Close()
		if !clean {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	clean = true
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		defer directory.Close()
		_ = directory.Sync()
	}
	return nil
}
