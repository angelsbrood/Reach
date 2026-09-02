package bootstrap

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ensureAbsent(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("attributable path already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func makePrivateDirectoriesAt(root *os.Root, relative []string, deps dependencies) error {
	for _, item := range relative {
		if !safeRelative(item) {
			return errors.New("unsafe private directory path")
		}
		if err := deps.reach("before-mkdir:" + item); err != nil {
			return err
		}
		if err := root.Mkdir(item, 0700); err != nil {
			return err
		}
		if err := deps.reach("after-mkdir:" + item); err != nil {
			return err
		}
	}
	return nil
}

func writePrivateFileAt(root *os.Root, relative string, data []byte, deps dependencies, point string) error {
	if !safeRelative(relative) {
		return errors.New("unsafe private file path")
	}
	if err := deps.reach("before-write:" + point); err != nil {
		return err
	}
	file, err := root.OpenFile(relative, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	accepted := 0
	for accepted < len(data) {
		count, writeErr := file.Write(data[accepted:])
		if count > 0 {
			accepted += count
		}
		if writeErr != nil {
			file.Close()
			return writeErr
		}
		if count == 0 {
			file.Close()
			return errors.New("zero-progress file write")
		}
	}
	if err := deps.reach("after-write:" + point); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := deps.reach("after-fsync:" + point); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return deps.reach("after-close:" + point)
}

func syncDirectory(path string, deps dependencies, point string) error {
	if err := deps.reach("before-fsync-dir:" + point); err != nil {
		return err
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return deps.reach("after-fsync-dir:" + point)
}

func syncOpenedRoot(root *os.Root, deps dependencies, point string) error {
	if err := deps.reach("before-fsync-dir:" + point); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return deps.reach("after-fsync-dir:" + point)
}

func syncTreeDirectories(root string, deps dependencies) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(left, right int) bool {
		return strings.Count(directories[left], string(filepath.Separator)) > strings.Count(directories[right], string(filepath.Separator))
	})
	for _, path := range directories {
		relative, _ := filepath.Rel(root, path)
		if err := syncDirectory(path, deps, "tree:"+filepath.ToSlash(relative)); err != nil {
			return err
		}
	}
	return nil
}

func safeRelative(path string) bool {
	if path == "" || path == "." || filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') || strings.Contains(path, "\\") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean == path && clean != ".." && !strings.HasPrefix(clean, "../")
}
