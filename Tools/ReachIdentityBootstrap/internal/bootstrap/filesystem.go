package bootstrap

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func requireOperator() error {
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		return errors.New("an unprivileged operator is required")
	}
	return nil
}

func canonical(path string, existing bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 4096 {
		return errors.New("path must be canonical and absolute")
	}
	p := path
	if !existing {
		p = filepath.Dir(path)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil || resolved != p {
		return errors.New("path aliases or missing parents are not allowed")
	}
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		p = filepath.Dir(p)
	}
	for ancestor := p; ; ancestor = filepath.Dir(ancestor) {
		if _, err := os.Lstat(filepath.Join(ancestor, ".git")); err == nil {
			return errors.New("paths inside a checkout are not allowed")
		} else if !os.IsNotExist(err) {
			return err
		}
		if ancestor == "/" {
			break
		}
	}
	return nil
}

func privateDirectory(path string) error {
	if err := canonical(path, true); err != nil {
		return err
	}
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm() != 0700 || s.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory must be current-owner 0700")
	}
	return nil
}

func privateFile(info os.FileInfo, maximum int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Size() < 1 || info.Size() > int64(maximum) {
		return errors.New("file must be bounded, regular, single-link and current-owner 0600")
	}
	return nil
}

func readPrivate(path string, maximum int) ([]byte, error) {
	if err := canonical(path, true); err != nil {
		return nil, err
	}
	if err := privateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := privateFile(before, maximum); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := privateFile(after, maximum); err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, errors.New("file changed during open")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if err != nil || len(data) > maximum || int64(len(data)) != after.Size() {
		return nil, errors.New("bounded read failed or file changed")
	}
	return data, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("invalid write count")
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func writeFile(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	err = f.Chmod(0600)
	if err == nil {
		err = writeAll(f, data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func exactEntries(path string, names []string) error {
	if err := privateDirectory(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := f.ReadDir(len(names) + 1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) != len(names) {
		return errors.New("missing or extra bundle entry")
	}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return errors.New("unexpected bundle entry")
		}
	}
	return nil
}
