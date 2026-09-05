package bootstrap

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPrivateModesPathsAndExistingOutput(t *testing.T) {
	r, root, result, now := fixture(t)
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("generated mode differs")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(r, root); err == nil {
		t.Fatal("existing output overwritten")
	}
	if _, err := verifyAt(r, root, result.CADERSHA256, now); err != nil {
		t.Fatal("existing bundle was changed")
	}
	alias := root + "-alias"
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(r, alias, result.CADERSHA256); err == nil {
		t.Fatal("bundle alias accepted")
	}
	for _, path := range []string{"relative", root + "/../new", alias + "/new"} {
		if _, err := Create(r, path); err == nil {
			t.Fatal("unsafe output accepted")
		}
	}
	checkout := filepath.Join(parent(t), "checkout")
	os.Mkdir(checkout, 0700)
	put(t, filepath.Join(checkout, ".git"), []byte("gitdir: ignored"))
	if _, err := Create(r, filepath.Join(checkout, "bundle")); err == nil {
		t.Fatal("checkout output accepted")
	}
	p := parent(t)
	os.Chmod(p, 0755)
	if _, err := Create(r, filepath.Join(p, "bundle")); err == nil {
		t.Fatal("wide parent accepted")
	}
}

func TestLinkedWidenedAndSpecialFilesRefuse(t *testing.T) {
	for _, kind := range []string{"file mode", "directory mode", "hardlink", "symlink", "extra directory", "empty file", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			r, root, result, _ := fixture(t)
			path := filepath.Join(root, "server/server-key.pem")
			switch kind {
			case "file mode":
				os.Chmod(path, 0644)
			case "directory mode":
				os.Chmod(filepath.Join(root, "server"), 0755)
			case "hardlink":
				if err := os.Link(path, root+"-key"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				data := read(t, path)
				os.Remove(path)
				put(t, root+"-key", data)
				os.Symlink(root+"-key", path)
			case "extra directory":
				os.Mkdir(filepath.Join(root, "extra"), 0700)
			case "empty file":
				put(t, path, nil)
			case "oversized":
				put(t, path, bytes.Repeat([]byte("x"), 32769))
			}
			if _, err := Verify(r, root, result.CADERSHA256); err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) { return w.Buffer.Write(b[:1]) }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 1, io.ErrShortWrite }

func TestWritesAndPartialCreation(t *testing.T) {
	var w shortWriter
	if err := writeAll(&w, []byte("abc")); err != nil || w.String() != "abc" {
		t.Fatal("short writes truncated")
	}
	if err := writeAll(zeroWriter{}, []byte("abc")); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal("zero progress accepted")
	}
	if err := writeAll(failingWriter{}, []byte("abc")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("write failure lost")
	}
	p := filepath.Join(parent(t), "partial")
	r := request()
	_, err := createWith(r, p, time.Now(), nil, func(root *os.Root, name string, data []byte) error {
		if err := writeFile(root, name, data[:len(data)/2]); err != nil {
			return err
		}
		return io.ErrShortWrite
	})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("creation lost write failure")
	}
	if _, err := Verify(r, p, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("partial output verifies")
	}
	if _, err := Create(r, p); err == nil {
		t.Fatal("partial output overwritten")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("partial output not retained")
	}
}

func TestCrashHelper(t *testing.T) {
	if os.Getenv("REACH_IDENTITY_TEST_CRASH") != "1" {
		return
	}
	_, _ = createAt(request(), os.Getenv("REACH_IDENTITY_TEST_ROOT"), time.Now(), func(string) error { os.Exit(86); return nil })
	os.Exit(87)
}

func TestInterruptedCreationRemainsPrivateAndUnverifiable(t *testing.T) {
	root := filepath.Join(parent(t), "interrupted")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
	cmd.Env = append(os.Environ(), "REACH_IDENTITY_TEST_CRASH=1", "REACH_IDENTITY_TEST_ROOT="+root)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 86 {
		t.Fatal("helper did not interrupt creation")
	}
	if _, err := Create(request(), root); err == nil {
		t.Fatal("interrupted output overwritten")
	}
	ca, _ := parseCertificates(read(t, filepath.Join(root, "operator/ca.pem")), 1)
	if _, err := Verify(request(), root, fingerprint(ca[0].Raw)); err == nil {
		t.Fatal("interrupted output verified")
	}
	if err := privateDirectory(root); err != nil {
		t.Fatal(err)
	}
}
