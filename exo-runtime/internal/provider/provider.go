// Package provider owns one EXO process group and its terminal settlement.
package provider

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"reach.dev/exo-runtime/internal/authority"
)

type Manager struct {
	mu      sync.Mutex
	command *exec.Cmd
	done    chan error
	log     *os.File
}

func (m *Manager) Start(epoch, role, namespacePrefix string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.command != nil {
		return 0, errors.New("provider process already owned")
	}
	if role != "coordinator" && role != "worker" {
		return 0, errors.New("invalid provider role")
	}
	for _, r := range epoch {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return 0, errors.New("invalid provider epoch")
		}
	}
	if err := os.MkdirAll(authority.StateRoot+"/logs", 0700); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(authority.StateRoot+"/home", 0700); err != nil {
		return 0, err
	}
	logPath := filepath.Join(authority.StateRoot, "logs", "provider-"+epoch+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	program, arguments := commandLine(epoch, role, namespacePrefix)
	command := exec.Command(program, arguments...)
	command.Dir = authority.ProgramRoot + "/provider"
	command.Stdout = logFile
	command.Stderr = logFile
	command.Stdin = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Env = providerEnvironment(epoch)
	if err := command.Start(); err != nil {
		logFile.Close()
		return 0, err
	}
	done := make(chan error, 1)
	m.command = command
	m.done = done
	m.log = logFile
	go func() {
		err := command.Wait()
		logFile.Close()
		done <- err
		close(done)
	}()
	return command.Process.Pid, nil
}

func commandLine(epoch, role, namespacePrefix string) (string, []string) {
	program := authority.ProgramRoot + "/provider/.venv/bin/exo"
	arguments := []string{
		"--offline", "--no-downloads", "--no-batch",
		"--namespace", namespacePrefix + "-" + epoch,
		"--zenoh-port", strconv.Itoa(authority.ProviderZenohPort),
		"--discovery-port", strconv.Itoa(authority.ProviderDiscoverPort),
		"--api-port", strconv.Itoa(authority.ProviderAPIPort),
	}
	if role == "coordinator" {
		arguments = append(arguments, "--force-master")
	}
	return program, arguments
}

func (m *Manager) Running() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.command == nil {
		return false, nil
	}
	select {
	case err := <-m.done:
		m.clearLocked()
		if err == nil {
			return false, errors.New("provider exited unexpectedly with status zero")
		}
		return false, err
	default:
		return true, nil
	}
}

func (m *Manager) PID() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.command == nil || m.command.Process == nil {
		return 0
	}
	return m.command.Process.Pid
}

func (m *Manager) Stop(timeout time.Duration) error {
	m.mu.Lock()
	if m.command == nil {
		m.mu.Unlock()
		return nil
	}
	command := m.command
	done := m.done
	pid := command.Process.Pid
	m.mu.Unlock()
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var err error
	select {
	case waitErr := <-done:
		if waitErr != nil && !expectedSignal(waitErr) {
			err = waitErr
		}
	case <-timer.C:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			err = errors.New("provider process group did not acknowledge SIGKILL")
		}
	}
	m.mu.Lock()
	if m.command == command {
		m.clearLocked()
	}
	m.mu.Unlock()
	return err
}

func (m *Manager) clearLocked() {
	m.command = nil
	m.done = nil
	m.log = nil
}

func providerEnvironment(epoch string) []string {
	home := authority.StateRoot + "/home"
	values := []string{
		"PATH=" + authority.ProgramRoot + "/provider/.venv/bin:/usr/bin:/bin",
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + authority.StateRoot + "/config",
		"XDG_DATA_HOME=" + authority.StateRoot + "/data",
		"XDG_CACHE_HOME=" + authority.StateRoot + "/cache",
		"TMPDIR=" + authority.StateRoot + "/tmp",
		"EXO_MODELS_READ_ONLY_DIRS=" + authority.ModelRoot,
		"EXO_DEFAULT_MODELS_DIR=" + authority.StateRoot + "/models",
		"EXO_RESOURCES_DIR=" + authority.ProgramRoot + "/provider/resources",
		"EXO_DASHBOARD_DIR=" + authority.ProgramRoot + "/provider/dashboard",
		"EXO_OFFLINE=true",
		"HF_HUB_OFFLINE=1",
		"TRANSFORMERS_OFFLINE=1",
		"HF_HUB_DISABLE_TELEMETRY=1",
		"DO_NOT_TRACK=1",
		"REACH_EXO_EPOCH=" + epoch,
		"PYTHONPATH=" + authority.ProgramRoot + "/provider/src",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONUNBUFFERED=1",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	return values
}

func expectedSignal(err error) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && (status.Signal() == syscall.SIGTERM || status.Signal() == syscall.SIGKILL)
}

func ValidateInstalledLayout() error {
	checks := map[string]os.FileMode{
		authority.ProgramRoot + "/provider/.venv/bin/python": 0111,
		authority.ProgramRoot + "/provider/.venv/bin/exo":    0111,
		authority.ProgramRoot + "/provider/pyproject.toml":   0444,
		authority.ModelRoot: os.ModeDir,
	}
	for path, required := range checks {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if required == os.ModeDir {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", path)
			}
			continue
		}
		if info.Mode().Perm()&required != required {
			return fmt.Errorf("%s lacks required mode %04o", path, required)
		}
	}
	modelDir := filepath.Join(authority.ModelRoot, strings.ReplaceAll(authority.ModelID, "/", "--"))
	info, err := os.Stat(modelDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("selected model directory unavailable: %w", err)
	}
	return validateModel(modelDir)
}

func validateModel(modelDir string) error {
	manifestPath := authority.ProgramRoot + "/share/model.MANIFEST.sha256"
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(manifestDigest[:]) != authority.ModelManifestSHA256 {
		return errors.New("installed model authority manifest has drifted")
	}
	wanted := make(map[string]string, authority.ModelFileCount)
	scanner := bufio.NewScanner(strings.NewReader(string(manifestBytes)))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return errors.New("model authority manifest has invalid syntax")
		}
		name := line[66:]
		if name == "" || filepath.Base(name) != name || strings.Contains(name, "..") {
			return errors.New("model authority manifest has unsafe path")
		}
		wanted[name] = line[:64]
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(wanted) != authority.ModelFileCount {
		return errors.New("model authority manifest file count is not exact")
	}
	entries, err := os.ReadDir(modelDir)
	if err != nil {
		return err
	}
	if len(entries) != authority.ModelFileCount {
		return fmt.Errorf("model directory entry count is %d, want %d", len(entries), authority.ModelFileCount)
	}
	var byteCount int64
	for _, entry := range entries {
		expected, ok := wanted[entry.Name()]
		if !ok || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected or nonregular model entry %q", entry.Name())
		}
		path := filepath.Join(modelDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0222 != 0 {
			return fmt.Errorf("model entry %q is writable", entry.Name())
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(hash.Sum(nil)) != expected {
			return fmt.Errorf("model entry %q hash mismatch", entry.Name())
		}
		byteCount += info.Size()
	}
	if byteCount != authority.ModelByteCount {
		return fmt.Errorf("model byte count is %d, want %d", byteCount, authority.ModelByteCount)
	}
	return nil
}
