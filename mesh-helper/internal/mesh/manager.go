// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

type Manager struct {
	mu      sync.Mutex
	paths   Paths
	backend Backend
	owner   uint32
	active  *Specification
	status  Status
}

func NewManager(paths Paths, backend Backend) *Manager {
	return &Manager{paths: paths, backend: backend, owner: 0, status: NewStatus()}
}

func (manager *Manager) Start() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ensureDirectories(manager.paths, manager.owner); err != nil {
		return err
	}
	active, activeErr := readSpecification(manager.paths.Active, manager.owner)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		manager.status = manager.status.WithError("configuration rejected")
		_ = WriteStatus(manager.paths.Status, manager.status)
		return activeErr
	}
	if activeErr == nil {
		manager.active = &active
	}

	if _, err := os.Lstat(manager.paths.Pending); err == nil {
		if err := manager.applyPendingLocked(); err == nil {
			return nil
		}
		// A pending update may fail without taking the last-known-good road
		// down. Apply the active specification again before reporting it.
		if manager.active != nil {
			if _, restoreErr := manager.applyBackend(*manager.active); restoreErr == nil {
				_ = os.Remove(manager.paths.Pending)
				manager.status.Error = "rollback restored"
				_ = WriteStatus(manager.paths.Status, manager.status)
				return nil
			}
		}
		return errors.New("pending and active configurations unavailable")
	}

	if manager.active == nil {
		manager.status = manager.status.WithError("unconfigured")
		return WriteStatus(manager.paths.Status, manager.status)
	}
	_, err := manager.applyBackend(*manager.active)
	return err
}

func (manager *Manager) ApplyPending() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.applyPendingLocked()
}

func (manager *Manager) applyPendingLocked() error {
	candidate, err := readSpecification(manager.paths.Pending, manager.owner)
	if err != nil {
		manager.status = manager.status.WithError("configuration rejected")
		_ = WriteStatus(manager.paths.Status, manager.status)
		return err
	}
	if manager.active != nil {
		activeDigest := manager.active.PublicDigest()
		candidateDigest := candidate.PublicDigest()
		switch {
		case candidate.Generation < manager.active.Generation:
			_ = os.Remove(manager.paths.Pending)
			manager.status = manager.status.WithError("update refused")
			_ = WriteStatus(manager.paths.Status, manager.status)
			return errors.New("generation rollback refused")
		case candidate.Generation == manager.active.Generation && candidateDigest != activeDigest:
			_ = os.Remove(manager.paths.Pending)
			manager.status = manager.status.WithError("update refused")
			_ = WriteStatus(manager.paths.Status, manager.status)
			return errors.New("generation reused with different configuration")
		case candidate.Generation == manager.active.Generation && candidateDigest == activeDigest:
			_ = os.Remove(manager.paths.Pending)
			_, err := manager.applyBackend(*manager.active)
			return err
		}
	}

	if _, err := manager.applyBackend(candidate); err != nil {
		if manager.active != nil {
			if _, restoreErr := manager.applyBackend(*manager.active); restoreErr == nil {
				_ = os.Remove(manager.paths.Pending)
				manager.status.Error = "rollback restored"
				_ = WriteStatus(manager.paths.Status, manager.status)
			}
		}
		return err
	}
	if err := os.Rename(manager.paths.Pending, manager.paths.Active); err != nil {
		if manager.active != nil {
			_, _ = manager.applyBackend(*manager.active)
		} else {
			_ = manager.backend.Close()
			manager.status = manager.status.WithError("configuration rejected")
		}
		if manager.active != nil {
			manager.status = manager.status.WithError("rollback restored")
		}
		_ = WriteStatus(manager.paths.Status, manager.status)
		return err
	}
	manager.active = &candidate
	if directory, err := os.Open(manager.paths.Private); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (manager *Manager) applyBackend(spec Specification) (string, error) {
	name, err := manager.backend.Apply(spec)
	if err != nil {
		manager.status = manager.status.WithError("interface unavailable")
		_ = WriteStatus(manager.paths.Status, manager.status)
		return "", err
	}
	manager.status = Status{
		HelperVersion: HelperVersion,
		PID:           os.Getpid(),
		Generation:    spec.Generation,
		PublicDigest:  spec.PublicDigest(),
		InterfaceName: name,
		Ready:         true,
		PeerCount:     len(spec.Peers),
	}
	if err := WriteStatus(manager.paths.Status, manager.status); err != nil {
		return "", err
	}
	return name, nil
}

func (manager *Manager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	err := manager.backend.Close()
	manager.status = manager.status.WithError("stopped")
	_ = WriteStatus(manager.paths.Status, manager.status)
	return err
}

func readSpecification(path string, owner uint32) (Specification, error) {
	data, err := ReadSecureFile(path, FileRule{Owner: owner, Mode: 0o600, Limit: MaximumSpecBytes})
	if err != nil {
		return Specification{}, err
	}
	return DecodeSpecification(data)
}

func stageRootPending(paths Paths, data []byte, spec Specification) error {
	if err := EnsureRootDirectories(paths); err != nil {
		return err
	}
	if active, err := readSpecification(paths.Active, 0); err == nil {
		if spec.Generation < active.Generation || (spec.Generation == active.Generation && spec.PublicDigest() != active.PublicDigest()) {
			return errors.New("generation rollback refused")
		}
	}
	if pending, err := readSpecification(paths.Pending, 0); err == nil {
		if spec.Generation < pending.Generation || (spec.Generation == pending.Generation && spec.PublicDigest() != pending.PublicDigest()) {
			return errors.New("newer pending generation already staged")
		}
	}
	if err := WriteRootFileAtomically(paths.Pending, data, 0o600); err != nil {
		return fmt.Errorf("could not stage pending configuration: %w", err)
	}
	return nil
}
