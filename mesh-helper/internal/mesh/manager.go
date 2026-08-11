// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

type Manager struct {
	mu          sync.Mutex
	paths       Paths
	backend     Backend
	owner       uint32
	active      *Specification
	status      Status
	rename      func(string, string) error
	remove      func(string) error
	writeStatus func(string, Status) error
}

func NewManager(paths Paths, backend Backend) *Manager {
	return &Manager{
		paths:       paths,
		backend:     backend,
		owner:       0,
		status:      NewStatus(),
		rename:      os.Rename,
		remove:      os.Remove,
		writeStatus: WriteStatus,
	}
}

func (manager *Manager) Start() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := ensureDirectories(manager.paths, manager.owner); err != nil {
		return err
	}
	active, activeErr := readSpecification(manager.paths.Active, manager.owner)
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return errors.Join(activeErr, manager.publishUnavailable("configuration rejected"))
	}
	if activeErr == nil {
		manager.active = &active
	}

	if _, err := os.Lstat(manager.paths.Pending); err == nil {
		result := manager.applyPendingTransactionLocked()
		if result.err == nil {
			return nil
		}
		if result.recovered && !result.beforeBackend {
			return nil
		}
		if result.beforeBackend && manager.active != nil {
			name, restoreErr := manager.backend.Apply(*manager.active)
			if restoreErr != nil {
				return errors.Join(
					result.err,
					fmt.Errorf("pending configuration refused and active configuration unavailable: %w", restoreErr),
					manager.publishUnavailable("interface unavailable"),
				)
			}
			if err := manager.publishReady(*manager.active, name, result.reason); err != nil {
				return errors.Join(result.err, err)
			}
			if result.recovered {
				return nil
			}
			return result.err
		}
		return result.err
	}

	if manager.active == nil {
		return manager.publishUnavailable("unconfigured")
	}
	name, err := manager.backend.Apply(*manager.active)
	if err != nil {
		return errors.Join(err, manager.publishUnavailable("interface unavailable"))
	}
	return manager.publishReady(*manager.active, name, "")
}

func (manager *Manager) ApplyPending() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.applyPendingTransactionLocked().err
}

type pendingResult struct {
	err           error
	beforeBackend bool
	reason        string
	recovered     bool
}

func (manager *Manager) applyPendingTransactionLocked() pendingResult {
	candidate, err := readSpecification(manager.paths.Pending, manager.owner)
	if err != nil {
		publicationErr := manager.recordRefusal("configuration rejected")
		return pendingResult{
			err: errors.Join(err, publicationErr), beforeBackend: true,
			reason: "configuration rejected", recovered: publicationErr == nil,
		}
	}
	if manager.active != nil {
		activeDigest := manager.active.PublicDigest()
		candidateDigest := candidate.PublicDigest()
		switch {
		case candidate.Generation < manager.active.Generation:
			refusal := errors.New("generation rollback refused")
			if err := manager.remove(manager.paths.Pending); err != nil {
				return pendingResult{err: errors.Join(refusal, fmt.Errorf("could not remove refused pending configuration: %w", err)), beforeBackend: true, reason: "update refused"}
			}
			publicationErr := manager.recordRefusal("update refused")
			return pendingResult{err: errors.Join(refusal, publicationErr), beforeBackend: true, reason: "update refused", recovered: publicationErr == nil}
		case candidate.Generation == manager.active.Generation && candidateDigest != activeDigest:
			refusal := errors.New("generation reused with different configuration")
			if err := manager.remove(manager.paths.Pending); err != nil {
				return pendingResult{err: errors.Join(refusal, fmt.Errorf("could not remove refused pending configuration: %w", err)), beforeBackend: true, reason: "update refused"}
			}
			publicationErr := manager.recordRefusal("update refused")
			return pendingResult{err: errors.Join(refusal, publicationErr), beforeBackend: true, reason: "update refused", recovered: publicationErr == nil}
		case candidate.Generation == manager.active.Generation && candidateDigest == activeDigest:
			if err := manager.remove(manager.paths.Pending); err != nil {
				return pendingResult{err: fmt.Errorf("could not remove idempotent pending configuration: %w", err), beforeBackend: true}
			}
			name, err := manager.backend.Apply(*manager.active)
			if err != nil {
				return pendingResult{err: errors.Join(err, manager.publishUnavailable("interface unavailable"))}
			}
			return pendingResult{err: manager.publishReady(*manager.active, name, "")}
		}
	}

	candidateName, err := manager.backend.Apply(candidate)
	if err != nil {
		if manager.active != nil {
			if name, restoreErr := manager.backend.Apply(*manager.active); restoreErr == nil {
				if removeErr := manager.remove(manager.paths.Pending); removeErr != nil {
					return pendingResult{err: errors.Join(err, fmt.Errorf("active configuration restored but failed pending configuration remains: %w", removeErr))}
				}
				if publicationErr := manager.publishReady(*manager.active, name, "rollback restored"); publicationErr != nil {
					return pendingResult{err: errors.Join(err, publicationErr)}
				}
				return pendingResult{err: err, recovered: true}
			} else {
				return pendingResult{err: errors.Join(
					fmt.Errorf("candidate failed: %v; active restoration failed: %w", err, restoreErr),
					manager.publishUnavailable("interface unavailable"),
				)}
			}
		} else {
			return pendingResult{err: errors.Join(err, manager.publishUnavailable("interface unavailable"))}
		}
	}
	if err := manager.rename(manager.paths.Pending, manager.paths.Active); err != nil {
		if manager.active != nil {
			if name, restoreErr := manager.backend.Apply(*manager.active); restoreErr == nil {
				if removeErr := manager.remove(manager.paths.Pending); removeErr != nil {
					return pendingResult{err: errors.Join(err, fmt.Errorf("active configuration restored but non-durable pending configuration remains: %w", removeErr))}
				}
				if publicationErr := manager.publishReady(*manager.active, name, "rollback restored"); publicationErr != nil {
					return pendingResult{err: errors.Join(err, publicationErr)}
				}
				return pendingResult{err: err, recovered: true}
			} else {
				return pendingResult{err: errors.Join(
					fmt.Errorf("promotion failed: %v; active restoration failed: %w", err, restoreErr),
					manager.publishUnavailable("interface unavailable"),
				)}
			}
		} else {
			return pendingResult{err: errors.Join(err, manager.backend.Close(), manager.publishUnavailable("configuration rejected"))}
		}
	}
	manager.active = &candidate
	if directory, err := os.Open(manager.paths.Private); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return pendingResult{err: manager.publishReady(candidate, candidateName, "")}
}

func (manager *Manager) recordRefusal(reason string) error {
	if manager.status.Ready {
		return manager.publish(manager.status.WithLastError(reason))
	}
	if manager.active == nil || manager.status.Error == "" {
		return manager.publishUnavailable(reason)
	}
	return nil
}

func (manager *Manager) publishReady(spec Specification, name, reason string) error {
	status := ReadyStatus(spec, name)
	if reason != "" {
		status = status.WithLastError(reason)
	}
	return manager.publish(status)
}

func (manager *Manager) publishUnavailable(reason string) error {
	return manager.publish(UnavailableStatus(manager.active, reason))
}

func (manager *Manager) publish(status Status) error {
	if err := manager.writeStatus(manager.paths.Status, status); err != nil {
		return fmt.Errorf("could not publish mesh status: %w", err)
	}
	manager.status = status
	return nil
}

func (manager *Manager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	err := manager.backend.Close()
	return errors.Join(err, manager.publishUnavailable("stopped"))
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
