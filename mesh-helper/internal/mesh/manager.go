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
	claim       func(string, string) error
	rename      func(string, string) error
	remove      func(string) error
	syncClaim   func(string) error
	syncDir     func(string) error
	writeStatus func(string, Status) error
}

var errRequestedAuthorityStillStaged = errors.New("requested authority remains staged")

type authorityIdentity struct {
	generation uint64
	digest     string
}

func NewManager(paths Paths, backend Backend) *Manager {
	return &Manager{
		paths:       paths,
		backend:     backend,
		owner:       0,
		status:      NewStatus(),
		claim:       claimPendingFile,
		rename:      os.Rename,
		remove:      os.Remove,
		syncClaim:   syncDirectory,
		syncDir:     syncDirectory,
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

	var result pendingResult
	hasTransaction := false
	if _, err := os.Lstat(manager.paths.Claimed); err == nil {
		result = manager.applyClaimedTransactionLocked()
		hasTransaction = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, manager.publishUnavailable("configuration rejected"))
	} else if _, err := os.Lstat(manager.paths.Pending); err == nil {
		result = manager.applyPendingTransactionLocked()
		hasTransaction = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, manager.publishUnavailable("configuration rejected"))
	}
	if hasTransaction {
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

func (manager *Manager) ApplyExpected(generation uint64, digest string) (authorityIdentity, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	expected := authorityIdentity{generation: generation, digest: digest}
	// At most one older claimed transaction can coexist with the pending
	// authority staged by this caller. Finish that claim first, then continue
	// through the caller's pending transaction before acknowledging it.
	for range 2 {
		result := manager.applyPendingTransactionLocked()
		if result.err != nil {
			if staged, inspectionErr := manager.hasStagedAuthorityLocked(expected); inspectionErr != nil {
				return manager.activeAuthorityLocked(), errors.Join(result.err, inspectionErr)
			} else if staged {
				return manager.activeAuthorityLocked(), errors.Join(errRequestedAuthorityStillStaged, result.err)
			}
			return manager.activeAuthorityLocked(), result.err
		}

		applied := manager.activeAuthorityLocked()
		if applied == expected {
			return applied, nil
		}
		staged, err := manager.hasStagedAuthorityLocked(expected)
		if err != nil {
			return applied, err
		}
		if !staged {
			return applied, fmt.Errorf(
				"applied generation %d does not match requested generation %d",
				applied.generation,
				expected.generation,
			)
		}
	}

	return manager.activeAuthorityLocked(), errors.New("requested authority remains staged after prior claim")
}

func (manager *Manager) activeAuthorityLocked() authorityIdentity {
	if manager.active == nil {
		return authorityIdentity{}
	}
	return authorityIdentity{
		generation: manager.active.Generation,
		digest:     manager.active.PublicDigest(),
	}
}

func (manager *Manager) hasStagedAuthorityLocked(expected authorityIdentity) (bool, error) {
	for _, path := range []string{manager.paths.Pending, manager.paths.Claimed} {
		spec, err := readSpecification(path, manager.owner)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("could not inspect staged authority: %w", err)
		}
		if spec.Generation == expected.generation && spec.PublicDigest() == expected.digest {
			return true, nil
		}
	}
	return false, nil
}

type pendingResult struct {
	err           error
	beforeBackend bool
	reason        string
	recovered     bool
}

func (manager *Manager) applyPendingTransactionLocked() pendingResult {
	if _, err := os.Lstat(manager.paths.Claimed); err == nil {
		return manager.applyClaimedTransactionLocked()
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingResult{err: err, beforeBackend: true}
	}
	if err := manager.claim(manager.paths.Pending, manager.paths.Claimed); err != nil {
		return pendingResult{err: fmt.Errorf("could not claim pending configuration: %w", err), beforeBackend: true}
	}
	if err := manager.syncClaim(manager.paths.Private); err != nil {
		return pendingResult{err: fmt.Errorf("could not make claimed configuration durable: %w", err), beforeBackend: true}
	}
	return manager.applyClaimedTransactionLocked()
}

func (manager *Manager) applyClaimedTransactionLocked() pendingResult {
	candidate, err := readSpecification(manager.paths.Claimed, manager.owner)
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
			if err := manager.remove(manager.paths.Claimed); err != nil {
				return pendingResult{err: errors.Join(refusal, fmt.Errorf("could not remove refused claimed configuration: %w", err)), beforeBackend: true, reason: "update refused"}
			}
			publicationErr := manager.recordRefusal("update refused")
			return pendingResult{err: errors.Join(refusal, publicationErr), beforeBackend: true, reason: "update refused", recovered: publicationErr == nil}
		case candidate.Generation == manager.active.Generation && candidateDigest != activeDigest:
			refusal := errors.New("generation reused with different configuration")
			if err := manager.remove(manager.paths.Claimed); err != nil {
				return pendingResult{err: errors.Join(refusal, fmt.Errorf("could not remove refused claimed configuration: %w", err)), beforeBackend: true, reason: "update refused"}
			}
			publicationErr := manager.recordRefusal("update refused")
			return pendingResult{err: errors.Join(refusal, publicationErr), beforeBackend: true, reason: "update refused", recovered: publicationErr == nil}
		case candidate.Generation == manager.active.Generation && candidateDigest == activeDigest:
			if err := manager.remove(manager.paths.Claimed); err != nil {
				return pendingResult{err: fmt.Errorf("could not remove idempotent claimed configuration: %w", err), beforeBackend: true}
			}
			if manager.status.Direct.Ready {
				if err := manager.publish(UpdatingStatus(*manager.active, manager.status.InterfaceName)); err != nil {
					return pendingResult{err: err, beforeBackend: true}
				}
			}
			name, err := manager.backend.Apply(*manager.active)
			if err != nil {
				return pendingResult{err: errors.Join(err, manager.publishUnavailable("interface unavailable"))}
			}
			return pendingResult{err: manager.publishReady(*manager.active, name, "")}
		}
	}
	if manager.active != nil && manager.status.Direct.Ready {
		if err := manager.publish(UpdatingStatus(*manager.active, manager.status.InterfaceName)); err != nil {
			return pendingResult{err: err, beforeBackend: true}
		}
	}

	candidateName, err := manager.backend.Apply(candidate)
	if err != nil {
		if manager.active != nil {
			if name, restoreErr := manager.backend.Apply(*manager.active); restoreErr == nil {
				if removeErr := manager.remove(manager.paths.Claimed); removeErr != nil {
					return pendingResult{err: errors.Join(err, fmt.Errorf("active configuration restored but failed claimed configuration remains: %w", removeErr))}
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
	if err := manager.rename(manager.paths.Claimed, manager.paths.Active); err != nil {
		if manager.active != nil {
			if name, restoreErr := manager.backend.Apply(*manager.active); restoreErr == nil {
				if removeErr := manager.remove(manager.paths.Claimed); removeErr != nil {
					return pendingResult{err: errors.Join(err, fmt.Errorf("active configuration restored but non-durable claimed configuration remains: %w", removeErr))}
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
	if err := manager.syncDir(manager.paths.Private); err != nil {
		return manager.restoreAfterUndurablePromotion(candidate, err)
	}
	manager.active = &candidate
	return pendingResult{err: manager.publishReady(candidate, candidateName, "")}
}

func (manager *Manager) restoreAfterUndurablePromotion(candidate Specification, promotionErr error) pendingResult {
	candidateData, encodeCandidateErr := EncodeSpecification(candidate)
	var claimedErr error
	if encodeCandidateErr == nil {
		claimedErr = WriteRootFileAtomically(manager.paths.Claimed, candidateData, 0o600)
	} else {
		claimedErr = encodeCandidateErr
	}
	if manager.active != nil {
		activeData, encodeActiveErr := EncodeSpecification(*manager.active)
		var activeErr error
		if encodeActiveErr == nil {
			activeErr = WriteRootFileAtomically(manager.paths.Active, activeData, 0o600)
		} else {
			activeErr = encodeActiveErr
		}
		if activeErr == nil {
			if name, restoreErr := manager.backend.Apply(*manager.active); restoreErr == nil {
				publicationErr := manager.publishReady(*manager.active, name, "rollback restored")
				return pendingResult{
					err:       errors.Join(promotionErr, claimedErr, publicationErr),
					recovered: claimedErr == nil && publicationErr == nil,
				}
			} else {
				return pendingResult{err: errors.Join(
					promotionErr, claimedErr,
					fmt.Errorf("undurable candidate active restoration failed: %w", restoreErr),
					manager.publishUnavailable("interface unavailable"),
				)}
			}
		}
		return pendingResult{err: errors.Join(
			promotionErr, claimedErr,
			fmt.Errorf("could not restore durable active configuration: %w", activeErr),
			manager.publishUnavailable("interface unavailable"),
		)}
	}

	if claimedErr == nil {
		removeErr := manager.remove(manager.paths.Active)
		syncErr := manager.syncDir(manager.paths.Private)
		closeErr := manager.backend.Close()
		return pendingResult{err: errors.Join(
			promotionErr, removeErr, syncErr, closeErr,
			manager.publishUnavailable("configuration rejected"),
		)}
	}
	return pendingResult{err: errors.Join(
		promotionErr,
		fmt.Errorf("could not preserve undurable candidate: %w", claimedErr),
		manager.backend.Close(),
		manager.publishUnavailable("configuration rejected"),
	)}
}

func claimPendingFile(source, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("claimed configuration already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (manager *Manager) recordRefusal(reason string) error {
	if manager.status.Ready {
		return manager.publish(manager.status.WithLastError(reason))
	}
	if manager.status.Direct.Ready {
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
	if claimed, err := readSpecification(paths.Claimed, 0); err == nil {
		if spec.Generation < claimed.Generation || (spec.Generation == claimed.Generation && spec.PublicDigest() != claimed.PublicDigest()) {
			return errors.New("newer generation is already being applied")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not inspect claimed configuration: %w", err)
	}
	if err := WriteRootFileAtomically(paths.Pending, data, 0o600); err != nil {
		return fmt.Errorf("could not stage pending configuration: %w", err)
	}
	return nil
}
