// SPDX-License-Identifier: MIT

package manager

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"systems.reach/relay-hub/internal/backend"
	"systems.reach/relay-hub/internal/config"
	"systems.reach/relay-hub/internal/router"
	statuspkg "systems.reach/relay-hub/internal/status"
)

type Paths struct {
	Active  string
	Pending string
	Status  string
}
type StatusWriter func(string, statuspkg.Status) error

type transactionHooks struct {
	afterReadyFalse      func()
	afterQuiesce         func()
	afterPeerApply       func()
	afterPeerVerify      func()
	afterPromotion       func()
	afterSnapshotInstall func()
	afterReopen          func()
}

type Manager struct {
	mu          sync.Mutex
	paths       Paths
	owner       *uint32
	routes      config.RouteInventory
	backend     backend.Backend
	router      *router.Router
	active      *config.Specification
	writeStatus StatusWriter
	now         func() time.Time
	hooks       transactionHooks
	writeSpec   func(string, []byte, os.FileMode) error
	promoteSpec func(string, string) error
	removeSpec  func(string) error
}

func New(paths Paths, owner *uint32, routes config.RouteInventory, b backend.Backend, r *router.Router) *Manager {
	return &Manager{
		paths: paths, owner: owner, routes: routes, backend: b, router: r,
		writeStatus: statuspkg.Write, now: time.Now,
		writeSpec: writeAtomically, promoteSpec: promote, removeSpec: removeAndSync,
	}
}

func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureDirectories(); err != nil {
		return err
	}
	// Pending bytes are never authority. A process crash may leave them behind,
	// but startup restores only the last durably promoted active specification.
	if err := m.removeSpec(m.paths.Pending); err != nil {
		return errors.Join(err, m.publish(nil, false, "configuration rejected"))
	}
	activeData, activeErr := config.ReadSecureFile(m.paths.Active, config.FileRule{Owner: m.owner, Mode: 0o600, Limit: config.MaximumBytes})
	if activeErr == nil {
		spec, err := config.Decode(activeData, m.routes)
		if err != nil {
			return errors.Join(err, m.publish(nil, false, "configuration rejected"))
		}
		if err = m.backend.ConfigureInitial(spec); err != nil {
			return errors.Join(err, m.publish(&spec, false, "backend unavailable"))
		}
		snapshot, _ := router.SnapshotFor(spec)
		if err = m.router.Install(snapshot); err != nil {
			return err
		}
		if !m.router.Verify(snapshot) {
			return errors.New("router snapshot verification failed")
		}
		if err = m.router.Reopen(); err != nil {
			return err
		}
		m.active = &spec
		if err = m.publish(&spec, true, ""); err != nil {
			return err
		}
	} else if !errors.Is(activeErr, os.ErrNotExist) {
		return errors.Join(activeErr, m.publish(nil, false, "configuration rejected"))
	}
	if m.active == nil {
		return m.publish(nil, false, "unconfigured")
	}
	return nil
}

func (m *Manager) Apply(data []byte) error {
	spec, err := config.Decode(data, m.routes)
	if err != nil {
		return err
	}
	canonical, err := spec.CanonicalJSON()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(canonical, spec)
}

func (m *Manager) applyLocked(data []byte, candidate config.Specification) error {
	if m.active == nil {
		if candidate.Generation != 1 {
			return errors.New("initial generation must equal 1")
		}
		if err := m.writeSpec(m.paths.Pending, data, 0o600); err != nil {
			return err
		}
		if err := m.publish(&candidate, false, ""); err != nil {
			return errors.Join(err, m.removeSpec(m.paths.Pending))
		}
		if err := m.backend.ConfigureInitial(candidate); err != nil {
			return errors.Join(err, m.removeSpec(m.paths.Pending), m.publish(&candidate, false, "backend unavailable"))
		}
		snapshot, _ := router.SnapshotFor(candidate)
		if err := m.router.Install(snapshot); err != nil {
			return errors.Join(err, m.backend.Close(), m.removeSpec(m.paths.Pending), m.publish(&candidate, false, "configuration rejected"))
		}
		if !m.router.Verify(snapshot) {
			return errors.Join(errors.New("router snapshot verification failed"), m.backend.Close(), m.removeSpec(m.paths.Pending), m.publish(&candidate, false, "configuration rejected"))
		}
		if err := m.promoteSpec(m.paths.Pending, m.paths.Active); err != nil {
			return errors.Join(err, m.backend.Close(), m.removeSpec(m.paths.Pending), m.publish(&candidate, false, "configuration rejected"))
		}
		m.active = &candidate
		if err := m.router.Reopen(); err != nil {
			return errors.Join(err, m.publish(&candidate, false, "backend unavailable"))
		}
		return m.publish(&candidate, true, "")
	}
	previous := *m.active
	if candidate.Generation < previous.Generation {
		return errors.New("generation rollback refused")
	}
	if candidate.Generation == previous.Generation {
		if candidate.PublicDigest() != previous.PublicDigest() {
			return errors.New("generation reused with different configuration")
		}
		manifest, manifestErr := m.backend.Manifest()
		snapshot, snapshotErr := router.SnapshotFor(previous)
		authorityErr := manifestErr
		if authorityErr == nil && !manifestMatches(manifest, previous.Peers()) {
			authorityErr = errors.New("active peer manifest mismatch")
		}
		if authorityErr == nil && snapshotErr != nil {
			authorityErr = snapshotErr
		}
		if authorityErr == nil && !m.router.Ready(snapshot) {
			authorityErr = errors.New("active router authority mismatch")
		}
		if authorityErr != nil {
			return errors.Join(authorityErr, m.publish(&previous, false, "backend unavailable"))
		}
		if err := m.removeSpec(m.paths.Pending); err != nil {
			return err
		}
		return m.publish(&previous, true, "")
	}
	if !previous.SameInstance(candidate) {
		return errors.New("frozen hub instance field changed")
	}
	candidateSnapshot, err := router.SnapshotFor(candidate)
	if err != nil {
		return err
	}
	previousSnapshot, _ := router.SnapshotFor(previous)
	if err = m.writeSpec(m.paths.Pending, data, 0o600); err != nil {
		return err
	}
	if err = m.publish(&previous, false, ""); err != nil {
		return errors.Join(err, m.removeSpec(m.paths.Pending))
	}
	call(m.hooks.afterReadyFalse)
	if err = m.router.Quiesce(); err != nil {
		return errors.Join(err, m.restorePriorRouting(previousSnapshot, previous, ""))
	}
	call(m.hooks.afterQuiesce)
	if err = m.backend.ApplyManifest(candidate.Peers()); err != nil {
		return m.rollback(previous, previousSnapshot, err)
	}
	call(m.hooks.afterPeerApply)
	manifest, err := m.backend.Manifest()
	if err != nil || !manifestMatches(manifest, candidate.Peers()) {
		if err == nil {
			err = errors.New("candidate manifest mismatch")
		}
		return m.rollback(previous, previousSnapshot, err)
	}
	call(m.hooks.afterPeerVerify)
	if err = m.promoteSpec(m.paths.Pending, m.paths.Active); err != nil {
		return m.rollback(previous, previousSnapshot, err)
	}
	call(m.hooks.afterPromotion)
	if err = m.router.Install(candidateSnapshot); err != nil {
		return m.rollbackAfterPromotion(previous, previousSnapshot, err)
	}
	call(m.hooks.afterSnapshotInstall)
	if !m.router.Verify(candidateSnapshot) {
		return m.rollbackAfterPromotion(previous, previousSnapshot, errors.New("router snapshot verification failed"))
	}
	if err = m.router.Reopen(); err != nil {
		return m.rollbackAfterPromotion(previous, previousSnapshot, err)
	}
	call(m.hooks.afterReopen)
	m.active = &candidate
	// A ready publication failure does not roll back durable authority.
	return m.publish(&candidate, true, "")
}

func (m *Manager) rollback(previous config.Specification, snapshot router.Snapshot, cause error) error {
	restoreErr := m.backend.ApplyManifest(previous.Peers())
	if restoreErr == nil {
		manifest, err := m.backend.Manifest()
		if err != nil || !manifestMatches(manifest, previous.Peers()) {
			if err == nil {
				err = errors.New("rollback manifest mismatch")
			}
			restoreErr = err
		}
	}
	if restoreErr == nil {
		restoreErr = m.writeSpec(m.paths.Active, mustJSON(previous), 0o600)
	}
	if restoreErr == nil {
		restoreErr = m.removeSpec(m.paths.Pending)
	}
	if restoreErr == nil {
		restoreErr = m.restorePriorRouting(snapshot, previous, "rollback restored")
	}
	if restoreErr != nil {
		_ = m.publish(&previous, false, "backend unavailable")
		return errors.Join(cause, fmt.Errorf("rollback failed: %w", restoreErr))
	}
	return cause
}

func (m *Manager) rollbackAfterPromotion(previous config.Specification, snapshot router.Snapshot, cause error) error {
	return m.rollback(previous, snapshot, cause)
}
func (m *Manager) restorePriorRouting(snapshot router.Snapshot, previous config.Specification, reason string) error {
	if err := m.router.Install(snapshot); err != nil {
		return err
	}
	if err := m.router.Reopen(); err != nil {
		return err
	}
	m.active = &previous
	return m.publish(&previous, true, reason)
}

func (m *Manager) publish(spec *config.Specification, ready bool, reason string) error {
	runtime := map[string]backend.PeerRuntime{}
	if spec != nil {
		if value, err := m.backend.Runtime(); err == nil {
			runtime = value
		}
	}
	return m.writeStatus(m.paths.Status, statuspkg.Build(spec, ready, reason, runtime, m.now()))
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := errors.Join(m.backend.Close(), m.router.Close())
	return errors.Join(err, m.publish(m.active, false, "stopped"))
}

func (m *Manager) ensureDirectories() error {
	for _, dir := range []string{filepath.Dir(m.paths.Active), filepath.Dir(m.paths.Status)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
func manifestMatches(actual backend.Manifest, peers []config.Peer) bool {
	if len(actual) != len(peers) {
		return false
	}
	for _, p := range peers {
		if actual[p.PublicKey] != p.Address {
			return false
		}
	}
	return true
}
func mustJSON(spec config.Specification) []byte {
	data, err := spec.CanonicalJSON()
	if err != nil {
		panic(err)
	}
	return data
}

func call(hook func()) {
	if hook != nil {
		hook()
	}
}

func writeAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err = f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	ok = true
	return nil
}
func promote(pending, active string) error {
	if err := os.Rename(pending, active); err != nil {
		return err
	}
	f, err := os.Open(active)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(active))
}
func removeAndSync(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
