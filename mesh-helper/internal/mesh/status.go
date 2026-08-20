// SPDX-License-Identifier: MIT

package mesh

import (
	"encoding/json"
	"os"
	"time"
)

type Status struct {
	HelperVersion string          `json:"helperVersion"`
	PID           int             `json:"pid"`
	Generation    uint64          `json:"generation"`
	PublicDigest  string          `json:"publicDigest"`
	InterfaceName string          `json:"interfaceName"`
	Ready         bool            `json:"ready"`
	PeerCount     int             `json:"peerCount"`
	Direct        ComponentStatus `json:"direct"`
	Relay         RelayStatus     `json:"relay"`
	UpdatedAt     string          `json:"updatedAt"`
	Error         string          `json:"error,omitempty"`
}

type ComponentStatus struct {
	Ready     bool   `json:"ready"`
	Digest    string `json:"digest"`
	PeerCount int    `json:"peerCount"`
}

type RelayStatus struct {
	Configured   bool   `json:"configured"`
	Ready        bool   `json:"ready"`
	Digest       string `json:"digest"`
	Address      string `json:"address"`
	RouteCount   int    `json:"routeCount"`
	HubPeerCount int    `json:"hubPeerCount"`
}

func NewStatus() Status {
	return Status{
		HelperVersion: HelperVersion,
		PID:           os.Getpid(),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
}

func ReadyStatus(spec Specification, interfaceName string) Status {
	status := NewStatus()
	status.Generation = spec.Generation
	status.PublicDigest = spec.PublicDigest()
	status.InterfaceName = interfaceName
	status.Ready = true
	status.PeerCount = len(spec.Peers)
	status.Direct = ComponentStatus{Ready: true, Digest: spec.DirectDigest(), PeerCount: len(spec.Peers)}
	status.Relay = RelayStatus{Ready: true}
	if spec.Relay != nil {
		status.Relay.Configured = true
		status.Relay.Digest = spec.RelayDigest()
		status.Relay.Address = spec.Relay.Address
		status.Relay.RouteCount = len(spec.Relay.Routes)
		status.Relay.HubPeerCount = 1
	}
	return status
}

// UpdatingStatus closes observable relay readiness before a live authority
// transaction starts. The existing direct component remains truthful and
// usable; overall readiness stays false until the peer manifest, relay path,
// and durable active specification all agree again.
func UpdatingStatus(spec Specification, interfaceName string) Status {
	status := ReadyStatus(spec, interfaceName)
	status.Ready = false
	status.Relay.Ready = false
	status.Error = "updating"
	return status
}

func (status Status) WithLastError(reason string) Status {
	status.Error = boundedReason(reason)
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return status
}

func UnavailableStatus(active *Specification, reason string) Status {
	status := NewStatus()
	if active != nil {
		status.Generation = active.Generation
		status.PublicDigest = active.PublicDigest()
		status.PeerCount = len(active.Peers)
		status.Direct = ComponentStatus{Digest: active.DirectDigest(), PeerCount: len(active.Peers)}
		if active.Relay != nil {
			status.Relay.Configured = true
			status.Relay.Digest = active.RelayDigest()
			status.Relay.Address = active.Relay.Address
			status.Relay.RouteCount = len(active.Relay.Routes)
			status.Relay.HubPeerCount = 1
		}
	}
	status.Error = boundedReason(reason)
	return status
}

func WriteStatus(path string, status Status) error {
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return WriteRootFileAtomically(path, data, 0o644)
}

func boundedReason(reason string) string {
	switch reason {
	case "unconfigured", "configuration rejected", "update refused", "interface unavailable", "rollback restored", "stopped", "updating":
		return reason
	default:
		return "mesh owner unavailable"
	}
}
