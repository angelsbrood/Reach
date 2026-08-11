// SPDX-License-Identifier: MIT

package mesh

import (
	"encoding/json"
	"os"
	"time"
)

type Status struct {
	HelperVersion string `json:"helperVersion"`
	PID           int    `json:"pid"`
	Generation    uint64 `json:"generation"`
	PublicDigest  string `json:"publicDigest"`
	InterfaceName string `json:"interfaceName"`
	Ready         bool   `json:"ready"`
	PeerCount     int    `json:"peerCount"`
	UpdatedAt     string `json:"updatedAt"`
	Error         string `json:"error,omitempty"`
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
	case "unconfigured", "configuration rejected", "update refused", "interface unavailable", "rollback restored", "stopped":
		return reason
	default:
		return "mesh owner unavailable"
	}
}
