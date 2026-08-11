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

func (status Status) WithError(reason string) Status {
	status.Ready = false
	status.Error = boundedReason(reason)
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
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
