// Package status writes one bounded, content-free lifecycle status document.
package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"reach.dev/exo-runtime/internal/authority"
)

type Document struct {
	SchemaVersion int      `json:"schema_version"`
	Role          string   `json:"role"`
	State         string   `json:"state"`
	Reason        string   `json:"reason,omitempty"`
	Epoch         string   `json:"epoch,omitempty"`
	ProviderPID   int      `json:"provider_pid,omitempty"`
	StateSHA256   string   `json:"provider_state_sha256,omitempty"`
	NodeIDs       []string `json:"node_ids,omitempty"`
	RunnerIDs     []string `json:"runner_ids,omitempty"`
	InstanceID    string   `json:"instance_id,omitempty"`
	UpdatedUTC    string   `json:"updated_utc"`
}

type Writer struct{ mu sync.Mutex }

func (w *Writer) Write(document Document) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	document.SchemaVersion = authority.SchemaVersion
	document.UpdatedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if len(document.Reason) > 256 {
		document.Reason = document.Reason[:256]
	}
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(authority.RuntimeRoot, 0750); err != nil {
		return err
	}
	temporary := filepath.Join(authority.RuntimeRoot, ".status.json.tmp")
	final := filepath.Join(authority.RuntimeRoot, "status.json")
	if err := os.WriteFile(temporary, data, 0640); err != nil {
		return err
	}
	return os.Rename(temporary, final)
}
