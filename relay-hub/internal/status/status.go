// SPDX-License-Identifier: MIT

package status

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"systems.reach/relay-hub/internal/backend"
	"systems.reach/relay-hub/internal/config"
)

const HelperVersion = "1"

type Peer struct {
	Role                string `json:"role"`
	Ordinal             int    `json:"ordinal"`
	HandshakeAgeSeconds *int64 `json:"handshakeAgeSeconds,omitempty"`
	ReceiveBytes        uint64 `json:"receiveBytes"`
	TransmitBytes       uint64 `json:"transmitBytes"`
}

type Status struct {
	SchemaVersion int    `json:"schemaVersion"`
	HelperVersion string `json:"helperVersion"`
	PID           int    `json:"pid"`
	Generation    uint64 `json:"generation"`
	PublicDigest  string `json:"publicDigest"`
	Ready         bool   `json:"ready"`
	PeerCount     int    `json:"peerCount"`
	UpdatedAt     string `json:"updatedAt"`
	Error         string `json:"error,omitempty"`
	Peers         []Peer `json:"peers,omitempty"`
}

func Build(spec *config.Specification, ready bool, reason string, runtime map[string]backend.PeerRuntime, now time.Time) Status {
	s := Status{SchemaVersion: 1, HelperVersion: HelperVersion, PID: os.Getpid(), Ready: ready, UpdatedAt: now.UTC().Format(time.RFC3339Nano), Error: bounded(reason)}
	if spec == nil {
		return s
	}
	s.Generation = spec.Generation
	s.PublicDigest = spec.PublicDigest()
	s.PeerCount = 1 + len(spec.Devices)
	peers := spec.Peers()
	s.Peers = make([]Peer, 0, len(peers))
	for i, p := range peers {
		role := "device"
		ordinal := i + 1
		if i == 0 {
			role = "host"
			ordinal = 1
		} else {
			address := p.Address
			prefix, _ := configAddress(address)
			ordinal = int(prefix)
		}
		ps := Peer{Role: role, Ordinal: ordinal}
		if r, ok := runtime[p.PublicKey]; ok {
			ps.ReceiveBytes = r.ReceiveBytes
			ps.TransmitBytes = r.TransmitBytes
			if !r.LastHandshake.IsZero() {
				age := int64(now.Sub(r.LastHandshake).Seconds())
				if age < 0 {
					age = 0
				}
				ps.HandshakeAgeSeconds = &age
			}
		}
		s.Peers = append(s.Peers, ps)
	}
	return s
}

func configAddress(value string) (byte, error) {
	// Strict config validation already established the canonical /32. Keeping
	// address parsing local avoids putting the address itself in status.
	var a, b, c, d int
	if _, err := fmtSscanf(value, "%d.%d.%d.%d/32", &a, &b, &c, &d); err != nil || d < 0 || d > 255 {
		return 0, errors.New("invalid peer ordinal")
	}
	return byte(d), nil
}

var fmtSscanf = func(str, format string, a ...any) (int, error) { return fmt.Sscanf(str, format, a...) }

func bounded(reason string) string {
	switch reason {
	case "", "unconfigured", "configuration rejected", "update refused", "backend unavailable", "rollback restored", "stopped", "status unavailable":
		return reason
	default:
		return "relay hub unavailable"
	}
}

func Write(path string, value Status) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".status.tmp-*")
	if err != nil {
		return err
	}
	if err = temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return err
	}
	name := temp.Name()
	ok := false
	defer func() {
		_ = temp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
