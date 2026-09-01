// Package neighbor owns the one exact static peer-neighbor entry needed by the
// disposable Lima VZ network. It refuses to adopt or delete unowned entries.
package neighbor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/linklocal"
)

const markerPath = "/run/reach-exo-peer-neighbor.json"

type record struct {
	SchemaVersion int    `json:"schema_version"`
	Interface     string `json:"interface"`
	Address       string `json:"address"`
	MAC           string `json:"mac"`
}

type kernelNeighbor struct {
	Destination string   `json:"dst"`
	Device      string   `json:"dev"`
	LinkAddress string   `json:"lladdr"`
	State       []string `json:"state"`
}

var runIP = func(arguments ...string) ([]byte, error) {
	command := exec.Command("/usr/sbin/ip", arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("ip %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Apply installs one static entry only when no unowned entry exists. Recording
// intent before mutation makes interruption recoverable without adopting
// unrelated kernel state.
func Apply(value config.Node) error {
	if os.Geteuid() != 0 {
		return errors.New("peer-neighbor apply requires root")
	}
	wanted, err := wantedRecord(value)
	if err != nil {
		return err
	}
	owned, markerErr := readMarker()
	if markerErr == nil && owned != wanted {
		return errors.New("peer-neighbor ownership marker does not match configuration")
	}
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return markerErr
	}
	existing, err := inspect(wanted)
	if err != nil {
		return err
	}
	if markerErr == nil {
		if len(existing) == 1 && sameNeighbor(existing[0], wanted) {
			return nil
		}
		if len(existing) != 0 {
			return errors.New("owned peer-neighbor entry has drifted")
		}
	} else {
		if len(existing) != 0 {
			cleared, clearErr := clearFailedResolution(existing, wanted)
			if clearErr != nil {
				return clearErr
			}
			if !cleared {
				return errors.New("refusing to adopt a pre-existing peer-neighbor entry")
			}
		}
		data, err := json.Marshal(wanted)
		if err != nil {
			return err
		}
		if err := writeMarker(append(data, '\n')); err != nil {
			return fmt.Errorf("record peer-neighbor ownership: %w", err)
		}
	}
	if _, err := runIP("-6", "neighbor", "add", wanted.Address, "lladdr", wanted.MAC, "nud", "permanent", "dev", wanted.Interface); err != nil {
		remaining, inspectErr := inspect(wanted)
		if inspectErr == nil && len(remaining) == 0 {
			_ = os.Remove(markerPath)
		}
		return err
	}
	existing, err = inspect(wanted)
	if err != nil || len(existing) != 1 || !sameNeighbor(existing[0], wanted) {
		return errors.New("peer-neighbor entry did not reach exact permanent state")
	}
	return nil
}

// clearFailedResolution removes only the MAC-less FAILED cache object Linux
// may recreate after the package deletes its owned permanent neighbor. This is
// not adoption: an addressed, reachable, incomplete, or otherwise ambiguous
// tuple still refuses. The exact authenticated peer tuple is then created and
// owned through the normal marker-before-mutation path.
func clearFailedResolution(existing []kernelNeighbor, wanted record) (bool, error) {
	if len(existing) != 1 || existing[0].Destination != wanted.Address || existing[0].Device != wanted.Interface || existing[0].LinkAddress != "" || len(existing[0].State) != 1 || !strings.EqualFold(existing[0].State[0], "failed") {
		return false, nil
	}
	if _, err := runIP("-6", "neighbor", "del", wanted.Address, "dev", wanted.Interface); err != nil {
		return false, fmt.Errorf("delete failed peer-neighbor resolution: %w", err)
	}
	remaining, err := inspect(wanted)
	if err != nil {
		return false, err
	}
	if len(remaining) != 0 {
		return false, errors.New("failed peer-neighbor resolution survived deletion")
	}
	return true, nil
}

// Remove deletes only the exact entry named by the root-owned marker and the
// still-authenticated node configuration.
func Remove(value config.Node) error {
	if os.Geteuid() != 0 {
		return errors.New("peer-neighbor remove requires root")
	}
	wanted, err := wantedRecord(value)
	if err != nil {
		return err
	}
	owned, err := readMarker()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if owned != wanted {
		return errors.New("peer-neighbor ownership marker does not match configuration")
	}
	existing, err := inspect(wanted)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return os.Remove(markerPath)
	}
	if len(existing) != 1 || !sameNeighbor(existing[0], wanted) {
		return errors.New("owned peer-neighbor entry has drifted")
	}
	if _, err := runIP("-6", "neighbor", "del", wanted.Address, "lladdr", wanted.MAC, "nud", "permanent", "dev", wanted.Interface); err != nil {
		return err
	}
	remaining, err := inspect(wanted)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("peer-neighbor entry survived deletion")
	}
	return os.Remove(markerPath)
}

func wantedRecord(value config.Node) (record, error) {
	address, err := linklocal.FromMAC(value.PeerMAC)
	if err != nil {
		return record{}, err
	}
	return record{SchemaVersion: 1, Interface: value.NetworkInterface, Address: address, MAC: value.PeerMAC}, nil
}

func inspect(wanted record) ([]kernelNeighbor, error) {
	// Do not pre-filter by device: iproute2 omits the dev field from its JSON
	// object when dev is already a selector, which would weaken tuple proof.
	data, err := runIP("-j", "-6", "neighbor", "show", "to", wanted.Address)
	if err != nil {
		return nil, err
	}
	var values []kernelNeighbor
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&values); err != nil {
		return nil, fmt.Errorf("decode peer-neighbor state: %w", err)
	}
	if len(values) > 1 {
		return nil, errors.New("peer-neighbor query returned more than one entry")
	}
	return values, nil
}

func sameNeighbor(value kernelNeighbor, wanted record) bool {
	if value.Destination != wanted.Address || value.Device != wanted.Interface || value.LinkAddress != wanted.MAC || len(value.State) != 1 {
		return false
	}
	return strings.EqualFold(value.State[0], "permanent")
}

func writeMarker(data []byte) error {
	file, err := os.OpenFile(markerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(markerPath)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(markerPath)
		return err
	}
	return file.Close()
}

func readMarker() (record, error) {
	info, err := os.Lstat(markerPath)
	if err != nil {
		return record{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return record{}, errors.New("peer-neighbor ownership marker tuple is invalid")
	}
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return record{}, err
	}
	var value record
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return record{}, err
	}
	if value.SchemaVersion != 1 {
		return record{}, errors.New("peer-neighbor ownership marker schema is invalid")
	}
	return value, nil
}
