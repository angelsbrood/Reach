// SPDX-License-Identifier: MIT

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/crypto/curve25519"
)

const (
	Version        = 1
	MTU            = 1280
	DirectPrefix   = "10.86.0.0/24"
	MaximumBytes   = 1024 * 1024
	MaximumDevices = 253
)

type Specification struct {
	Version     int    `json:"version"`
	Generation  uint64 `json:"generation"`
	PrivateKey  string `json:"privateKey"`
	PublicKey   string `json:"publicKey"`
	ListenPort  int    `json:"listenPort"`
	MTU         int    `json:"mtu"`
	RelayPrefix string `json:"relayPrefix"`
	Host        Peer   `json:"host"`
	Devices     []Peer `json:"devices"`
}

type Peer struct {
	PublicKey string `json:"publicKey"`
	Address   string `json:"address"`
}

type RouteInventory interface{ Prefixes() []netip.Prefix }
type StaticRoutes []netip.Prefix

func (r StaticRoutes) Prefixes() []netip.Prefix { return []netip.Prefix(r) }

func Decode(data []byte, inventory RouteInventory) (Specification, error) {
	var spec Specification
	if len(data) == 0 || len(data) > MaximumBytes {
		return spec, errors.New("configuration size rejected")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return spec, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return spec, errors.New("configuration shape rejected")
	}
	if err := requireEOF(decoder); err != nil {
		return spec, err
	}
	if err := spec.Validate(inventory); err != nil {
		return spec, err
	}
	return spec, nil
}

func (s Specification) Validate(inventory RouteInventory) error {
	if s.Version != Version {
		return errors.New("unsupported configuration version")
	}
	if s.Generation == 0 {
		return errors.New("generation must be positive")
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 || s.MTU != MTU {
		return errors.New("hub instance policy rejected")
	}
	privateKey, err := DecodeKey(s.PrivateKey)
	if err != nil {
		return errors.New("private key rejected")
	}
	publicKey, err := DecodeKey(s.PublicKey)
	if err != nil {
		return errors.New("public key rejected")
	}
	derived, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil || !bytes.Equal(derived, publicKey) {
		return errors.New("hub key agreement rejected")
	}
	prefix, err := netip.ParsePrefix(s.RelayPrefix)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 || prefix.Masked() != prefix || !prefix.Addr().IsPrivate() {
		return errors.New("relay prefix rejected")
	}
	direct := netip.MustParsePrefix(DirectPrefix)
	if prefix.Overlaps(direct) {
		return errors.New("relay prefix overlaps direct mesh")
	}
	if inventory != nil {
		for _, route := range inventory.Prefixes() {
			if route.IsValid() && prefix.Overlaps(route) {
				return errors.New("relay prefix overlaps configured route")
			}
		}
	}
	if len(s.Devices) < 1 || len(s.Devices) > MaximumDevices {
		return errors.New("device count rejected")
	}
	if err := validatePeer(s.Host, prefix, 1); err != nil {
		return errors.New("host peer rejected")
	}
	seenKeys := map[string]bool{s.PublicKey: true, s.Host.PublicKey: true}
	seenAddresses := map[string]bool{s.Host.Address: true}
	previous := 1
	for _, peer := range s.Devices {
		ordinal, err := peerOrdinal(peer.Address, prefix)
		if err != nil || ordinal < 2 || ordinal > 254 || ordinal <= previous {
			return errors.New("device ordering rejected")
		}
		if err := validatePeer(peer, prefix, ordinal); err != nil {
			return errors.New("device peer rejected")
		}
		if seenKeys[peer.PublicKey] || seenAddresses[peer.Address] {
			return errors.New("duplicate key or route")
		}
		seenKeys[peer.PublicKey] = true
		seenAddresses[peer.Address] = true
		previous = ordinal
	}
	if s.Host.PublicKey == s.PublicKey {
		return errors.New("hub key reused by host")
	}
	return nil
}

func validatePeer(peer Peer, prefix netip.Prefix, ordinal int) error {
	if _, err := DecodeKey(peer.PublicKey); err != nil {
		return err
	}
	actual, err := peerOrdinal(peer.Address, prefix)
	if err != nil || actual != ordinal {
		return errors.New("peer route rejected")
	}
	return nil
}

func peerOrdinal(value string, prefix netip.Prefix) (int, error) {
	p, err := netip.ParsePrefix(value)
	if err != nil || !p.Addr().Is4() || p.Bits() != 32 || p.String() != value || !prefix.Contains(p.Addr()) {
		return 0, errors.New("noncanonical peer route")
	}
	a := p.Addr().As4()
	base := prefix.Addr().As4()
	if a[0] != base[0] || a[1] != base[1] || a[2] != base[2] {
		return 0, errors.New("peer outside relay prefix")
	}
	return int(a[3]), nil
}

func (s Specification) CanonicalJSON() ([]byte, error) {
	copySpec := s
	prefix, _ := netip.ParsePrefix(copySpec.RelayPrefix)
	sort.Slice(copySpec.Devices, func(i, j int) bool {
		left, _ := peerOrdinal(copySpec.Devices[i].Address, prefix)
		right, _ := peerOrdinal(copySpec.Devices[j].Address, prefix)
		return left < right
	})
	data, err := json.MarshalIndent(copySpec, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (s Specification) PublicDigest() string {
	var b strings.Builder
	fmt.Fprintf(&b, "reach-relay-hub-public-v1\nversion=%d\ngeneration=%d\npublicKey=%s\nlistenPort=%d\nmtu=%d\nrelayPrefix=%s\nhost.publicKey=%s\nhost.address=%s\n", s.Version, s.Generation, s.PublicKey, s.ListenPort, s.MTU, s.RelayPrefix, s.Host.PublicKey, s.Host.Address)
	for i, p := range s.Devices {
		fmt.Fprintf(&b, "device.%d.publicKey=%s\ndevice.%d.address=%s\n", i, p.PublicKey, i, p.Address)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func (s Specification) SameInstance(other Specification) bool {
	return s.PrivateKey == other.PrivateKey && s.PublicKey == other.PublicKey && s.ListenPort == other.ListenPort && s.MTU == other.MTU && s.RelayPrefix == other.RelayPrefix && s.Host == other.Host
}

func (s Specification) Peers() []Peer {
	result := make([]Peer, 0, 1+len(s.Devices))
	result = append(result, s.Host)
	result = append(result, s.Devices...)
	return result
}

func DecodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("key must be canonical 32-byte base64")
	}
	return decoded, nil
}

func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	if err := walk(d); err != nil {
		return err
	}
	return requireEOF(d)
}
func walk(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return errors.New("malformed JSON")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return errors.New("malformed JSON object")
			}
			key, ok := kt.(string)
			if !ok || seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if err := walk(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for d.More() {
			if err := walk(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
func requireEOF(d *json.Decoder) error {
	if _, err := d.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return errors.New("malformed trailing JSON data")
	}
	return errors.New("trailing JSON data")
}

type FileRule struct {
	Owner *uint32
	Group *uint32
	Mode  os.FileMode
	Limit int64
}

func ReadSecureFile(path string, rule FileRule) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != rule.Mode {
		return nil, errors.New("unsafe configuration file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errors.New("ambiguous configuration file")
	}
	if rule.Owner != nil && stat.Uid != *rule.Owner {
		return nil, errors.New("configuration owner rejected")
	}
	if rule.Group != nil && stat.Gid != *rule.Group {
		return nil, errors.New("configuration group rejected")
	}
	if info.Size() < 1 || info.Size() > rule.Limit {
		return nil, errors.New("configuration size rejected")
	}
	return io.ReadAll(io.LimitReader(f, rule.Limit+1))
}
