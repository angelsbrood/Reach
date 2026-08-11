// SPDX-License-Identifier: MIT

package mesh

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	SpecificationVersion = 1
	HostAddress          = "10.86.0.1/24"
	MeshNetwork          = "10.86.0.0/24"
	ListenPort           = 51820
	InterfaceMTU         = 1280
	MaximumPeers         = 253
	MaximumKeepalive     = 3600
	MaximumSpecBytes     = 64 * 1024
)

type Specification struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	MTU        int    `json:"mtu"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey string `json:"publicKey"`
	AllowedIP string `json:"allowedIP"`
	Keepalive int    `json:"keepalive"`
}

func DecodeSpecification(data []byte) (Specification, error) {
	var spec Specification
	if len(data) == 0 || len(data) > MaximumSpecBytes {
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
	if err := requireJSONEOF(decoder); err != nil {
		return spec, err
	}
	if err := spec.Validate(); err != nil {
		return spec, err
	}
	return spec, nil
}

func (spec Specification) Validate() error {
	if spec.Version != SpecificationVersion {
		return errors.New("unsupported configuration version")
	}
	if spec.Generation == 0 {
		return errors.New("generation must be positive")
	}
	if spec.Address != HostAddress || spec.Port != ListenPort || spec.MTU != InterfaceMTU {
		return errors.New("interface policy rejected")
	}
	if len(spec.Peers) < 1 || len(spec.Peers) > MaximumPeers {
		return errors.New("peer count rejected")
	}
	privateKey, err := DecodeKey(spec.PrivateKey)
	if err != nil {
		return errors.New("private key rejected")
	}
	publicKey, err := DecodeKey(spec.PublicKey)
	if err != nil {
		return errors.New("public key rejected")
	}
	derived, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil || !bytes.Equal(derived, publicKey) {
		return errors.New("host key agreement rejected")
	}

	seenKeys := make(map[string]bool, len(spec.Peers))
	seenRoutes := make(map[string]bool, len(spec.Peers))
	previousOrdinal := 1
	for _, peer := range spec.Peers {
		if _, err := DecodeKey(peer.PublicKey); err != nil || seenKeys[peer.PublicKey] {
			return errors.New("peer key rejected")
		}
		seenKeys[peer.PublicKey] = true
		ip, network, err := net.ParseCIDR(peer.AllowedIP)
		if err != nil || ip.To4() == nil || network.String() != peer.AllowedIP || !ip.Equal(network.IP) {
			return errors.New("peer route rejected")
		}
		ones, bits := network.Mask.Size()
		last := ip.To4()[3]
		if bits != 32 || ones != 32 || !strings.HasPrefix(peer.AllowedIP, "10.86.0.") || last < 2 || last > 254 {
			return errors.New("peer route outside Reach mesh")
		}
		if seenRoutes[peer.AllowedIP] {
			return errors.New("duplicate or overlapping peer route")
		}
		seenRoutes[peer.AllowedIP] = true
		ordinal, ok := peerOrdinal(peer.AllowedIP)
		if !ok || ordinal <= previousOrdinal {
			return errors.New("peer routes are not in canonical order")
		}
		previousOrdinal = ordinal
		if peer.Keepalive < 0 || peer.Keepalive > MaximumKeepalive {
			return errors.New("peer keepalive rejected")
		}
	}
	return nil
}

func DecodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("key must be canonical 32-byte base64")
	}
	return decoded, nil
}

func (spec Specification) PublicDigest() string {
	var source strings.Builder
	source.WriteString("reach-mesh-public-v1\n")
	fmt.Fprintf(&source, "version=%d\n", spec.Version)
	fmt.Fprintf(&source, "generation=%d\n", spec.Generation)
	fmt.Fprintf(&source, "publicKey=%s\n", spec.PublicKey)
	fmt.Fprintf(&source, "address=%s\n", spec.Address)
	fmt.Fprintf(&source, "port=%d\n", spec.Port)
	fmt.Fprintf(&source, "mtu=%d\n", spec.MTU)
	fmt.Fprintf(&source, "peerCount=%d\n", len(spec.Peers))
	for index, peer := range spec.Peers {
		fmt.Fprintf(&source, "peer.%d.publicKey=%s\n", index, peer.PublicKey)
		fmt.Fprintf(&source, "peer.%d.allowedIP=%s\n", index, peer.AllowedIP)
		fmt.Fprintf(&source, "peer.%d.keepalive=%d\n", index, peer.Keepalive)
	}
	digest := sha256.Sum256([]byte(source.String()))
	return hex.EncodeToString(digest[:])
}

func (spec Specification) UAPI() string {
	privateKey, _ := DecodeKey(spec.PrivateKey)
	var output strings.Builder
	fmt.Fprintf(&output, "private_key=%s\n", hex.EncodeToString(privateKey))
	fmt.Fprintf(&output, "listen_port=%d\n", spec.Port)
	output.WriteString("replace_peers=true\n")
	for _, peer := range spec.Peers {
		publicKey, _ := DecodeKey(peer.PublicKey)
		fmt.Fprintf(&output, "public_key=%s\n", hex.EncodeToString(publicKey))
		output.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&output, "allowed_ip=%s\n", peer.AllowedIP)
		fmt.Fprintf(&output, "persistent_keepalive_interval=%d\n", peer.Keepalive)
	}
	output.WriteByte('\n')
	return output.String()
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("malformed JSON")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("malformed JSON object")
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return errors.New("malformed trailing JSON data")
	}
	return errors.New("trailing JSON data")
}

func peerOrdinal(route string) (int, bool) {
	prefix := "10.86.0."
	if !strings.HasPrefix(route, prefix) || !strings.HasSuffix(route, "/32") {
		return 0, false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(route, prefix), "/32")
	ordinal, err := strconv.Atoi(value)
	return ordinal, err == nil && ordinal >= 2 && ordinal <= 254
}
