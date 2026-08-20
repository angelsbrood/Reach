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
	SpecificationVersion      = 1
	RelaySpecificationVersion = 2
	HostAddress               = "10.86.0.1/24"
	MeshNetwork               = "10.86.0.0/24"
	ListenPort                = 51820
	InterfaceMTU              = 1280
	MaximumPeers              = 253
	MaximumKeepalive          = 3600
	RelayKeepalive            = 25
	MaximumSpecBytes          = 64 * 1024
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
	Relay      *Relay `json:"relay,omitempty"`
}

type Peer struct {
	PublicKey string `json:"publicKey"`
	AllowedIP string `json:"allowedIP"`
	Keepalive int    `json:"keepalive"`
}

type Relay struct {
	Network      string   `json:"network"`
	Address      string   `json:"address"`
	HubPublicKey string   `json:"hubPublicKey"`
	Endpoint     string   `json:"endpoint"`
	Keepalive    int      `json:"keepalive"`
	Routes       []string `json:"routes"`
}

func DecodeSpecification(data []byte) (Specification, error) {
	var spec Specification
	if len(data) == 0 || len(data) > MaximumSpecBytes {
		return spec, errors.New("configuration size rejected")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return spec, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return spec, errors.New("configuration shape rejected")
	}
	var version int
	if value, ok := fields["version"]; !ok || json.Unmarshal(value, &version) != nil {
		return spec, errors.New("configuration version rejected")
	}
	want := map[string]bool{
		"version": true, "generation": true, "privateKey": true, "publicKey": true,
		"address": true, "port": true, "mtu": true, "peers": true,
	}
	if version == RelaySpecificationVersion {
		if len(fields) != len(want) && len(fields) != len(want)+1 {
			return spec, errors.New("configuration shape rejected")
		}
		if _, present := fields["relay"]; present {
			want["relay"] = true
		}
	}
	if len(fields) != len(want) {
		return spec, errors.New("configuration shape rejected")
	}
	for key := range fields {
		if !want[key] {
			return spec, errors.New("configuration shape rejected")
		}
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

func EncodeSpecification(spec Specification) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (spec Specification) Validate() error {
	if spec.Version != SpecificationVersion && spec.Version != RelaySpecificationVersion {
		return errors.New("unsupported configuration version")
	}
	if spec.Version == SpecificationVersion && spec.Relay != nil {
		return errors.New("version 1 cannot contain relay configuration")
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
	if spec.Relay != nil {
		if err := spec.validateRelay(seenKeys); err != nil {
			return err
		}
	}
	return nil
}

func (spec Specification) validateRelay(directKeys map[string]bool) error {
	relay := spec.Relay
	ip, network, err := net.ParseCIDR(relay.Network)
	if err != nil || ip.To4() == nil || network.String() != relay.Network || !ip.Equal(network.IP) {
		return errors.New("relay network rejected")
	}
	ones, bits := network.Mask.Size()
	octets := ip.To4()
	if bits != 32 || ones != 24 || !isRFC1918(octets) || relay.Network == MeshNetwork {
		return errors.New("relay network must be a distinct private /24")
	}
	wantAddress := fmt.Sprintf("%d.%d.%d.1/32", octets[0], octets[1], octets[2])
	if relay.Address != wantAddress {
		return errors.New("relay host address rejected")
	}
	if _, err := DecodeKey(relay.HubPublicKey); err != nil || relay.HubPublicKey == spec.PublicKey || directKeys[relay.HubPublicKey] {
		return errors.New("relay hub key rejected")
	}
	if relay.Keepalive != RelayKeepalive {
		return errors.New("relay keepalive rejected")
	}
	if canonical, ok := canonicalEndpoint(relay.Endpoint, network); !ok || canonical != relay.Endpoint {
		return errors.New("relay endpoint rejected")
	}
	if len(relay.Routes) != len(spec.Peers) {
		return errors.New("relay route count rejected")
	}
	for index, peer := range spec.Peers {
		ordinal, ok := peerOrdinal(peer.AllowedIP)
		if !ok {
			return errors.New("relay peer ordinal rejected")
		}
		want := fmt.Sprintf("%d.%d.%d.%d/32", octets[0], octets[1], octets[2], ordinal)
		if relay.Routes[index] != want {
			return errors.New("relay routes do not match direct peer ordinals")
		}
	}
	return nil
}

func isRFC1918(ip net.IP) bool {
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)
}

func canonicalEndpoint(value string, relay *net.IPNet) (string, bool) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return "", false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != portText {
		return "", false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || relay.Contains(ip) {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		if strings.HasPrefix(host, "0") || host != v4.String() || v4.Equal(net.IPv4bcast) || strings.HasPrefix(host, "10.86.0.") {
			return "", false
		}
		return net.JoinHostPort(v4.String(), portText), true
	}
	canonical := strings.ToLower(ip.String())
	if strings.ToLower(host) != canonical {
		return "", false
	}
	return net.JoinHostPort(canonical, portText), true
}

func DecodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("key must be canonical 32-byte base64")
	}
	return decoded, nil
}

func (spec Specification) PublicDigest() string {
	if spec.Relay != nil {
		var source strings.Builder
		source.WriteString("reach-mesh-public-v2\n")
		fmt.Fprintf(&source, "version=%d\n", spec.Version)
		fmt.Fprintf(&source, "generation=%d\n", spec.Generation)
		fmt.Fprintf(&source, "directDigest=%s\n", spec.DirectDigest())
		fmt.Fprintf(&source, "relayDigest=%s\n", spec.RelayDigest())
		return digestString(source.String())
	}
	var source strings.Builder
	source.WriteString("reach-mesh-public-v1\n")
	// A v2 envelope without a relay block is the canonical direct-only v1
	// authority. This keeps removal byte/digest compatible across an upgrade.
	fmt.Fprintf(&source, "version=%d\n", SpecificationVersion)
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
	return digestString(source.String())
}

func (spec Specification) DirectDigest() string {
	var source strings.Builder
	source.WriteString("reach-mesh-direct-v1\n")
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
	return digestString(source.String())
}

func (spec Specification) RelayDigest() string {
	if spec.Relay == nil {
		return ""
	}
	var source strings.Builder
	source.WriteString("reach-mesh-relay-v1\n")
	fmt.Fprintf(&source, "network=%s\n", spec.Relay.Network)
	fmt.Fprintf(&source, "address=%s\n", spec.Relay.Address)
	fmt.Fprintf(&source, "hubPublicKey=%s\n", spec.Relay.HubPublicKey)
	fmt.Fprintf(&source, "endpoint=%s\n", spec.Relay.Endpoint)
	fmt.Fprintf(&source, "keepalive=%d\n", spec.Relay.Keepalive)
	fmt.Fprintf(&source, "routeCount=%d\n", len(spec.Relay.Routes))
	for index, route := range spec.Relay.Routes {
		fmt.Fprintf(&source, "route.%d=%s\n", index, route)
	}
	return digestString(source.String())
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

type DesiredPeer struct {
	PublicKey string
	Allowed   []string
	Endpoint  string
	Keepalive int
	Hub       bool
}

func (spec Specification) DesiredPeers() []DesiredPeer {
	peers := make([]DesiredPeer, 0, len(spec.Peers)+1)
	for _, peer := range spec.Peers {
		peers = append(peers, DesiredPeer{
			PublicKey: peer.PublicKey,
			Allowed:   []string{peer.AllowedIP},
			Keepalive: peer.Keepalive,
		})
	}
	if spec.Relay != nil {
		peers = append(peers, DesiredPeer{
			PublicKey: spec.Relay.HubPublicKey,
			Allowed:   append([]string(nil), spec.Relay.Routes...),
			Endpoint:  spec.Relay.Endpoint,
			Keepalive: spec.Relay.Keepalive,
			Hub:       true,
		})
	}
	return peers
}

func (spec Specification) UAPI() string {
	privateKey, _ := DecodeKey(spec.PrivateKey)
	var output strings.Builder
	fmt.Fprintf(&output, "private_key=%s\n", hex.EncodeToString(privateKey))
	fmt.Fprintf(&output, "listen_port=%d\n", spec.Port)
	// Retained for deterministic schema fixtures. The live Darwin backend uses
	// an exact diff and never sends replace_peers, so unchanged peers keep their
	// roaming endpoint, handshake, counters, and staged traffic.
	for _, peer := range spec.Peers {
		publicKey, _ := DecodeKey(peer.PublicKey)
		fmt.Fprintf(&output, "public_key=%s\n", hex.EncodeToString(publicKey))
		output.WriteString("replace_allowed_ips=true\n")
		fmt.Fprintf(&output, "allowed_ip=%s\n", peer.AllowedIP)
		fmt.Fprintf(&output, "persistent_keepalive_interval=%d\n", peer.Keepalive)
	}
	if spec.Relay != nil {
		publicKey, _ := DecodeKey(spec.Relay.HubPublicKey)
		fmt.Fprintf(&output, "public_key=%s\n", hex.EncodeToString(publicKey))
		fmt.Fprintf(&output, "endpoint=%s\n", spec.Relay.Endpoint)
		output.WriteString("replace_allowed_ips=true\n")
		for _, route := range spec.Relay.Routes {
			fmt.Fprintf(&output, "allowed_ip=%s\n", route)
		}
		fmt.Fprintf(&output, "persistent_keepalive_interval=%d\n", spec.Relay.Keepalive)
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
