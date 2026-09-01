// Package config owns strict, fail-closed operator configuration decoding.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"reach.dev/exo-runtime/internal/authority"
)

type LayerRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type TLSFiles struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type Node struct {
	SchemaVersion       int        `json:"schema_version"`
	Role                string     `json:"role"`
	NodeName            string     `json:"node_name"`
	PeerName            string     `json:"peer_name"`
	PrivateAddress      string     `json:"private_address"`
	PeerAddress         string     `json:"peer_address"`
	ConnectorAddress    string     `json:"connector_address"`
	PrivateNetworkCIDR  string     `json:"private_network_cidr"`
	NetworkInterface    string     `json:"network_interface"`
	PeerMAC             string     `json:"peer_mac"`
	ExpectedRange       LayerRange `json:"expected_range"`
	ExpectedPeerRange   LayerRange `json:"expected_peer_range"`
	ModelID             string     `json:"model_id"`
	ModelSnapshot       string     `json:"model_snapshot"`
	ModelManifestSHA256 string     `json:"model_manifest_sha256"`
	NamespacePrefix     string     `json:"namespace_prefix"`
	TLS                 TLSFiles   `json:"tls"`
}

type Connector struct {
	SchemaVersion  int      `json:"schema_version"`
	ListenAddress  string   `json:"listen_address"`
	GatewayAddress string   `json:"gateway_address"`
	ServerName     string   `json:"server_name"`
	TLS            TLSFiles `json:"tls"`
}

func strictDecode[T any](data []byte, target *T) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains more than one JSON value")
		}
		return err
	}
	return nil
}

func DecodeNode(data []byte) (Node, error) {
	var value Node
	if err := strictDecode(data, &value); err != nil {
		return Node{}, fmt.Errorf("decode node configuration: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Node{}, err
	}
	return value, nil
}

func DecodeConnector(data []byte) (Connector, error) {
	var value Connector
	if err := strictDecode(data, &value); err != nil {
		return Connector{}, fmt.Errorf("decode connector configuration: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Connector{}, err
	}
	return value, nil
}

func LoadNode(path string) (Node, error) {
	data, err := readSecureFile(path, 0640, true)
	if err != nil {
		return Node{}, err
	}
	if err := requireGroup(path, authority.ServiceUser); err != nil {
		return Node{}, err
	}
	return DecodeNode(data)
}

func LoadConnector(path string) (Connector, error) {
	data, err := readSecureFile(path, 0600, false)
	if err != nil {
		return Connector{}, err
	}
	return DecodeConnector(data)
}

func (n Node) Validate() error {
	if n.SchemaVersion != authority.SchemaVersion {
		return fmt.Errorf("schema_version must be %d", authority.SchemaVersion)
	}
	if n.Role != "coordinator" && n.Role != "worker" {
		return errors.New("role must be coordinator or worker")
	}
	if n.NodeName == "" || n.PeerName == "" || n.NodeName == n.PeerName {
		return errors.New("node_name and peer_name must be distinct and nonempty")
	}
	if !safeName(n.NodeName) || !safeName(n.PeerName) {
		return errors.New("node names may contain only lowercase ASCII letters, digits, and hyphens")
	}
	if n.ModelID != authority.ModelID || n.ModelSnapshot != authority.ModelSnapshot || n.ModelManifestSHA256 != authority.ModelManifestSHA256 {
		return errors.New("model authority does not match the selected immutable snapshot")
	}
	if !safeName(n.NamespacePrefix) || len(n.NamespacePrefix) > 48 {
		return errors.New("namespace_prefix must be a short safe name")
	}
	self := net.ParseIP(n.PrivateAddress)
	peer := net.ParseIP(n.PeerAddress)
	connector := net.ParseIP(n.ConnectorAddress)
	if self == nil || peer == nil || connector == nil || self.To4() == nil || peer.To4() == nil || connector.To4() == nil {
		return errors.New("private, peer, and connector addresses must be numeric IPv4 addresses")
	}
	if self.IsLoopback() || peer.IsLoopback() || connector.IsLoopback() || self.Equal(peer) || self.Equal(connector) || peer.Equal(connector) {
		return errors.New("private, peer, and connector addresses must be distinct non-loopback addresses")
	}
	_, network, err := net.ParseCIDR(n.PrivateNetworkCIDR)
	if err != nil {
		return errors.New("private_network_cidr must be a canonical IPv4 CIDR")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 24 || ones > 30 || network.String() != n.PrivateNetworkCIDR {
		return errors.New("private_network_cidr must be canonical and no wider than /24 or narrower than /30")
	}
	if !network.Contains(self) || !network.Contains(peer) || !network.Contains(connector) {
		return errors.New("all declared addresses must belong to private_network_cidr")
	}
	if !privateIPv4(network.IP) {
		return errors.New("private_network_cidr must be RFC1918 private space")
	}
	if !safeInterface(n.NetworkInterface) {
		return errors.New("network_interface must be a canonical Linux interface name")
	}
	peerMAC, err := net.ParseMAC(n.PeerMAC)
	if err != nil || len(peerMAC) != 6 || peerMAC.String() != n.PeerMAC || peerMAC[0]&1 != 0 || allZero(peerMAC) {
		return errors.New("peer_mac must be a canonical unicast EUI-48 address")
	}
	if n.Role == "coordinator" {
		if n.ExpectedRange != (LayerRange{Start: 14, End: 28}) || n.ExpectedPeerRange != (LayerRange{Start: 0, End: 14}) {
			return errors.New("coordinator ranges must be exactly 14..<28 and peer 0..<14")
		}
	} else if n.ExpectedRange != (LayerRange{Start: 0, End: 14}) || n.ExpectedPeerRange != (LayerRange{Start: 14, End: 28}) {
		return errors.New("worker ranges must be exactly 0..<14 and peer 14..<28")
	}
	return validateTLSPaths(n.TLS, true)
}

func (c Connector) Validate() error {
	if c.SchemaVersion != authority.SchemaVersion {
		return fmt.Errorf("schema_version must be %d", authority.SchemaVersion)
	}
	if c.ListenAddress != fmt.Sprintf("127.0.0.1:%d", authority.ConnectorPort) {
		return fmt.Errorf("listen_address must be canonical numeric loopback 127.0.0.1:%d", authority.ConnectorPort)
	}
	host, port, err := net.SplitHostPort(c.GatewayAddress)
	if err != nil {
		return errors.New("gateway_address must be a numeric IPv4 address with an admitted gateway port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return errors.New("gateway_address must use a numeric IPv4 address")
	}
	direct := port == fmt.Sprint(authority.GatewayPort) && !ip.IsLoopback() && privateIPv4(ip)
	tunnel := c.GatewayAddress == fmt.Sprintf("127.0.0.1:%d", authority.GatewayTunnelPort)
	if !direct && !tunnel {
		return fmt.Errorf("gateway_address must use non-loopback RFC1918 IPv4 port %d or canonical account-owned tunnel 127.0.0.1:%d", authority.GatewayPort, authority.GatewayTunnelPort)
	}
	if c.ServerName != "reach-exo-gateway" {
		return errors.New("server_name must be reach-exo-gateway")
	}
	return validateTLSPaths(c.TLS, false)
}

func validateTLSPaths(t TLSFiles, node bool) error {
	root := authority.ConfigRoot + "/tls/"
	for label, path := range map[string]string{"ca": t.CA, "certificate": t.Certificate, "private_key": t.PrivateKey} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("tls %s path must be absolute and canonical", label)
		}
		if node && !strings.HasPrefix(path, root) {
			return fmt.Errorf("node tls %s must be beneath %s", label, root)
		}
	}
	if t.CA == t.Certificate || t.CA == t.PrivateKey || t.Certificate == t.PrivateKey {
		return errors.New("TLS paths must be distinct")
	}
	return nil
}

func ValidateTLSFileModes(t TLSFiles, node bool) error {
	ownerRoot := node
	if _, err := readSecureFile(t.CA, 0644, ownerRoot); err != nil {
		return fmt.Errorf("CA: %w", err)
	}
	if _, err := readSecureFile(t.Certificate, 0644, ownerRoot); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	keyMode := os.FileMode(0600)
	if node {
		keyMode = 0640
	}
	if _, err := readSecureFile(t.PrivateKey, keyMode, ownerRoot); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if node {
		if err := requireGroup(t.PrivateKey, authority.ServiceUser); err != nil {
			return fmt.Errorf("private key: %w", err)
		}
	}
	return nil
}

func requireGroup(path, name string) error {
	group, err := user.LookupGroup(name)
	if err != nil {
		return fmt.Errorf("lookup required group %s: %w", name, err)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Gid) != gid {
		return fmt.Errorf("%s group does not match %s", path, name)
	}
	return nil
}

func readSecureFile(path string, expected os.FileMode, rootOwned bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular non-symlink file", path)
	}
	if info.Mode().Perm() != expected {
		return nil, fmt.Errorf("%s mode is %04o, want %04o", path, info.Mode().Perm(), expected)
	}
	if runtime.GOOS != "windows" {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("cannot determine owner for %s", path)
		}
		want := uint32(os.Getuid())
		if rootOwned {
			want = 0
		}
		if stat.Uid != want {
			return nil, fmt.Errorf("%s uid is %d, want %d", path, stat.Uid, want)
		}
		if stat.Nlink != 1 {
			return nil, fmt.Errorf("%s link count is %d, want 1", path, stat.Nlink)
		}
	}
	return os.ReadFile(path)
}

func safeName(value string) bool {
	if value == "" || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func safeInterface(value string) bool {
	if value == "" || len(value) > 15 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func privateIPv4(ip net.IP) bool {
	v := ip.To4()
	return v != nil && (v[0] == 10 || (v[0] == 172 && v[1]&0xf0 == 16) || (v[0] == 192 && v[1] == 168))
}
