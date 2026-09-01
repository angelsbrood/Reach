package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reach.dev/exo-runtime/internal/authority"
)

func validNode() Node {
	return Node{
		SchemaVersion:       1,
		Role:                "coordinator",
		NodeName:            "reach-exo-a",
		PeerName:            "reach-exo-b",
		PrivateAddress:      "192.168.108.2",
		PeerAddress:         "192.168.108.3",
		ConnectorAddress:    "192.168.108.1",
		PrivateNetworkCIDR:  "192.168.108.0/24",
		NetworkInterface:    "eth0",
		PeerMAC:             "52:55:55:00:00:03",
		ExpectedRange:       LayerRange{Start: 14, End: 28},
		ExpectedPeerRange:   LayerRange{Start: 0, End: 14},
		ModelID:             authority.ModelID,
		ModelSnapshot:       authority.ModelSnapshot,
		ModelManifestSHA256: authority.ModelManifestSHA256,
		NamespacePrefix:     "reach-exo-s47",
		TLS: TLSFiles{
			CA:          "/etc/reach-exo/tls/ca.pem",
			Certificate: "/etc/reach-exo/tls/node.pem",
			PrivateKey:  "/etc/reach-exo/tls/node-key.pem",
		},
	}
}

func TestSecureFileRefusesModeLinksAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureFile(path, 0600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureFile(path, 0600, false); err == nil {
		t.Fatal("widened mode was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	hardlink := filepath.Join(directory, "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureFile(path, 0600, false); err == nil {
		t.Fatal("multiply linked file was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureFile(symlink, 0600, false); err == nil {
		t.Fatal("symlink was accepted")
	}
}

func TestNodeConfigurationValidRoles(t *testing.T) {
	coordinator := validNode()
	if err := coordinator.Validate(); err != nil {
		t.Fatal(err)
	}
	worker := coordinator
	worker.Role = "worker"
	worker.NodeName, worker.PeerName = worker.PeerName, worker.NodeName
	worker.PrivateAddress, worker.PeerAddress = worker.PeerAddress, worker.PrivateAddress
	worker.ExpectedRange, worker.ExpectedPeerRange = worker.ExpectedPeerRange, worker.ExpectedRange
	if err := worker.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNodeConfigurationRefusesDrift(t *testing.T) {
	tests := map[string]func(*Node){
		"schema":         func(v *Node) { v.SchemaVersion++ },
		"role":           func(v *Node) { v.Role = "auto" },
		"duplicate name": func(v *Node) { v.PeerName = v.NodeName },
		"unsafe name":    func(v *Node) { v.NodeName = "node_a" },
		"loopback":       func(v *Node) { v.PrivateAddress = "127.0.0.1" },
		"non-numeric":    func(v *Node) { v.PeerAddress = "peer.local" },
		"duplicate IP":   func(v *Node) { v.PeerAddress = v.PrivateAddress },
		"public CIDR": func(v *Node) {
			v.PrivateNetworkCIDR = "8.8.8.0/24"
			v.PrivateAddress = "8.8.8.2"
			v.PeerAddress = "8.8.8.3"
			v.ConnectorAddress = "8.8.8.1"
		},
		"widened CIDR":      func(v *Node) { v.PrivateNetworkCIDR = "192.168.0.0/16" },
		"noncanonical CIDR": func(v *Node) { v.PrivateNetworkCIDR = "192.168.108.1/24" },
		"outside CIDR":      func(v *Node) { v.PeerAddress = "192.168.109.3" },
		"unsafe interface":  func(v *Node) { v.NetworkInterface = "../../eth0" },
		"long interface":    func(v *Node) { v.NetworkInterface = "interface-name-too-long" },
		"noncanonical MAC":  func(v *Node) { v.PeerMAC = "52-55-55-00-00-03" },
		"multicast MAC":     func(v *Node) { v.PeerMAC = "53:55:55:00:00:03" },
		"zero MAC":          func(v *Node) { v.PeerMAC = "00:00:00:00:00:00" },
		"wrong range":       func(v *Node) { v.ExpectedRange.End = 15 },
		"wrong model":       func(v *Node) { v.ModelID = "another/model" },
		"wrong snapshot":    func(v *Node) { v.ModelSnapshot = strings.Repeat("0", 40) },
		"wrong manifest":    func(v *Node) { v.ModelManifestSHA256 = strings.Repeat("0", 64) },
		"unsafe namespace":  func(v *Node) { v.NamespacePrefix = "Reach S47" },
		"relative TLS":      func(v *Node) { v.TLS.CA = "ca.pem" },
		"outside TLS root":  func(v *Node) { v.TLS.CA = "/tmp/ca.pem" },
		"duplicate TLS":     func(v *Node) { v.TLS.PrivateKey = v.TLS.Certificate },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validNode()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("drift was accepted")
			}
		})
	}
}

func TestDecodeNodeRefusesUnknownAndTrailingValues(t *testing.T) {
	value := validNode()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodeNode(data); err == nil {
		t.Fatal("unknown field was accepted")
	}
	clean, _ := json.Marshal(value)
	clean = append(clean, []byte(` {}`)...)
	if _, err := DecodeNode(clean); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestConnectorConfiguration(t *testing.T) {
	value := Connector{
		SchemaVersion:  1,
		ListenAddress:  "127.0.0.1:52415",
		GatewayAddress: "192.168.108.2:53421",
		ServerName:     "reach-exo-gateway",
		TLS:            TLSFiles{CA: "/tmp/ca.pem", Certificate: "/tmp/connector.pem", PrivateKey: "/tmp/connector-key.pem"},
	}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	tunnel := value
	tunnel.GatewayAddress = "127.0.0.1:53422"
	if err := tunnel.Validate(); err != nil {
		t.Fatalf("canonical account-owned tunnel was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Connector){
		"hostname listen":   func(v *Connector) { v.ListenAddress = "localhost:52415" },
		"wildcard listen":   func(v *Connector) { v.ListenAddress = "0.0.0.0:52415" },
		"wrong port":        func(v *Connector) { v.ListenAddress = "127.0.0.1:52416" },
		"public gateway":    func(v *Connector) { v.GatewayAddress = "8.8.8.8:53421" },
		"hostname gateway":  func(v *Connector) { v.GatewayAddress = "node:53421" },
		"wrong tunnel port": func(v *Connector) { v.GatewayAddress = "127.0.0.1:53421" },
		"wide tunnel host":  func(v *Connector) { v.GatewayAddress = "0.0.0.0:53422" },
		"wrong TLS name":    func(v *Connector) { v.ServerName = "anything" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := value
			mutate(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("invalid connector was accepted")
			}
		})
	}
}
