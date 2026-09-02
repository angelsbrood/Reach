package bootstrap

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func validInventory(root string) Inventory {
	return Inventory{
		SchemaVersion: 1, Namespace: "reach-lab", AuthorityRoot: root,
		PrivateNetwork: "192.168.108.0/29", ConnectorAddress: "192.168.108.1",
		GatewayMode:       GatewayDirect,
		Coordinator:       NodeInventory{Name: "reach-exo-a", Address: "192.168.108.2", Interface: "eth0", MACAddress: "52:55:55:00:00:02"},
		Worker:            NodeInventory{Name: "reach-exo-b", Address: "192.168.108.6", Interface: "eth0", MACAddress: "52:55:55:00:00:03"},
		CertificateExpiry: testNow.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
}

func TestInventoryStrictCanonicalAndBoundaryValidation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "authority")
	value := validInventory(root)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, canonical, digest, err := DecodeInventory(data, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != value || len(canonical) == 0 || !validLowerSHA256(digest) {
		t.Fatal("canonical inventory result differs")
	}

	unknown := append(data[:len(data)-1], []byte(`,"credential":"forbidden"}`)...)
	if _, _, _, err := DecodeInventory(unknown, testNow); err == nil {
		t.Fatal("unknown secret-like field was accepted")
	}
	if _, _, _, err := DecodeInventory(append(data, []byte(` {}`)...), testNow); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
}

func TestInventoryRefusalMatrix(t *testing.T) {
	base := validInventory(filepath.Join(t.TempDir(), "authority"))
	tests := map[string]func(*Inventory){
		"schema":           func(v *Inventory) { v.SchemaVersion++ },
		"namespace empty":  func(v *Inventory) { v.Namespace = "" },
		"namespace unsafe": func(v *Inventory) { v.Namespace = "Reach Lab" },
		"namespace long":   func(v *Inventory) { v.Namespace = strings.Repeat("a", 49) },
		"relative root":    func(v *Inventory) { v.AuthorityRoot = "authority" },
		"unclean root":     func(v *Inventory) { v.AuthorityRoot += "/../authority" },
		"root slash":       func(v *Inventory) { v.AuthorityRoot = "/" },
		"public network": func(v *Inventory) {
			v.PrivateNetwork = "8.8.8.0/29"
			v.ConnectorAddress = "8.8.8.1"
			v.Coordinator.Address = "8.8.8.2"
			v.Worker.Address = "8.8.8.6"
		},
		"wide network":         func(v *Inventory) { v.PrivateNetwork = "192.168.108.0/23" },
		"narrow network":       func(v *Inventory) { v.PrivateNetwork = "192.168.108.0/30" },
		"noncanonical network": func(v *Inventory) { v.PrivateNetwork = "192.168.108.1/29" },
		"bad gateway mode":     func(v *Inventory) { v.GatewayMode = "automatic" },
		"duplicate names":      func(v *Inventory) { v.Worker.Name = v.Coordinator.Name },
		"duplicate address":    func(v *Inventory) { v.Worker.Address = v.Coordinator.Address },
		"duplicate MAC":        func(v *Inventory) { v.Worker.MACAddress = v.Coordinator.MACAddress },
		"unsafe node name":     func(v *Inventory) { v.Worker.Name = "worker_1" },
		"unsafe interface":     func(v *Inventory) { v.Worker.Interface = "../../eth0" },
		"long interface":       func(v *Inventory) { v.Worker.Interface = "interface-name-too-long" },
		"noncanonical MAC":     func(v *Inventory) { v.Worker.MACAddress = "52-55-55-00-00-03" },
		"multicast MAC":        func(v *Inventory) { v.Worker.MACAddress = "53:55:55:00:00:03" },
		"zero MAC":             func(v *Inventory) { v.Worker.MACAddress = "00:00:00:00:00:00" },
		"network endpoint":     func(v *Inventory) { v.ConnectorAddress = "192.168.108.0" },
		"broadcast endpoint":   func(v *Inventory) { v.Worker.Address = "192.168.108.7" },
		"outside endpoint":     func(v *Inventory) { v.Worker.Address = "192.168.109.2" },
		"IPv6 endpoint":        func(v *Inventory) { v.Worker.Address = "fd00::2" },
		"early expiry":         func(v *Inventory) { v.CertificateExpiry = testNow.Add(23 * time.Hour).Format(time.RFC3339) },
		"late expiry":          func(v *Inventory) { v.CertificateExpiry = testNow.Add(826 * 24 * time.Hour).Format(time.RFC3339) },
		"fractional expiry":    func(v *Inventory) { v.CertificateExpiry = "2026-10-01T12:00:00.500Z" },
		"non-UTC expiry":       func(v *Inventory) { v.CertificateExpiry = "2026-10-01T12:00:00+01:00" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if err := value.Validate(testNow); err == nil {
				t.Fatal("invalid inventory was accepted")
			}
		})
	}
}

func TestMinimumNetworkEveryUsableBoundary(t *testing.T) {
	base := validInventory(filepath.Join(t.TempDir(), "authority"))
	for name, addresses := range map[string][3]string{
		"first hosts": {"192.168.108.1", "192.168.108.2", "192.168.108.3"},
		"last hosts":  {"192.168.108.4", "192.168.108.5", "192.168.108.6"},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.ConnectorAddress = addresses[0]
			value.Coordinator.Address = addresses[1]
			value.Worker.Address = addresses[2]
			if err := value.Validate(testNow); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDerivationFixesTopologyAndGatewayModes(t *testing.T) {
	value := validInventory(filepath.Join(t.TempDir(), "authority"))
	direct := deriveTopology(value)
	if direct.GatewayAddress != "192.168.108.2:53421" || direct.Coordinator.RangeStart != 14 || direct.Worker.RangeStart != 0 || direct.Coordinator.PeerMAC != value.Worker.MACAddress || direct.Worker.PeerMAC != value.Coordinator.MACAddress {
		t.Fatal("direct topology derivation differs")
	}
	value.GatewayMode = GatewayTunnel
	tunnel := deriveTopology(value)
	if tunnel.GatewayAddress != "127.0.0.1:53422" {
		t.Fatal("loopback tunnel derivation differs")
	}
}

func TestRecoveryInventoryDoesNotDependOnRemainingCertificateLifetime(t *testing.T) {
	value := validInventory(filepath.Join(t.TempDir(), "authority"))
	value.CertificateExpiry = "2026-01-31T12:00:00Z"
	data, _ := json.Marshal(value)
	if _, _, _, err := DecodeInventory(data, testNow); err == nil {
		t.Fatal("expired inventory was accepted for new creation")
	}
	decoded, _, digest, err := DecodeInventoryForRecovery(data)
	if err != nil || decoded != value || !validLowerSHA256(digest) {
		t.Fatalf("same strict inventory could not authorize cleanup after expiry: %v", err)
	}
}

func TestAuthorityDigestSerializationGolden(t *testing.T) {
	exact := exactAuthority()
	fingerprints := Fingerprints{CA: strings.Repeat("1", 64), Coordinator: strings.Repeat("2", 64), Worker: strings.Repeat("3", 64), Connector: strings.Repeat("4", 64)}
	got := authorityDigest(strings.Repeat("a", 64), "/private/tmp/reach-authority", exact, strings.Repeat("b", 64), fingerprints, strings.Repeat("c", 64))
	const expected = "77718d589410753f2a7351bf109171a0cc050514e04ea7bd8ced0562f88bf0c6"
	if got != expected {
		t.Fatalf("authority digest golden differs: got %s", got)
	}
}
