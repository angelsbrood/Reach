package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"reach.dev/exo-runtime/internal/authority"
	"reach.dev/exo-runtime/internal/config"
)

func deriveTopology(inventory Inventory) Topology {
	gatewayAddress := fmt.Sprintf("%s:%d", inventory.Coordinator.Address, authority.GatewayPort)
	if inventory.GatewayMode == GatewayTunnel {
		gatewayAddress = fmt.Sprintf("127.0.0.1:%d", authority.GatewayTunnelPort)
	}
	return Topology{
		Namespace: inventory.Namespace, PrivateNetwork: inventory.PrivateNetwork,
		ConnectorAddress: inventory.ConnectorAddress, GatewayMode: inventory.GatewayMode,
		GatewayAddress: gatewayAddress, GatewayServerName: "reach-exo-gateway",
		ProviderAPIPort: authority.ProviderAPIPort, ProviderZenohPort: authority.ProviderZenohPort,
		ProviderDiscoverPort: authority.ProviderDiscoverPort, ControlPort: authority.ControlPort,
		GatewayPort: authority.GatewayPort, GatewayTunnelPort: authority.GatewayTunnelPort,
		ConnectorPort: authority.ConnectorPort,
		Coordinator: TopologyNode{
			Role: "coordinator", Name: inventory.Coordinator.Name, Address: inventory.Coordinator.Address,
			Interface: inventory.Coordinator.Interface, MACAddress: inventory.Coordinator.MACAddress,
			PeerName: inventory.Worker.Name, PeerAddress: inventory.Worker.Address, PeerMAC: inventory.Worker.MACAddress,
			RangeStart: 14, RangeEnd: 28, PeerRangeStart: 0, PeerRangeEnd: 14,
		},
		Worker: TopologyNode{
			Role: "worker", Name: inventory.Worker.Name, Address: inventory.Worker.Address,
			Interface: inventory.Worker.Interface, MACAddress: inventory.Worker.MACAddress,
			PeerName: inventory.Coordinator.Name, PeerAddress: inventory.Coordinator.Address, PeerMAC: inventory.Coordinator.MACAddress,
			RangeStart: 0, RangeEnd: 14, PeerRangeStart: 14, PeerRangeEnd: 28,
		},
	}
}

func topologyDigest(topology Topology) (string, error) {
	data, err := json.Marshal(topology)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func nodeConfiguration(topology Topology, role string) (config.Node, error) {
	self, peer := topology.Coordinator, topology.Worker
	if role == "worker" {
		self, peer = topology.Worker, topology.Coordinator
	} else if role != "coordinator" {
		return config.Node{}, fmt.Errorf("unknown node role %q", role)
	}
	certificate := role + ".pem"
	privateKey := role + "-key.pem"
	value := config.Node{
		SchemaVersion: authority.SchemaVersion, Role: role, NodeName: self.Name, PeerName: peer.Name,
		PrivateAddress: self.Address, PeerAddress: peer.Address, ConnectorAddress: topology.ConnectorAddress,
		PrivateNetworkCIDR: topology.PrivateNetwork, NetworkInterface: self.Interface, PeerMAC: peer.MACAddress,
		ExpectedRange:     config.LayerRange{Start: self.RangeStart, End: self.RangeEnd},
		ExpectedPeerRange: config.LayerRange{Start: self.PeerRangeStart, End: self.PeerRangeEnd},
		ModelID:           authority.ModelID, ModelSnapshot: authority.ModelSnapshot,
		ModelManifestSHA256: authority.ModelManifestSHA256, NamespacePrefix: topology.Namespace,
		TLS: config.TLSFiles{
			CA:          authority.ConfigRoot + "/tls/ca.pem",
			Certificate: authority.ConfigRoot + "/tls/" + certificate,
			PrivateKey:  authority.ConfigRoot + "/tls/" + privateKey,
		},
	}
	return value, value.Validate()
}

func connectorConfiguration(root string, topology Topology) (config.Connector, error) {
	tlsRoot := filepath.Join(root, "connector", "tls")
	value := config.Connector{
		SchemaVersion:  authority.SchemaVersion,
		ListenAddress:  fmt.Sprintf("127.0.0.1:%d", authority.ConnectorPort),
		GatewayAddress: topology.GatewayAddress, ServerName: topology.GatewayServerName,
		TLS: config.TLSFiles{
			CA: filepath.Join(tlsRoot, "ca.pem"), Certificate: filepath.Join(tlsRoot, "connector.pem"),
			PrivateKey: filepath.Join(tlsRoot, "connector-key.pem"),
		},
	}
	return value, value.Validate()
}
