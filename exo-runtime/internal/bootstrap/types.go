// Package bootstrap compiles and verifies one exact two-node cluster authority.
package bootstrap

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"reach.dev/exo-runtime/internal/authority"
)

const (
	SchemaVersion          = 1
	maxInventoryBytes      = 64 * 1024
	maxManifestBytes       = 1024 * 1024
	commitmentDomain       = "reach-exo-bootstrap-authority-v1"
	commitmentRecordFormat = "{\"schema_version\":1,\"authority_sha256\":\"%s\"}\n"
	fileManifestName       = "FILE-MANIFEST.tsv"
	clusterManifestName    = "cluster-manifest.json"
	prepareName            = "PREPARE.json"
	stagingSuffix          = ".reach-exo-bootstrap-staging"
	quarantineSuffix       = ".reach-exo-bootstrap-quarantine"
)

const (
	BArchiveSHA256        = "66ff6ffc43cd93cb06aded235bb0cf65afd545b0886b29dfb74578dc8f437966"
	BPayloadSHA256        = "eac3f2e414964ae0a444757fb6b65b49a6cf935654296d052ead093807c624a6"
	BMetadataSHA256       = "9e80bc06414cfdcaaa3ac0d72dc0da7efd73112c12c56d82c1d3835ae4f9b865"
	BNodeSHA256           = "298de47d66ec0db12b223fb92a42c400a4f1e1f08955d88c23da2391a841880e"
	BPackageCommandSHA256 = "074964c3c0893e82a31febd4a62016accd262de1b97f49eec49e91f0c381fd41"
	BConnectorSHA256      = "53797f562dd5a8331d04b171b5b1fcb9fdb656a4f5193a68f2750b9026657e0e"
)

var (
	ErrCommitmentCompleteOrUncertain = errors.New("commitment-complete-or-uncertain")
	ErrUncommittedAuthorityRemains   = errors.New("uncommitted-authority-remains")
)

type GatewayMode string

const (
	GatewayDirect GatewayMode = "direct-gateway"
	GatewayTunnel GatewayMode = "loopback-tunnel"
)

type NodeInventory struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Interface  string `json:"interface"`
	MACAddress string `json:"mac_address"`
}

type Inventory struct {
	SchemaVersion     int           `json:"schema_version"`
	Namespace         string        `json:"namespace"`
	AuthorityRoot     string        `json:"authority_root"`
	PrivateNetwork    string        `json:"private_network_cidr"`
	ConnectorAddress  string        `json:"connector_address"`
	GatewayMode       GatewayMode   `json:"gateway_mode"`
	Coordinator       NodeInventory `json:"coordinator"`
	Worker            NodeInventory `json:"worker"`
	CertificateExpiry string        `json:"certificate_expiry"`
}

type PrepareRecord struct {
	SchemaVersion       int    `json:"schema_version"`
	InventorySHA256     string `json:"inventory_sha256"`
	AuthorityRootSHA256 string `json:"authority_root_sha256"`
}

type ExactAuthority struct {
	BundleVersion        string `json:"bundle_version"`
	Architecture         string `json:"architecture"`
	PackageGeneration    string `json:"package_generation"`
	ArchiveSHA256        string `json:"archive_sha256"`
	PayloadSHA256        string `json:"payload_manifest_sha256"`
	MetadataSHA256       string `json:"metadata_sha256"`
	NodeSHA256           string `json:"node_sha256"`
	PackageCommandSHA256 string `json:"package_command_sha256"`
	ConnectorSHA256      string `json:"connector_sha256"`
	EXOVersion           string `json:"exo_version"`
	EXOCommit            string `json:"exo_commit"`
	EXOTree              string `json:"exo_tree"`
	DerivativeSHA256     string `json:"derivative_sha256"`
	PyprojectSHA256      string `json:"pyproject_sha256"`
	UVLockSHA256         string `json:"uv_lock_sha256"`
	MLXVersion           string `json:"mlx_version"`
	MLXCPUVersion        string `json:"mlx_cpu_version"`
	Backend              string `json:"backend"`
	ModelRepository      string `json:"model_repository"`
	ModelSnapshot        string `json:"model_snapshot"`
	ModelManifestSHA256  string `json:"model_manifest_sha256"`
	ModelLayerCount      int    `json:"model_layer_count"`
}

type TopologyNode struct {
	Role           string `json:"role"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	Interface      string `json:"interface"`
	MACAddress     string `json:"mac_address"`
	PeerName       string `json:"peer_name"`
	PeerAddress    string `json:"peer_address"`
	PeerMAC        string `json:"peer_mac"`
	RangeStart     int    `json:"range_start"`
	RangeEnd       int    `json:"range_end"`
	PeerRangeStart int    `json:"peer_range_start"`
	PeerRangeEnd   int    `json:"peer_range_end"`
}

type Topology struct {
	Namespace            string       `json:"namespace"`
	PrivateNetwork       string       `json:"private_network_cidr"`
	ConnectorAddress     string       `json:"connector_address"`
	GatewayMode          GatewayMode  `json:"gateway_mode"`
	GatewayAddress       string       `json:"gateway_address"`
	GatewayServerName    string       `json:"gateway_server_name"`
	ProviderAPIPort      int          `json:"provider_api_port"`
	ProviderZenohPort    int          `json:"provider_zenoh_port"`
	ProviderDiscoverPort int          `json:"provider_discover_port"`
	ControlPort          int          `json:"control_port"`
	GatewayPort          int          `json:"gateway_port"`
	GatewayTunnelPort    int          `json:"gateway_tunnel_port"`
	ConnectorPort        int          `json:"connector_port"`
	Coordinator          TopologyNode `json:"coordinator"`
	Worker               TopologyNode `json:"worker"`
}

type Fingerprints struct {
	CA          string `json:"ca"`
	Coordinator string `json:"coordinator"`
	Worker      string `json:"worker"`
	Connector   string `json:"connector"`
}

type BoundFile struct {
	Path       string `json:"path"`
	Bytes      int64  `json:"bytes"`
	Mode       string `json:"mode"`
	SHA256     string `json:"sha256"`
	Slice      string `json:"slice"`
	TargetPath string `json:"target_path,omitempty"`
	TargetMode string `json:"target_mode,omitempty"`
}

type ClusterManifest struct {
	SchemaVersion        int            `json:"schema_version"`
	BootstrapAuthorityID string         `json:"bootstrap_authority_id"`
	CreatedAt            string         `json:"created_at"`
	CertificateExpiry    string         `json:"certificate_expiry"`
	InventorySHA256      string         `json:"inventory_sha256"`
	AuthorityRootSHA256  string         `json:"authority_root_sha256"`
	Exact                ExactAuthority `json:"exact_authority"`
	Topology             Topology       `json:"topology"`
	TopologySHA256       string         `json:"topology_sha256"`
	Certificates         Fingerprints   `json:"certificate_fingerprints"`
	Files                []BoundFile    `json:"files"`
}

type Verification struct {
	SchemaVersion     int          `json:"schema_version"`
	Valid             bool         `json:"valid"`
	PackageGeneration string       `json:"package_generation"`
	AuthoritySHA256   string       `json:"authority_sha256"`
	Certificates      Fingerprints `json:"certificate_fingerprints"`
}

type CreateResult struct {
	AuthoritySHA256 string
	AcceptedBytes   int
	Commitment      []byte
}

type RecoveryTarget string

const (
	RecoverStaging    RecoveryTarget = "staging"
	RecoverPrepared   RecoveryTarget = "prepared"
	RecoverQuarantine RecoveryTarget = "quarantine"
)

type CommitmentState string

const (
	CommitmentAbsent  CommitmentState = "absent"
	CommitmentPartial CommitmentState = "partial"
)

type dependencies struct {
	now  func() time.Time
	rand io.Reader
	hook func(string) error
}

func productionDependencies() dependencies {
	return dependencies{now: time.Now, rand: nil, hook: func(string) error { return nil }}
}

func (d dependencies) reach(point string) error {
	if d.hook == nil {
		return nil
	}
	return d.hook(point)
}

func exactAuthority() ExactAuthority {
	return ExactAuthority{
		BundleVersion: authority.BundleVersion, Architecture: authority.Architecture,
		PackageGeneration: authority.PackageGeneration,
		ArchiveSHA256:     BArchiveSHA256, PayloadSHA256: BPayloadSHA256,
		MetadataSHA256: BMetadataSHA256, NodeSHA256: BNodeSHA256,
		PackageCommandSHA256: BPackageCommandSHA256, ConnectorSHA256: BConnectorSHA256,
		EXOVersion: authority.EXOVersion, EXOCommit: authority.EXOCommit, EXOTree: authority.EXOTree,
		DerivativeSHA256: authority.DerivativeSHA256, PyprojectSHA256: authority.PyprojectSHA256, UVLockSHA256: authority.UVLockSHA256,
		MLXVersion: "0.32.0", MLXCPUVersion: "0.32.0", Backend: authority.Backend,
		ModelRepository: authority.ModelID, ModelSnapshot: authority.ModelSnapshot,
		ModelManifestSHA256: authority.ModelManifestSHA256, ModelLayerCount: authority.ModelLayerCount,
	}
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func constantTimeDigestEqual(left, right string) bool {
	if !validLowerSHA256(left) || !validLowerSHA256(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func deterministicPaths(root string) (string, string) {
	parent, base := filepath.Dir(root), filepath.Base(root)
	return filepath.Join(parent, "."+base+stagingSuffix), filepath.Join(parent, "."+base+quarantineSuffix)
}
