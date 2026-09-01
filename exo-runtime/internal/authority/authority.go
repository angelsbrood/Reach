// Package authority contains the immutable identities admitted by the S47 bundle.
package authority

const (
	BundleVersion         = "0.2.0"
	ParentBundleVersion   = "0.1.0"
	Architecture          = "linux-arm64"
	PackageGeneration     = "reach-exo-lifecycle/0.2.0/linux-arm64/parent-0.1.0"
	ParentNodeSHA256      = "e6d04335313d8949bec2362abc8701de0fe24f9547377a8d43024e8ea8bd033f"
	ParentConnectorSHA256 = "53797f562dd5a8331d04b171b5b1fcb9fdb656a4f5193a68f2750b9026657e0e"
	ParentPackageSHA256   = "fe3a5e334ea89f30487bba02bfbd749ad9a8c51736cda35699aedc7b1eb5e138"
	ParentPayloadSHA256   = "2e8ac39eb950212dd6bb6200459ef15c16d94d88a5194556780f7e033b2a2e27"
	ParentMetadataSHA256  = "2549bb3dc7d368b7b6fd9fdb62b1c940f7166ba2c1648a56a67321e6b3a54ef4"
	SchemaVersion         = 1
	EXOVersion            = "0.3.70"
	EXOCommit             = "21a54c5ea0230a3bec1e1a786d200126c7e34ec6"
	EXOTree               = "ff0204b2a02506a15cda8abbdcbed25663c89403"
	DerivativeSHA256      = "6c3094908c689789ac02b9bd126d05b6fe2f6baa74502a05446899a775266bb7"
	PyprojectSHA256       = "35b3e83937d745e1a6393932015a58b9c98046fcbe4b205631a617e66e5517aa"
	UVLockSHA256          = "564c3c0c8b00a5c463f7d3d1d9d89750e5dd1fd48ec014341758393626fabd3d"
	ModelID               = "mlx-community/Qwen3-0.6B-4bit"
	ModelSnapshot         = "73e3e38d981303bc594367cd910ea6eb48349da8"
	ModelManifestSHA256   = "b8bbc65028022f822f9234e04137470d7c6b56fa5bebe32285b7217e47d21629"
	ModelFileCount        = 11
	ModelByteCount        = int64(351386061)
	ModelLayerCount       = 28
	Backend               = "MlxCpu"
	ProviderAPIPort       = 52415
	ProviderZenohPort     = 52414
	ProviderDiscoverPort  = 52413
	ControlPort           = 53420
	GatewayPort           = 53421
	GatewayTunnelPort     = 53422
	ConnectorPort         = 52415
	ServiceUser           = "reach-exo"
	ProgramRoot           = "/opt/reach-exo"
	ConfigRoot            = "/etc/reach-exo"
	ModelRoot             = "/srv/reach-exo-models"
	StateRoot             = "/var/lib/reach-exo"
	RuntimeRoot           = "/run/reach-exo"
	TransactionRoot       = "/var/lib/reach-exo-transaction"
	TransactionLock       = "/run/lock/reach-exo-package.lock"
)
