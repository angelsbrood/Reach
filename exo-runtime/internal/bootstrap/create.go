package bootstrap

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type authorityMetadata struct {
	SchemaVersion int            `json:"schema_version"`
	AuthorityID   string         `json:"bootstrap_authority_id"`
	CreatedAt     string         `json:"created_at"`
	ExpiresAt     string         `json:"certificate_expiry"`
	Exact         ExactAuthority `json:"exact_authority"`
}

type preparedFile struct {
	Path       string
	Data       []byte
	Slice      string
	TargetPath string
	TargetMode string
}

func Create(inventory Inventory, inventoryDigest string, output io.Writer) (CreateResult, error) {
	return createWithDependencies(inventory, inventoryDigest, output, productionDependencies())
}

func createWithDependencies(inventory Inventory, inventoryDigest string, output io.Writer, deps dependencies) (result CreateResult, returnErr error) {
	if output == nil || !validLowerSHA256(inventoryDigest) {
		return CreateResult{}, errors.New("output and canonical inventory digest are required")
	}
	now := deps.now().UTC().Truncate(time.Second)
	if err := inventory.Validate(now); err != nil {
		return CreateResult{}, err
	}
	_, canonicalDigest, err := canonicalInventory(inventory)
	if err != nil || !constantTimeDigestEqual(canonicalDigest, inventoryDigest) {
		return CreateResult{}, errors.New("supplied inventory digest does not match canonical inventory")
	}
	if err := validatePublicationParent(inventory.AuthorityRoot); err != nil {
		return CreateResult{}, err
	}
	root := inventory.AuthorityRoot
	staging, quarantine := deterministicPaths(root)
	if err := ensureAbsent(root, staging, quarantine); err != nil {
		return CreateResult{}, err
	}
	if err := deps.reach("before-staging-directory"); err != nil {
		return CreateResult{}, err
	}
	if err := os.Mkdir(staging, 0700); err != nil {
		return CreateResult{}, err
	}
	createdStageInfo, err := os.Lstat(staging)
	if err != nil {
		return CreateResult{}, err
	}
	stageExists := true
	published := false
	defer func() {
		if returnErr == nil || !stageExists {
			return
		}
		target := staging
		if published {
			target = root
		}
		if cleanupErr := quarantineAndRemoveExpected(target, quarantine, deps, createdStageInfo); cleanupErr != nil {
			remaining := quarantine
			if _, statErr := os.Lstat(quarantine); errors.Is(statErr, os.ErrNotExist) {
				remaining = target
			}
			returnErr = fmt.Errorf("%w: original failure: %v; cleanup failure: %v; manual disposition: %s", ErrUncommittedAuthorityRemains, returnErr, cleanupErr, remaining)
		}
		stageExists = false
	}()
	if err := deps.reach("after-staging-directory"); err != nil {
		return CreateResult{}, err
	}
	stageRoot, err := os.OpenRoot(staging)
	if err != nil {
		return CreateResult{}, err
	}
	openedStageInfo, err := stageRoot.Stat(".")
	currentStageInfo, currentStageErr := os.Lstat(staging)
	if err != nil || currentStageErr != nil || !os.SameFile(createdStageInfo, openedStageInfo) || !os.SameFile(createdStageInfo, currentStageInfo) {
		_ = stageRoot.Close()
		return CreateResult{}, errors.New("staging directory identity changed before preparation")
	}
	defer func() {
		if stageRoot != nil {
			_ = stageRoot.Close()
		}
	}()
	if err := syncDirectory(filepath.Dir(root), deps, "publication-parent-after-staging"); err != nil {
		return CreateResult{}, err
	}
	rootDigest := sha256.Sum256([]byte(root))
	prepare := PrepareRecord{SchemaVersion: SchemaVersion, InventorySHA256: inventoryDigest, AuthorityRootSHA256: hex.EncodeToString(rootDigest[:])}
	prepareBytes, err := marshalJSON(prepare)
	if err != nil {
		return CreateResult{}, err
	}
	if err := writePrivateFileAt(stageRoot, prepareName, prepareBytes, deps, "prepare"); err != nil {
		return CreateResult{}, err
	}
	if err := syncDirectory(staging, deps, "prepare-durable"); err != nil {
		return CreateResult{}, err
	}
	if err := deps.reach("after-durable-prepare"); err != nil {
		return CreateResult{}, err
	}
	reader := deps.rand
	authorityIDBytes := make([]byte, 16)
	if reader == nil {
		reader = cryptorand.Reader
	}
	if _, err := io.ReadFull(reader, authorityIDBytes); err != nil {
		return CreateResult{}, err
	}
	authorityID := hex.EncodeToString(authorityIDBytes)
	expiresAt, _ := time.Parse(time.RFC3339, inventory.CertificateExpiry)
	certificates, err := issueCertificates(reader, now, expiresAt, authorityID)
	if err != nil {
		return CreateResult{}, err
	}
	topology := deriveTopology(inventory)
	topologySHA, err := topologyDigest(topology)
	if err != nil {
		return CreateResult{}, err
	}
	coordinator, err := nodeConfiguration(topology, "coordinator")
	if err != nil {
		return CreateResult{}, err
	}
	worker, err := nodeConfiguration(topology, "worker")
	if err != nil {
		return CreateResult{}, err
	}
	connector, err := connectorConfiguration(root, topology)
	if err != nil {
		return CreateResult{}, err
	}
	metadata := authorityMetadata{SchemaVersion: SchemaVersion, AuthorityID: authorityID, CreatedAt: now.Format(time.RFC3339), ExpiresAt: inventory.CertificateExpiry, Exact: exactAuthority()}
	metadataBytes, _ := marshalJSON(metadata)
	coordinatorBytes, _ := marshalJSON(coordinator)
	workerBytes, _ := marshalJSON(worker)
	connectorBytes, _ := marshalJSON(connector)
	files := []preparedFile{
		{Path: "operator/authority.json", Data: metadataBytes, Slice: "operator"},
		{Path: "operator/tls/ca.pem", Data: certificates.CA.CertificatePEM, Slice: "operator"},
		{Path: "operator/tls/ca-key.pem", Data: certificates.CA.PrivateKeyPEM, Slice: "operator"},
		{Path: "coordinator/etc/reach-exo/node.json", Data: coordinatorBytes, Slice: "coordinator", TargetPath: "/etc/reach-exo/node.json", TargetMode: "0640"},
		{Path: "coordinator/etc/reach-exo/tls/ca.pem", Data: certificates.CA.CertificatePEM, Slice: "coordinator", TargetPath: "/etc/reach-exo/tls/ca.pem", TargetMode: "0644"},
		{Path: "coordinator/etc/reach-exo/tls/coordinator.pem", Data: certificates.Coordinator.CertificatePEM, Slice: "coordinator", TargetPath: "/etc/reach-exo/tls/coordinator.pem", TargetMode: "0644"},
		{Path: "coordinator/etc/reach-exo/tls/coordinator-key.pem", Data: certificates.Coordinator.PrivateKeyPEM, Slice: "coordinator", TargetPath: "/etc/reach-exo/tls/coordinator-key.pem", TargetMode: "0640"},
		{Path: "worker/etc/reach-exo/node.json", Data: workerBytes, Slice: "worker", TargetPath: "/etc/reach-exo/node.json", TargetMode: "0640"},
		{Path: "worker/etc/reach-exo/tls/ca.pem", Data: certificates.CA.CertificatePEM, Slice: "worker", TargetPath: "/etc/reach-exo/tls/ca.pem", TargetMode: "0644"},
		{Path: "worker/etc/reach-exo/tls/worker.pem", Data: certificates.Worker.CertificatePEM, Slice: "worker", TargetPath: "/etc/reach-exo/tls/worker.pem", TargetMode: "0644"},
		{Path: "worker/etc/reach-exo/tls/worker-key.pem", Data: certificates.Worker.PrivateKeyPEM, Slice: "worker", TargetPath: "/etc/reach-exo/tls/worker-key.pem", TargetMode: "0640"},
		{Path: "connector/connector.json", Data: connectorBytes, Slice: "connector", TargetPath: filepath.Join(root, "connector", "connector.json"), TargetMode: "0600"},
		{Path: "connector/tls/ca.pem", Data: certificates.CA.CertificatePEM, Slice: "connector", TargetPath: filepath.Join(root, "connector", "tls", "ca.pem"), TargetMode: "0644"},
		{Path: "connector/tls/connector.pem", Data: certificates.Connector.CertificatePEM, Slice: "connector", TargetPath: filepath.Join(root, "connector", "tls", "connector.pem"), TargetMode: "0644"},
		{Path: "connector/tls/connector-key.pem", Data: certificates.Connector.PrivateKeyPEM, Slice: "connector", TargetPath: filepath.Join(root, "connector", "tls", "connector-key.pem"), TargetMode: "0600"},
	}
	directories := authorityDirectoryOrder()
	if err := makePrivateDirectoriesAt(stageRoot, directories, deps); err != nil {
		return CreateResult{}, err
	}
	paths := authorityPayloadFileOrder()
	if len(files) != len(paths) {
		return CreateResult{}, errors.New("internal prepared-file grammar differs")
	}
	for index := range files {
		if files[index].Path != paths[index] {
			return CreateResult{}, errors.New("internal prepared-file order differs from recovery grammar")
		}
	}
	var bound []BoundFile
	prepareDigest := sha256.Sum256(prepareBytes)
	bound = append(bound, BoundFile{Path: prepareName, Bytes: int64(len(prepareBytes)), Mode: "0600", SHA256: hex.EncodeToString(prepareDigest[:]), Slice: "provenance"})
	for _, file := range files {
		if err := writePrivateFileAt(stageRoot, file.Path, file.Data, deps, file.Path); err != nil {
			return CreateResult{}, err
		}
		digest := sha256.Sum256(file.Data)
		bound = append(bound, BoundFile{Path: file.Path, Bytes: int64(len(file.Data)), Mode: "0600", SHA256: hex.EncodeToString(digest[:]), Slice: file.Slice, TargetPath: file.TargetPath, TargetMode: file.TargetMode})
	}
	sort.Slice(bound, func(i, j int) bool { return bound[i].Path < bound[j].Path })
	fingerprints := Fingerprints{CA: certificates.CA.Fingerprint, Coordinator: certificates.Coordinator.Fingerprint, Worker: certificates.Worker.Fingerprint, Connector: certificates.Connector.Fingerprint}
	manifest := ClusterManifest{
		SchemaVersion: SchemaVersion, BootstrapAuthorityID: authorityID, CreatedAt: now.Format(time.RFC3339), CertificateExpiry: inventory.CertificateExpiry,
		InventorySHA256: inventoryDigest, AuthorityRootSHA256: prepare.AuthorityRootSHA256,
		Exact: exactAuthority(), Topology: topology, TopologySHA256: topologySHA, Certificates: fingerprints, Files: bound,
	}
	manifestBytes, err := marshalJSON(manifest)
	if err != nil {
		return CreateResult{}, err
	}
	if err := writePrivateFileAt(stageRoot, clusterManifestName, manifestBytes, deps, "cluster-manifest"); err != nil {
		return CreateResult{}, err
	}
	fileManifestBytes, _, err := buildFileManifest(staging)
	if err != nil {
		return CreateResult{}, err
	}
	if err := writePrivateFileAt(stageRoot, fileManifestName, fileManifestBytes, deps, "file-manifest"); err != nil {
		return CreateResult{}, err
	}
	if err := syncTreeDirectories(staging, deps); err != nil {
		return CreateResult{}, err
	}
	fileManifestSHA := sha256.Sum256(fileManifestBytes)
	authoritySHA := authorityDigest(inventoryDigest, root, exactAuthority(), topologySHA, fingerprints, hex.EncodeToString(fileManifestSHA[:]))
	completedStageInfo, err := stageRoot.Stat(".")
	if err != nil || !os.SameFile(createdStageInfo, completedStageInfo) {
		return CreateResult{}, errors.New("staging directory identity changed during preparation")
	}
	if err := stageRoot.Close(); err != nil {
		return CreateResult{}, err
	}
	stageRoot = nil
	if err := deps.reach("before-publication-rename"); err != nil {
		return CreateResult{}, err
	}
	if err := os.Rename(staging, root); err != nil {
		return CreateResult{}, err
	}
	published = true
	if err := deps.reach("after-publication-rename"); err != nil {
		return CreateResult{}, err
	}
	publishedInfo, err := os.Lstat(root)
	if err != nil || !os.SameFile(createdStageInfo, publishedInfo) {
		return CreateResult{}, errors.New("published authority identity differs from prepared tree")
	}
	if err := syncDirectory(filepath.Dir(root), deps, "publication-parent-after-rename"); err != nil {
		return CreateResult{}, err
	}
	publishedInfo, err = os.Lstat(root)
	if err != nil || !os.SameFile(createdStageInfo, publishedInfo) {
		return CreateResult{}, errors.New("published authority identity changed before commitment")
	}
	if err := deps.reach("before-commitment-output"); err != nil {
		return CreateResult{}, err
	}
	commitment := []byte(fmt.Sprintf(commitmentRecordFormat, authoritySHA))
	accepted, writeErr := writeCommitment(output, commitment, deps)
	result = CreateResult{AuthoritySHA256: authoritySHA, AcceptedBytes: accepted, Commitment: commitment}
	if accepted == len(commitment) {
		stageExists = false
		if writeErr != nil {
			return result, fmt.Errorf("%w: %v", ErrCommitmentCompleteOrUncertain, writeErr)
		}
		if err := deps.reach("after-complete-commitment"); err != nil {
			return result, fmt.Errorf("%w: %v", ErrCommitmentCompleteOrUncertain, err)
		}
		return result, nil
	}
	return result, fmt.Errorf("commitment delivery failed after %d of %d bytes: %w", accepted, len(commitment), writeErr)
}

func marshalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writeCommitment(output io.Writer, record []byte, deps dependencies) (int, error) {
	accepted := 0
	for accepted < len(record) {
		if err := deps.reach(fmt.Sprintf("before-commitment-write:%d", accepted)); err != nil {
			return accepted, err
		}
		count, err := output.Write(record[accepted:])
		if count < 0 || count > len(record)-accepted {
			return accepted, errors.New("commitment writer returned invalid count")
		}
		accepted += count
		if hookErr := deps.reach(fmt.Sprintf("after-commitment-write:%d", accepted)); hookErr != nil {
			if err == nil {
				err = hookErr
			}
		}
		if err != nil {
			return accepted, err
		}
		if count == 0 {
			return accepted, io.ErrNoProgress
		}
	}
	return accepted, nil
}
