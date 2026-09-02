package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"reach.dev/exo-runtime/internal/config"
)

func authorityDirectoryOrder() []string {
	return []string{
		"operator", "operator/tls",
		"coordinator", "coordinator/etc", "coordinator/etc/reach-exo", "coordinator/etc/reach-exo/tls",
		"worker", "worker/etc", "worker/etc/reach-exo", "worker/etc/reach-exo/tls",
		"connector", "connector/tls",
	}
}

func authorityPayloadFileOrder() []string {
	return []string{
		"operator/authority.json", "operator/tls/ca.pem", "operator/tls/ca-key.pem",
		"coordinator/etc/reach-exo/node.json", "coordinator/etc/reach-exo/tls/ca.pem", "coordinator/etc/reach-exo/tls/coordinator.pem", "coordinator/etc/reach-exo/tls/coordinator-key.pem",
		"worker/etc/reach-exo/node.json", "worker/etc/reach-exo/tls/ca.pem", "worker/etc/reach-exo/tls/worker.pem", "worker/etc/reach-exo/tls/worker-key.pem",
		"connector/connector.json", "connector/tls/ca.pem", "connector/tls/connector.pem", "connector/tls/connector-key.pem",
	}
}

func exactAuthorityDirectorySet() map[string]bool {
	result := map[string]bool{".": true}
	for _, path := range authorityDirectoryOrder() {
		result[path] = true
	}
	return result
}

func exactAuthorityFileSet(root string) map[string]bool {
	result := make(map[string]bool, len(expectedBoundFiles(root))+2)
	for path := range expectedBoundFiles(root) {
		result[path] = true
	}
	result[clusterManifestName] = true
	result[fileManifestName] = true
	return result
}

func authorityCreationOrder() []string {
	result := []string{prepareName}
	for _, path := range authorityDirectoryOrder() {
		result = append(result, path+"/")
	}
	result = append(result, authorityPayloadFileOrder()...)
	result = append(result, clusterManifestName, fileManifestName)
	return result
}

func Recover(inventory Inventory, inventoryDigest string, target RecoveryTarget, state CommitmentState, confirmed bool) error {
	return recoverWithDependencies(inventory, inventoryDigest, target, state, confirmed, productionDependencies())
}

func recoverWithDependencies(inventory Inventory, inventoryDigest string, target RecoveryTarget, state CommitmentState, confirmed bool, deps dependencies) error {
	if !confirmed {
		return errors.New("explicit --confirm-discard-uncommitted is required")
	}
	if state != CommitmentAbsent && state != CommitmentPartial {
		return errors.New("commitment state must be absent or partial; complete must be verified")
	}
	if !validLowerSHA256(inventoryDigest) || !validRootSpelling(inventory.AuthorityRoot) {
		return errors.New("valid inventory authority is required")
	}
	expiry, err := time.Parse(time.RFC3339, inventory.CertificateExpiry)
	if err != nil || inventory.Validate(expiry.Add(-24*time.Hour)) != nil {
		return errors.New("strict recovery inventory is invalid")
	}
	_, canonicalDigest, err := canonicalInventory(inventory)
	if err != nil || !constantTimeDigestEqual(canonicalDigest, inventoryDigest) {
		return errors.New("supplied inventory digest does not match canonical inventory")
	}
	if target == RecoverStaging && state != CommitmentAbsent {
		return errors.New("staging recovery requires absent commitment state")
	}
	if target != RecoverStaging && target != RecoverPrepared && target != RecoverQuarantine {
		return errors.New("recovery target must be staging, prepared, or quarantine")
	}
	if err := validatePublicationParent(inventory.AuthorityRoot); err != nil {
		return err
	}
	staging, quarantine := deterministicPaths(inventory.AuthorityRoot)
	path := quarantine
	if target == RecoverStaging {
		path = staging
	} else if target == RecoverPrepared {
		path = inventory.AuthorityRoot
	}
	if err := validateRecoveryTarget(path, inventory, inventoryDigest, target); err != nil {
		return fmt.Errorf("manual disposition required for %s: %w", path, err)
	}
	targetInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if target != RecoverQuarantine {
		if err := ensureAbsent(quarantine); err != nil {
			return fmt.Errorf("conflicting quarantine blocks recovery: %w", err)
		}
		if err := deps.reach("before-recovery-rename:" + string(target)); err != nil {
			return err
		}
		if err := validateRecoveryTarget(path, inventory, inventoryDigest, target); err != nil {
			return fmt.Errorf("manual disposition required for %s after pre-rename revalidation: %w", path, err)
		}
		if err := os.Rename(path, quarantine); err != nil {
			return err
		}
		quarantineInfo, statErr := os.Lstat(quarantine)
		if statErr != nil || !os.SameFile(targetInfo, quarantineInfo) {
			return errors.New("recovery target identity changed during quarantine rename")
		}
		if err := deps.reach("after-recovery-rename:" + string(target)); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(quarantine), deps, "recovery-parent-after-rename"); err != nil {
			return err
		}
	}
	return removeQuarantine(quarantine, deps)
}

func quarantineAndRemove(target, quarantine string, deps dependencies) error {
	return quarantineAndRemoveExpected(target, quarantine, deps, nil)
}

func quarantineAndRemoveExpected(target, quarantine string, deps dependencies, expected os.FileInfo) error {
	if err := ensureAbsent(quarantine); err != nil {
		return err
	}
	if err := validateOwnedTree(target, true); err != nil {
		return err
	}
	shape, err := observedAuthorityShape(target)
	if err != nil {
		return err
	}
	if err := validateStagingShape(shape); err != nil {
		return err
	}
	targetInfo, err := os.Lstat(target)
	if err != nil || (expected != nil && !os.SameFile(expected, targetInfo)) {
		return errors.New("cleanup target identity differs from the attributable tree")
	}
	if err := deps.reach("before-cleanup-rename"); err != nil {
		return err
	}
	if err := validateOwnedTree(target, true); err != nil {
		return err
	}
	shape, err = observedAuthorityShape(target)
	if err != nil {
		return err
	}
	if err := validateStagingShape(shape); err != nil {
		return err
	}
	if err := os.Rename(target, quarantine); err != nil {
		return err
	}
	quarantineInfo, statErr := os.Lstat(quarantine)
	if statErr != nil || !os.SameFile(targetInfo, quarantineInfo) {
		return errors.New("cleanup target identity changed during quarantine rename")
	}
	if err := deps.reach("after-cleanup-rename"); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(quarantine), deps, "cleanup-parent-after-rename"); err != nil {
		return err
	}
	return removeQuarantine(quarantine, deps)
}

func validateRecoveryTarget(path string, inventory Inventory, inventoryDigest string, target RecoveryTarget) error {
	if err := validateOwnedTree(path, true); err != nil {
		return err
	}
	shape, err := observedAuthorityShape(path)
	if err != nil {
		return err
	}
	if target == RecoverStaging {
		if err := validateStagingShape(shape); err != nil {
			return err
		}
	} else if target == RecoverQuarantine {
		if err := validateQuarantineShape(shape); err != nil {
			return err
		}
	} else if err := validateCompleteAuthorityShape(shape); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if target == RecoverPrepared {
			return errors.New("an empty prepared target lacks a complete cluster manifest")
		}
		return nil
	}
	prepare, err := readStrictJSON[PrepareRecord](filepath.Join(path, prepareName), 4096)
	if err != nil {
		return fmt.Errorf("matching PREPARE.json is absent: %w", err)
	}
	rootDigest := digestString(inventory.AuthorityRoot)
	if prepare.SchemaVersion != SchemaVersion || prepare.InventorySHA256 != inventoryDigest || prepare.AuthorityRootSHA256 != rootDigest {
		return errors.New("PREPARE.json does not match supplied inventory and authority root")
	}
	if err := validateRecoveryContents(path, inventory, inventoryDigest, shape); err != nil {
		return err
	}
	if target == RecoverPrepared {
		if !shape[clusterManifestName] || !shape[fileManifestName] {
			return errors.New("prepared tree lacks both complete manifests")
		}
	}
	return nil
}

func validateRecoveryContents(treeRoot string, inventory Inventory, inventoryDigest string, shape map[string]bool) error {
	if shape[clusterManifestName] {
		return validateRecoveryClusterManifest(treeRoot, inventory, inventoryDigest, shape[fileManifestName])
	}
	if shape[fileManifestName] {
		return errors.New("file manifest exists without its cluster manifest")
	}
	if shape["operator/authority.json"] {
		metadata, err := readStrictJSON[authorityMetadata](filepath.Join(treeRoot, "operator/authority.json"), 64*1024)
		if err != nil || metadata.SchemaVersion != SchemaVersion || metadata.Exact != exactAuthority() || metadata.ExpiresAt != inventory.CertificateExpiry || !validAuthorityID(metadata.AuthorityID) || !canonicalUTCTime(metadata.CreatedAt) || !canonicalUTCTime(metadata.ExpiresAt) {
			return errors.New("surviving operator metadata is damaged")
		}
	}
	topology := deriveTopology(inventory)
	for _, item := range []struct {
		path string
		role string
	}{
		{"coordinator/etc/reach-exo/node.json", "coordinator"},
		{"worker/etc/reach-exo/node.json", "worker"},
	} {
		if !shape[item.path] {
			continue
		}
		data, err := readPrivateFile(filepath.Join(treeRoot, filepath.FromSlash(item.path)), maxManifestBytes)
		if err != nil {
			return err
		}
		var expected any
		if item.role == "coordinator" {
			expected, _ = nodeConfiguration(topology, "coordinator")
		} else {
			expected, _ = nodeConfiguration(topology, "worker")
		}
		decoded, err := config.DecodeNode(data)
		if err != nil || !reflect.DeepEqual(decoded, expected) {
			return fmt.Errorf("surviving %s configuration is damaged", item.role)
		}
	}
	if shape["connector/connector.json"] {
		data, err := readPrivateFile(filepath.Join(treeRoot, "connector/connector.json"), maxManifestBytes)
		if err != nil {
			return err
		}
		decoded, err := config.DecodeConnector(data)
		expected, _ := connectorConfiguration(inventory.AuthorityRoot, topology)
		if err != nil || !reflect.DeepEqual(decoded, expected) {
			return errors.New("surviving connector configuration is damaged")
		}
	}
	return validateRecoveryPEMObjects(treeRoot, shape, inventory)
}

func validateRecoveryClusterManifest(treeRoot string, inventory Inventory, inventoryDigest string, hasFileManifest bool) error {
	manifest, err := readStrictJSON[ClusterManifest](filepath.Join(treeRoot, clusterManifestName), maxManifestBytes)
	if err != nil {
		return fmt.Errorf("complete cluster manifest is damaged: %w", err)
	}
	createdAt, createdErr := time.Parse(time.RFC3339, manifest.CreatedAt)
	expiresAt, expiryErr := time.Parse(time.RFC3339, manifest.CertificateExpiry)
	if manifest.SchemaVersion != SchemaVersion || manifest.Exact != exactAuthority() || manifest.InventorySHA256 != inventoryDigest || manifest.AuthorityRootSHA256 != digestString(inventory.AuthorityRoot) || createdErr != nil || expiryErr != nil || !canonicalUTCTime(manifest.CreatedAt) || !canonicalUTCTime(manifest.CertificateExpiry) || !validAuthorityID(manifest.BootstrapAuthorityID) || !expiresAt.Equal(mustParseTime(inventory.CertificateExpiry)) {
		return errors.New("complete cluster manifest authority fields differ")
	}
	if !reflect.DeepEqual(inventoryFromManifest(inventory.AuthorityRoot, manifest), inventory) {
		return errors.New("complete cluster manifest inventory differs")
	}
	derivedTopology := deriveTopology(inventory)
	topologySHA, err := topologyDigest(manifest.Topology)
	if err != nil || !reflect.DeepEqual(manifest.Topology, derivedTopology) || topologySHA != manifest.TopologySHA256 {
		return errors.New("complete cluster manifest topology differs")
	}
	metadata, err := readStrictJSON[authorityMetadata](filepath.Join(treeRoot, "operator/authority.json"), 64*1024)
	if err != nil || metadata.SchemaVersion != SchemaVersion || metadata.AuthorityID != manifest.BootstrapAuthorityID || metadata.CreatedAt != manifest.CreatedAt || metadata.ExpiresAt != manifest.CertificateExpiry || metadata.Exact != exactAuthority() {
		return errors.New("complete cluster manifest metadata differs")
	}
	if err := verifyBoundFiles(treeRoot, inventory.AuthorityRoot, manifest.Files); err != nil {
		return err
	}
	if err := verifyConfigurations(treeRoot, inventory.AuthorityRoot, manifest.Topology); err != nil {
		return err
	}
	fingerprints, err := verifyCertificates(treeRoot, manifest, createdAt)
	if err != nil || fingerprints != manifest.Certificates {
		return errors.New("complete cluster manifest certificate authority differs")
	}
	if hasFileManifest {
		fileManifestBytes, err := readPrivateFile(filepath.Join(treeRoot, fileManifestName), maxManifestBytes)
		if err != nil {
			return err
		}
		entries, err := parseFileManifest(fileManifestBytes)
		if err != nil {
			return err
		}
		if err := verifyFileManifestCoverage(treeRoot, entries); err != nil {
			return err
		}
	}
	return nil
}

func validateRecoveryPEMObjects(treeRoot string, shape map[string]bool, inventory Inventory) error {
	certificatePaths := []string{
		"operator/tls/ca.pem", "coordinator/etc/reach-exo/tls/ca.pem", "coordinator/etc/reach-exo/tls/coordinator.pem",
		"worker/etc/reach-exo/tls/ca.pem", "worker/etc/reach-exo/tls/worker.pem", "connector/tls/ca.pem", "connector/tls/connector.pem",
	}
	certificates := map[string]*x509.Certificate{}
	for _, path := range certificatePaths {
		if !shape[path] {
			continue
		}
		data, err := readPrivateFile(filepath.Join(treeRoot, filepath.FromSlash(path)), maxManifestBytes)
		if err != nil {
			return err
		}
		certificate, err := parseCertificate(data)
		if err != nil {
			return fmt.Errorf("surviving certificate %s is damaged", path)
		}
		if strings.HasSuffix(path, "/ca.pem") {
			if err := validateRecoveryCA(certificate, inventory.CertificateExpiry); err != nil {
				return fmt.Errorf("surviving CA certificate %s is damaged", path)
			}
		} else if err := validateRecoveryLeaf(certificate, path, inventory.CertificateExpiry); err != nil {
			return fmt.Errorf("surviving leaf certificate %s is damaged", path)
		}
		certificates[path] = certificate
	}
	logicalPublicKeys := map[string]string{}
	registerLogicalRole := func(role string, certificate *x509.Certificate) error {
		publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if err != nil {
			return fmt.Errorf("surviving %s certificate public key is malformed", role)
		}
		digest := sha256.Sum256(publicKey)
		identifier := hex.EncodeToString(digest[:])
		if existing, ok := logicalPublicKeys[identifier]; ok {
			return fmt.Errorf("surviving logical roles %s and %s reuse one public key", existing, role)
		}
		logicalPublicKeys[identifier] = role
		return nil
	}
	var survivingCA *x509.Certificate
	for _, path := range []string{"operator/tls/ca.pem", "coordinator/etc/reach-exo/tls/ca.pem", "worker/etc/reach-exo/tls/ca.pem", "connector/tls/ca.pem"} {
		if certificate := certificates[path]; certificate != nil {
			if survivingCA == nil {
				survivingCA = certificate
			} else if !bytes.Equal(certificate.Raw, survivingCA.Raw) {
				return fmt.Errorf("surviving CA copy differs at %s", path)
			}
		}
	}
	if survivingCA != nil {
		if err := registerLogicalRole("ca", survivingCA); err != nil {
			return err
		}
	}
	leafIdentitySurvives := false
	for _, path := range []string{
		"coordinator/etc/reach-exo/tls/coordinator.pem", "coordinator/etc/reach-exo/tls/coordinator-key.pem",
		"worker/etc/reach-exo/tls/worker.pem", "worker/etc/reach-exo/tls/worker-key.pem",
		"connector/tls/connector.pem", "connector/tls/connector-key.pem",
	} {
		leafIdentitySurvives = leafIdentitySurvives || shape[path]
	}
	if leafIdentitySurvives && survivingCA == nil {
		return errors.New("surviving leaf identity lacks an authenticated CA certificate witness")
	}
	for _, role := range []struct {
		name string
		path string
	}{
		{"coordinator", "coordinator/etc/reach-exo/tls/coordinator.pem"},
		{"worker", "worker/etc/reach-exo/tls/worker.pem"},
		{"connector", "connector/tls/connector.pem"},
	} {
		certificate := certificates[role.path]
		if certificate == nil {
			continue
		}
		if err := registerLogicalRole(role.name, certificate); err != nil {
			return err
		}
		if survivingCA != nil && certificate.CheckSignatureFrom(survivingCA) != nil {
			return fmt.Errorf("surviving leaf issuer differs at %s", role.path)
		}
	}
	keyPairs := []struct {
		certificate string
		key         string
	}{
		{"operator/tls/ca.pem", "operator/tls/ca-key.pem"},
		{"coordinator/etc/reach-exo/tls/coordinator.pem", "coordinator/etc/reach-exo/tls/coordinator-key.pem"},
		{"worker/etc/reach-exo/tls/worker.pem", "worker/etc/reach-exo/tls/worker-key.pem"},
		{"connector/tls/connector.pem", "connector/tls/connector-key.pem"},
	}
	for _, pair := range keyPairs {
		if !shape[pair.key] {
			continue
		}
		data, err := readPrivateFile(filepath.Join(treeRoot, filepath.FromSlash(pair.key)), maxManifestBytes)
		if err != nil {
			return err
		}
		key, err := parsePrivateKey(data)
		if err != nil {
			return fmt.Errorf("surviving private key %s is damaged", pair.key)
		}
		if certificate := certificates[pair.certificate]; certificate == nil || !publicKeysEqual(certificate.PublicKey, &key.PublicKey) {
			return fmt.Errorf("surviving certificate/key relationship differs at %s", pair.key)
		}
	}
	return nil
}

func validateRecoveryCA(certificate *x509.Certificate, expiry string) error {
	expiresAt, err := time.Parse(time.RFC3339, expiry)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 || certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 || len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 || len(certificate.UnhandledCriticalExtensions) != 0 || certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 || !strings.HasPrefix(certificate.Subject.CommonName, "reach-exo-bootstrap-ca-") || !exactCommonName(certificate.Subject, certificate.Subject.CommonName) || !exactCommonName(certificate.Issuer, certificate.Subject.CommonName) || certificate.CheckSignatureFrom(certificate) != nil || !certificate.NotAfter.Equal(expiresAt) || !certificate.NotBefore.Before(certificate.NotAfter) {
		return errors.New("CA profile differs")
	}
	return nil
}

func validateRecoveryLeaf(certificate *x509.Certificate, path, expiry string) error {
	expiresAt, err := time.Parse(time.RFC3339, expiry)
	if err != nil || certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage != x509.KeyUsageDigitalSignature || certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 || !strings.HasPrefix(certificate.Issuer.CommonName, "reach-exo-bootstrap-ca-") || !exactCommonName(certificate.Issuer, certificate.Issuer.CommonName) || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 || len(certificate.UnknownExtKeyUsage) != 0 || len(certificate.UnhandledCriticalExtensions) != 0 || !certificate.NotAfter.Equal(expiresAt) || !certificate.NotBefore.Before(certificate.NotAfter) {
		return errors.New("leaf profile differs")
	}
	var commonName string
	var dnsNames []string
	var usages []x509.ExtKeyUsage
	switch path {
	case "coordinator/etc/reach-exo/tls/coordinator.pem":
		commonName, dnsNames, usages = "reach-exo-coordinator", []string{"reach-exo-gateway"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	case "worker/etc/reach-exo/tls/worker.pem":
		commonName, dnsNames, usages = "reach-exo-worker", []string{"reach-exo-worker"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "connector/tls/connector.pem":
		commonName, dnsNames, usages = "reach-exo-connector", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return errors.New("unknown leaf path")
	}
	if !exactCommonName(certificate.Subject, commonName) || !reflect.DeepEqual(certificate.DNSNames, dnsNames) || !reflect.DeepEqual(certificate.ExtKeyUsage, usages) {
		return errors.New("leaf role profile differs")
	}
	return nil
}

func validAuthorityID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func canonicalUTCTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339) == value
}

func mustParseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func validateOwnedTree(root string, allowEmpty bool) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || ownerID(info) != os.Geteuid() {
		return errors.New("target root is absent or not an owner-only current-user directory")
	}
	rootDevice, ok := deviceID(info)
	if !ok {
		return errors.New("target root device identity is unavailable")
	}
	maxObjects := len(exactAuthorityDirectorySet()) - 1 + len(exactAuthorityFileSet(root))
	count := 0
	totalBytes := int64(0)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		count++
		if count > maxObjects {
			return errors.New("tree object count exceeds the fixed authority bound")
		}
		info, err := os.Lstat(path)
		if err != nil || ownerID(info) != os.Geteuid() {
			return errors.New("tree contains a foreign-owned object")
		}
		device, ok := deviceID(info)
		if !ok || device != rootDevice {
			return errors.New("tree crosses a filesystem or mount boundary")
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0700 {
				return errors.New("tree contains a widened directory")
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || linkCount(info) != 1 {
			return errors.New("tree contains a linked, special, or widened file")
		}
		if info.Size() < 0 || info.Size() > maxManifestBytes {
			return errors.New("tree contains an oversized file")
		}
		totalBytes += info.Size()
		if totalBytes > int64(len(exactAuthorityFileSet(root)))*maxManifestBytes {
			return errors.New("tree byte size exceeds the fixed authority bound")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if count == 0 && !allowEmpty {
		return errors.New("tree is unexpectedly empty")
	}
	return nil
}

func deviceID(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Dev), true
}

func observedAuthorityShape(root string) (map[string]bool, error) {
	shape := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			relative += "/"
		}
		shape[relative] = true
		return nil
	})
	return shape, err
}

func validateCompleteAuthorityShape(shape map[string]bool) error {
	expected := map[string]bool{}
	for _, path := range authorityCreationOrder() {
		expected[path] = true
	}
	if !reflect.DeepEqual(shape, expected) {
		return errors.New("prepared tree differs from the implementation-owned exact authority grammar")
	}
	return nil
}

func validateStagingShape(shape map[string]bool) error {
	order := authorityCreationOrder()
	for length := 0; length <= len(order); length++ {
		expected := map[string]bool{}
		for _, path := range order[:length] {
			expected[path] = true
		}
		if reflect.DeepEqual(shape, expected) {
			return nil
		}
	}
	return errors.New("staging tree is not a legitimate bounded preparation prefix")
}

func validateQuarantineShape(shape map[string]bool) error {
	creation := authorityCreationOrder()
	for prefix := 0; prefix <= len(creation); prefix++ {
		remaining := map[string]bool{}
		for _, path := range creation[:prefix] {
			remaining[path] = true
		}
		if reflect.DeepEqual(shape, remaining) {
			return nil
		}
		for _, removed := range authorityRemovalOrder(remaining) {
			delete(remaining, removed)
			if reflect.DeepEqual(shape, remaining) {
				return nil
			}
		}
	}
	return errors.New("quarantine tree is not a reachable bounded cleanup state")
}

func authorityRemovalOrder(shape map[string]bool) []string {
	regular := authorityRegularRemovalOrder(shape)
	directories := authorityDirectoryRemovalOrder(shape)
	result := append([]string{}, regular...)
	for _, directory := range directories {
		result = append(result, directory+"/")
	}
	if shape[prepareName] {
		result = append(result, prepareName)
	}
	return result
}

func authorityRegularRemovalOrder(shape map[string]bool) []string {
	const caWitness = "operator/tls/ca.pem"
	var regular []string
	for path := range shape {
		if !strings.HasSuffix(path, "/") && path != prepareName && path != caWitness {
			regular = append(regular, path)
		}
	}
	sort.Strings(regular)
	if shape[caWitness] {
		regular = append(regular, caWitness)
	}
	return regular
}

func authorityDirectoryRemovalOrder(shape map[string]bool) []string {
	var directories []string
	for path := range shape {
		if strings.HasSuffix(path, "/") {
			directories = append(directories, strings.TrimSuffix(path, "/"))
		}
	}
	sort.Slice(directories, func(i, j int) bool {
		leftDepth := strings.Count(directories[i], "/")
		rightDepth := strings.Count(directories[j], "/")
		if leftDepth == rightDepth {
			return directories[i] > directories[j]
		}
		return leftDepth > rightDepth
	})
	return directories
}

func removeQuarantine(root string, deps dependencies) error {
	if err := validateOwnedTree(root, true); err != nil {
		return err
	}
	shape, err := observedAuthorityShape(root)
	if err != nil {
		return err
	}
	if err := validateQuarantineShape(shape); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() {
		if rootHandle != nil {
			_ = rootHandle.Close()
		}
	}()
	openedInfo, err := rootHandle.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedInfo) {
		return errors.New("quarantine identity changed before removal")
	}
	regular := authorityRegularRemovalOrder(shape)
	directories := authorityDirectoryRemovalOrder(shape)
	for _, relative := range regular {
		if err := deps.reach("before-remove:" + relative); err != nil {
			return err
		}
		if err := rootHandle.Remove(relative); err != nil {
			return err
		}
		if err := deps.reach("after-remove:" + relative); err != nil {
			return err
		}
	}
	for _, relative := range directories {
		if err := deps.reach("before-remove-directory:" + relative); err != nil {
			return err
		}
		if err := rootHandle.Remove(relative); err != nil {
			return err
		}
		if err := deps.reach("after-remove-directory:" + relative); err != nil {
			return err
		}
	}
	preparePath := filepath.Join(root, prepareName)
	if _, err := os.Lstat(preparePath); err == nil {
		if err := deps.reach("before-remove-prepare"); err != nil {
			return err
		}
		if err := rootHandle.Remove(prepareName); err != nil {
			return err
		}
		if err := deps.reach("after-remove-prepare"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncOpenedRoot(rootHandle, deps, "empty-quarantine"); err != nil {
		return err
	}
	if err := rootHandle.Close(); err != nil {
		return err
	}
	rootHandle = nil
	currentInfo, err := os.Lstat(root)
	if err != nil || !os.SameFile(rootInfo, currentInfo) {
		return errors.New("quarantine identity changed before final removal")
	}
	if err := deps.reach("before-remove-quarantine"); err != nil {
		return err
	}
	if err := os.Remove(root); err != nil {
		return err
	}
	if err := deps.reach("after-remove-quarantine"); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(root), deps, "recovery-parent-final")
}

func readStrictJSON[T any](path string, limit int64) (T, error) {
	var zero T
	data, err := readPrivateFile(path, limit)
	if err != nil {
		return zero, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return zero, errors.New("JSON contains trailing value")
	}
	return value, nil
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
