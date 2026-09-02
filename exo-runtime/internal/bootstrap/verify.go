package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"reach.dev/exo-runtime/internal/config"
)

func Verify(root, expectedAuthoritySHA256 string) (Verification, error) {
	return verifyAt(root, expectedAuthoritySHA256, time.Now().UTC())
}

func verifyAt(root, expectedAuthoritySHA256 string, now time.Time) (Verification, error) {
	if !validRootSpelling(root) {
		return Verification{}, errors.New("authority root must be absolute and canonical")
	}
	if !validLowerSHA256(expectedAuthoritySHA256) {
		return Verification{}, errors.New("expected authority SHA-256 must be 64 lowercase hexadecimal characters")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return Verification{}, errors.New("authority root is absent or reached through a symlink alias")
	}
	if err := validateOwnedTree(root, false); err != nil {
		return Verification{}, err
	}
	manifestPath := filepath.Join(root, fileManifestName)
	fileManifestBytes, err := readPrivateFile(manifestPath, maxManifestBytes)
	if err != nil {
		return Verification{}, err
	}
	entries, err := parseFileManifest(fileManifestBytes)
	if err != nil {
		return Verification{}, err
	}
	if err := verifyFileManifestCoverage(root, entries); err != nil {
		return Verification{}, err
	}
	manifest, err := readStrictJSON[ClusterManifest](filepath.Join(root, clusterManifestName), maxManifestBytes)
	if err != nil {
		return Verification{}, fmt.Errorf("cluster manifest: %w", err)
	}
	if manifest.SchemaVersion != SchemaVersion || manifest.Exact != exactAuthority() || !validLowerSHA256(manifest.InventorySHA256) || manifest.AuthorityRootSHA256 != digestString(root) {
		return Verification{}, errors.New("cluster manifest schema, exact package authority, inventory, or root binding differs")
	}
	createdAt, createdErr := time.Parse(time.RFC3339, manifest.CreatedAt)
	expiresAt, expiryErr := time.Parse(time.RFC3339, manifest.CertificateExpiry)
	if createdErr != nil || expiryErr != nil || createdAt.Location() != time.UTC || expiresAt.Location() != time.UTC || createdAt.Format(time.RFC3339) != manifest.CreatedAt || expiresAt.Format(time.RFC3339) != manifest.CertificateExpiry {
		return Verification{}, errors.New("cluster manifest time authority is malformed")
	}
	inventory := inventoryFromManifest(root, manifest)
	if err := inventory.Validate(createdAt); err != nil {
		return Verification{}, fmt.Errorf("reconstructed inventory: %w", err)
	}
	canonicalInventory, _ := json.Marshal(inventory)
	inventoryHash := sha256.Sum256(canonicalInventory)
	if hex.EncodeToString(inventoryHash[:]) != manifest.InventorySHA256 {
		return Verification{}, errors.New("reconstructed inventory digest differs")
	}
	derivedTopology := deriveTopology(inventory)
	if !reflect.DeepEqual(derivedTopology, manifest.Topology) {
		return Verification{}, errors.New("semantic topology differs from strict inventory derivation")
	}
	topologySHA, err := topologyDigest(manifest.Topology)
	if err != nil || topologySHA != manifest.TopologySHA256 {
		return Verification{}, errors.New("semantic topology digest differs")
	}
	prepare, err := readStrictJSON[PrepareRecord](filepath.Join(root, prepareName), 4096)
	if err != nil || prepare.SchemaVersion != SchemaVersion || prepare.InventorySHA256 != manifest.InventorySHA256 || prepare.AuthorityRootSHA256 != manifest.AuthorityRootSHA256 {
		return Verification{}, errors.New("durable preparation provenance differs")
	}
	metadata, err := readStrictJSON[authorityMetadata](filepath.Join(root, "operator/authority.json"), 64*1024)
	if err != nil || metadata.SchemaVersion != SchemaVersion || metadata.AuthorityID != manifest.BootstrapAuthorityID || metadata.CreatedAt != manifest.CreatedAt || metadata.ExpiresAt != manifest.CertificateExpiry || metadata.Exact != exactAuthority() {
		return Verification{}, errors.New("operator authority metadata differs")
	}
	if len(metadata.AuthorityID) != 32 {
		return Verification{}, errors.New("bootstrap authority identifier is malformed")
	}
	if _, err := hex.DecodeString(metadata.AuthorityID); err != nil {
		return Verification{}, errors.New("bootstrap authority identifier is malformed")
	}
	if err := verifyBoundFiles(root, root, manifest.Files); err != nil {
		return Verification{}, err
	}
	if err := verifyConfigurations(root, root, manifest.Topology); err != nil {
		return Verification{}, err
	}
	fingerprints, err := verifyCertificates(root, manifest, now)
	if err != nil {
		return Verification{}, err
	}
	if fingerprints != manifest.Certificates {
		return Verification{}, errors.New("certificate fingerprints differ from cluster manifest")
	}
	fileManifestHash := sha256.Sum256(fileManifestBytes)
	authoritySHA := authorityDigest(manifest.InventorySHA256, root, manifest.Exact, manifest.TopologySHA256, fingerprints, hex.EncodeToString(fileManifestHash[:]))
	if !constantTimeDigestEqual(authoritySHA, expectedAuthoritySHA256) {
		return Verification{}, errors.New("external authority commitment does not match the reconstructed tree")
	}
	if err := validateOwnedTree(root, false); err != nil {
		return Verification{}, errors.New("authority tree changed during verification")
	}
	if err := verifyFileManifestCoverage(root, entries); err != nil {
		return Verification{}, fmt.Errorf("authority tree changed during verification: %w", err)
	}
	return Verification{SchemaVersion: SchemaVersion, Valid: true, PackageGeneration: manifest.Exact.PackageGeneration, AuthoritySHA256: authoritySHA, Certificates: fingerprints}, nil
}

func inventoryFromManifest(root string, manifest ClusterManifest) Inventory {
	return Inventory{
		SchemaVersion: SchemaVersion, Namespace: manifest.Topology.Namespace, AuthorityRoot: root,
		PrivateNetwork: manifest.Topology.PrivateNetwork, ConnectorAddress: manifest.Topology.ConnectorAddress,
		GatewayMode:       manifest.Topology.GatewayMode,
		Coordinator:       NodeInventory{Name: manifest.Topology.Coordinator.Name, Address: manifest.Topology.Coordinator.Address, Interface: manifest.Topology.Coordinator.Interface, MACAddress: manifest.Topology.Coordinator.MACAddress},
		Worker:            NodeInventory{Name: manifest.Topology.Worker.Name, Address: manifest.Topology.Worker.Address, Interface: manifest.Topology.Worker.Interface, MACAddress: manifest.Topology.Worker.MACAddress},
		CertificateExpiry: manifest.CertificateExpiry,
	}
}

func verifyFileManifestCoverage(root string, entries []fileManifestEntry) error {
	expectedFiles := exactAuthorityFileSet(root)
	delete(expectedFiles, fileManifestName)
	if len(entries) != len(expectedFiles) {
		return errors.New("file manifest entry count differs from the fixed authority grammar")
	}
	wanted := make(map[string]fileManifestEntry, len(entries))
	for _, entry := range entries {
		if !expectedFiles[entry.Path] {
			return fmt.Errorf("file manifest names a path outside the fixed authority grammar: %s", entry.Path)
		}
		wanted[entry.Path] = entry
	}
	seen := map[string]bool{}
	seenDirectories := map[string]bool{".": true}
	expectedDirectories := exactAuthorityDirectorySet()
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
			if !expectedDirectories[relative] {
				return fmt.Errorf("authority contains a directory outside the fixed grammar: %s", relative)
			}
			seenDirectories[relative] = true
			return nil
		}
		if relative == fileManifestName {
			return nil
		}
		wantedEntry, ok := wanted[relative]
		if !ok {
			return fmt.Errorf("authority contains undeclared file %s", relative)
		}
		info, err := os.Lstat(path)
		if err != nil || info.Size() != wantedEntry.Bytes || info.Mode().Perm() != wantedEntry.Mode {
			return fmt.Errorf("authority file %s tuple differs", relative)
		}
		digest, bytes, err := fileDigest(path, maxManifestBytes)
		if err != nil || bytes != wantedEntry.Bytes || digest != wantedEntry.SHA256 {
			return fmt.Errorf("authority file %s digest differs", relative)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(wanted) {
		return errors.New("file manifest names an absent file")
	}
	if !reflect.DeepEqual(seenDirectories, expectedDirectories) {
		return errors.New("authority contains an undeclared or missing directory")
	}
	return nil
}

func expectedBoundFiles(root string) map[string]BoundFile {
	return map[string]BoundFile{
		prepareName:                                         {Path: prepareName, Mode: "0600", Slice: "provenance"},
		"operator/authority.json":                           {Path: "operator/authority.json", Mode: "0600", Slice: "operator"},
		"operator/tls/ca.pem":                               {Path: "operator/tls/ca.pem", Mode: "0600", Slice: "operator"},
		"operator/tls/ca-key.pem":                           {Path: "operator/tls/ca-key.pem", Mode: "0600", Slice: "operator"},
		"coordinator/etc/reach-exo/node.json":               {Path: "coordinator/etc/reach-exo/node.json", Mode: "0600", Slice: "coordinator", TargetPath: "/etc/reach-exo/node.json", TargetMode: "0640"},
		"coordinator/etc/reach-exo/tls/ca.pem":              {Path: "coordinator/etc/reach-exo/tls/ca.pem", Mode: "0600", Slice: "coordinator", TargetPath: "/etc/reach-exo/tls/ca.pem", TargetMode: "0644"},
		"coordinator/etc/reach-exo/tls/coordinator.pem":     {Path: "coordinator/etc/reach-exo/tls/coordinator.pem", Mode: "0600", Slice: "coordinator", TargetPath: "/etc/reach-exo/tls/coordinator.pem", TargetMode: "0644"},
		"coordinator/etc/reach-exo/tls/coordinator-key.pem": {Path: "coordinator/etc/reach-exo/tls/coordinator-key.pem", Mode: "0600", Slice: "coordinator", TargetPath: "/etc/reach-exo/tls/coordinator-key.pem", TargetMode: "0640"},
		"worker/etc/reach-exo/node.json":                    {Path: "worker/etc/reach-exo/node.json", Mode: "0600", Slice: "worker", TargetPath: "/etc/reach-exo/node.json", TargetMode: "0640"},
		"worker/etc/reach-exo/tls/ca.pem":                   {Path: "worker/etc/reach-exo/tls/ca.pem", Mode: "0600", Slice: "worker", TargetPath: "/etc/reach-exo/tls/ca.pem", TargetMode: "0644"},
		"worker/etc/reach-exo/tls/worker.pem":               {Path: "worker/etc/reach-exo/tls/worker.pem", Mode: "0600", Slice: "worker", TargetPath: "/etc/reach-exo/tls/worker.pem", TargetMode: "0644"},
		"worker/etc/reach-exo/tls/worker-key.pem":           {Path: "worker/etc/reach-exo/tls/worker-key.pem", Mode: "0600", Slice: "worker", TargetPath: "/etc/reach-exo/tls/worker-key.pem", TargetMode: "0640"},
		"connector/connector.json":                          {Path: "connector/connector.json", Mode: "0600", Slice: "connector", TargetPath: filepath.Join(root, "connector", "connector.json"), TargetMode: "0600"},
		"connector/tls/ca.pem":                              {Path: "connector/tls/ca.pem", Mode: "0600", Slice: "connector", TargetPath: filepath.Join(root, "connector", "tls", "ca.pem"), TargetMode: "0644"},
		"connector/tls/connector.pem":                       {Path: "connector/tls/connector.pem", Mode: "0600", Slice: "connector", TargetPath: filepath.Join(root, "connector", "tls", "connector.pem"), TargetMode: "0644"},
		"connector/tls/connector-key.pem":                   {Path: "connector/tls/connector-key.pem", Mode: "0600", Slice: "connector", TargetPath: filepath.Join(root, "connector", "tls", "connector-key.pem"), TargetMode: "0600"},
	}
}

func verifyBoundFiles(treeRoot, authorityRoot string, files []BoundFile) error {
	expected := expectedBoundFiles(authorityRoot)
	if len(files) != len(expected) {
		return errors.New("cluster manifest file declaration count differs")
	}
	previous := ""
	for _, file := range files {
		if file.Path <= previous || !safeRelative(file.Path) || !validLowerSHA256(file.SHA256) || file.Bytes < 0 {
			return errors.New("cluster manifest file declarations are malformed, duplicate, or unsorted")
		}
		shape, ok := expected[file.Path]
		if !ok || file.Mode != shape.Mode || file.Slice != shape.Slice || file.TargetPath != shape.TargetPath || file.TargetMode != shape.TargetMode {
			return fmt.Errorf("cluster manifest declaration differs for %s", file.Path)
		}
		digest, bytes, err := fileDigest(filepath.Join(treeRoot, filepath.FromSlash(file.Path)), maxManifestBytes)
		if err != nil || digest != file.SHA256 || bytes != file.Bytes {
			return fmt.Errorf("cluster manifest file binding differs for %s", file.Path)
		}
		previous = file.Path
	}
	return nil
}

func verifyConfigurations(treeRoot, authorityRoot string, topology Topology) error {
	coordinatorBytes, err := readPrivateFile(filepath.Join(treeRoot, "coordinator/etc/reach-exo/node.json"), maxManifestBytes)
	if err != nil {
		return err
	}
	coordinator, err := config.DecodeNode(coordinatorBytes)
	if err != nil {
		return fmt.Errorf("coordinator configuration: %w", err)
	}
	expectedCoordinator, _ := nodeConfiguration(topology, "coordinator")
	if !reflect.DeepEqual(coordinator, expectedCoordinator) {
		return errors.New("coordinator configuration differs from semantic topology")
	}
	workerBytes, err := readPrivateFile(filepath.Join(treeRoot, "worker/etc/reach-exo/node.json"), maxManifestBytes)
	if err != nil {
		return err
	}
	worker, err := config.DecodeNode(workerBytes)
	if err != nil {
		return fmt.Errorf("worker configuration: %w", err)
	}
	expectedWorker, _ := nodeConfiguration(topology, "worker")
	if !reflect.DeepEqual(worker, expectedWorker) {
		return errors.New("worker configuration differs from semantic topology")
	}
	connectorBytes, err := readPrivateFile(filepath.Join(treeRoot, "connector/connector.json"), maxManifestBytes)
	if err != nil {
		return err
	}
	connector, err := config.DecodeConnector(connectorBytes)
	if err != nil {
		return fmt.Errorf("connector configuration: %w", err)
	}
	expectedConnector, _ := connectorConfiguration(authorityRoot, topology)
	if !reflect.DeepEqual(connector, expectedConnector) {
		return errors.New("connector configuration differs from semantic topology or root spelling")
	}
	return nil
}

func verifyCertificates(root string, manifest ClusterManifest, now time.Time) (Fingerprints, error) {
	caPEM, ca, caKey, err := readCertificatePair(filepath.Join(root, "operator/tls/ca.pem"), filepath.Join(root, "operator/tls/ca-key.pem"))
	if err != nil {
		return Fingerprints{}, fmt.Errorf("operator CA: %w", err)
	}
	expectedCAName := pkix.Name{CommonName: "reach-exo-bootstrap-ca-" + manifest.BootstrapAuthorityID[:16]}
	if !ca.IsCA || !ca.BasicConstraintsValid || !ca.MaxPathLenZero || ca.MaxPathLen != 0 || ca.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(ca.ExtKeyUsage) != 0 || len(ca.UnknownExtKeyUsage) != 0 || len(ca.DNSNames) != 0 || len(ca.IPAddresses) != 0 || len(ca.EmailAddresses) != 0 || len(ca.URIs) != 0 || len(ca.UnhandledCriticalExtensions) != 0 || ca.SignatureAlgorithm != x509.ECDSAWithSHA256 || !exactCommonName(ca.Subject, expectedCAName.CommonName) || !exactCommonName(ca.Issuer, expectedCAName.CommonName) || ca.CheckSignatureFrom(ca) != nil {
		return Fingerprints{}, errors.New("CA constraints or self-signature differ")
	}
	if !strings.HasPrefix(ca.Subject.CommonName, "reach-exo-bootstrap-ca-") || ca.Subject.CommonName != expectedCAName.CommonName {
		return Fingerprints{}, errors.New("CA identity differs")
	}
	createdAt, _ := time.Parse(time.RFC3339, manifest.CreatedAt)
	expiresAt, _ := time.Parse(time.RFC3339, manifest.CertificateExpiry)
	if !ca.NotBefore.Equal(createdAt.Add(-5*time.Minute)) || !ca.NotAfter.Equal(expiresAt) || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return Fingerprints{}, errors.New("CA validity differs or is not currently valid")
	}
	for _, copyPath := range []string{"coordinator/etc/reach-exo/tls/ca.pem", "worker/etc/reach-exo/tls/ca.pem", "connector/tls/ca.pem"} {
		copyBytes, err := readPrivateFile(filepath.Join(root, filepath.FromSlash(copyPath)), maxManifestBytes)
		if err != nil || !bytes.Equal(copyBytes, caPEM) {
			return Fingerprints{}, fmt.Errorf("CA copy differs at %s", copyPath)
		}
	}
	coordinator, coordinatorKey, err := readLeafPair(root, "coordinator/etc/reach-exo/tls/coordinator.pem", "coordinator/etc/reach-exo/tls/coordinator-key.pem")
	if err != nil {
		return Fingerprints{}, err
	}
	worker, workerKey, err := readLeafPair(root, "worker/etc/reach-exo/tls/worker.pem", "worker/etc/reach-exo/tls/worker-key.pem")
	if err != nil {
		return Fingerprints{}, err
	}
	connector, connectorKey, err := readLeafPair(root, "connector/tls/connector.pem", "connector/tls/connector-key.pem")
	if err != nil {
		return Fingerprints{}, err
	}
	if err := verifyLeaf(ca, coordinator, coordinatorKey, "reach-exo-coordinator", []string{"reach-exo-gateway"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, createdAt, expiresAt, now); err != nil {
		return Fingerprints{}, fmt.Errorf("coordinator certificate: %w", err)
	}
	if err := verifyLeaf(ca, worker, workerKey, "reach-exo-worker", []string{"reach-exo-worker"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, createdAt, expiresAt, now); err != nil {
		return Fingerprints{}, fmt.Errorf("worker certificate: %w", err)
	}
	if err := verifyLeaf(ca, connector, connectorKey, "reach-exo-connector", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, createdAt, expiresAt, now); err != nil {
		return Fingerprints{}, fmt.Errorf("connector certificate: %w", err)
	}
	serials := map[string]bool{}
	publicKeys := map[string]bool{}
	for _, certificate := range []*x509.Certificate{ca, coordinator, worker, connector} {
		if certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() != 128 || serials[certificate.SerialNumber.Text(16)] {
			return Fingerprints{}, errors.New("certificate serials are not distinct positive random 128-bit values")
		}
		serials[certificate.SerialNumber.Text(16)] = true
		publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
		if err != nil {
			return Fingerprints{}, errors.New("certificate public key is malformed")
		}
		publicKeyDigest := sha256.Sum256(publicKey)
		keyID := hex.EncodeToString(publicKeyDigest[:])
		if publicKeys[keyID] {
			return Fingerprints{}, errors.New("CA and leaf certificate public keys must be pairwise distinct")
		}
		publicKeys[keyID] = true
	}
	if !publicKeysEqual(ca.PublicKey, &caKey.PublicKey) {
		return Fingerprints{}, errors.New("CA private key does not match certificate")
	}
	return Fingerprints{CA: certificateFingerprint(ca), Coordinator: certificateFingerprint(coordinator), Worker: certificateFingerprint(worker), Connector: certificateFingerprint(connector)}, nil
}

func readCertificatePair(certificatePath, keyPath string) ([]byte, *x509.Certificate, *ecdsa.PrivateKey, error) {
	certificatePEM, err := readPrivateFile(certificatePath, maxManifestBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate, err := parseCertificate(certificatePEM)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := readPrivateFile(keyPath, maxManifestBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	if !publicKeysEqual(certificate.PublicKey, &key.PublicKey) {
		return nil, nil, nil, errors.New("certificate and private key do not match")
	}
	return certificatePEM, certificate, key, nil
}

func readLeafPair(root, certificatePath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	_, certificate, key, err := readCertificatePair(filepath.Join(root, filepath.FromSlash(certificatePath)), filepath.Join(root, filepath.FromSlash(keyPath)))
	return certificate, key, err
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("certificate PEM must contain exactly one certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key PEM must contain exactly one PKCS#8 key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("private key is not ECDSA P-256")
	}
	return key, nil
}

func verifyLeaf(ca, leaf *x509.Certificate, key *ecdsa.PrivateKey, commonName string, dnsNames []string, usages []x509.ExtKeyUsage, createdAt, expiresAt, now time.Time) error {
	expectedSubject := pkix.Name{CommonName: commonName}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || !exactCommonName(leaf.Subject, expectedSubject.CommonName) || !exactCommonName(leaf.Issuer, ca.Subject.CommonName) || !reflect.DeepEqual(leaf.DNSNames, dnsNames) || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.UnhandledCriticalExtensions) != 0 || !reflect.DeepEqual(leaf.ExtKeyUsage, usages) || !leaf.NotBefore.Equal(createdAt.Add(-5*time.Minute)) || !leaf.NotAfter.Equal(expiresAt) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.CheckSignatureFrom(ca) != nil || !publicKeysEqual(leaf.PublicKey, &key.PublicKey) {
		return errors.New("identity, usage, validity, issuer, or key relationship differs")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, usage := range usages {
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, DNSName: dnsNameForUsage(leaf, usage), KeyUsages: []x509.ExtKeyUsage{usage}})
		if err != nil || len(chains) != 1 || len(chains[0]) != 2 {
			return errors.New("certificate chain or admitted usage differs")
		}
	}
	return nil
}

func dnsNameForUsage(certificate *x509.Certificate, usage x509.ExtKeyUsage) string {
	if usage == x509.ExtKeyUsageServerAuth && len(certificate.DNSNames) == 1 {
		return certificate.DNSNames[0]
	}
	return ""
}

func exactCommonName(name pkix.Name, commonName string) bool {
	return name.CommonName == commonName && len(name.Country) == 0 && len(name.Organization) == 0 && len(name.OrganizationalUnit) == 0 && len(name.Locality) == 0 && len(name.Province) == 0 && len(name.StreetAddress) == 0 && len(name.PostalCode) == 0 && name.SerialNumber == "" && len(name.ExtraNames) == 0
}

func publicKeysEqual(left, right any) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func MarshalVerification(value Verification) ([]byte, error) {
	return marshalJSON(value)
}
