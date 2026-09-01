// Package packageupdate implements the exact offline A-to-B transaction.
package packageupdate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"reach.dev/exo-runtime/internal/authority"
)

const maxManifestBytes = 16 * 1024 * 1024

type Metadata struct {
	BundleVersion               string `json:"bundle_version"`
	Architecture                string `json:"architecture"`
	EXOVersion                  string `json:"exo_version"`
	EXOCommit                   string `json:"exo_commit"`
	EXOTree                     string `json:"exo_tree"`
	DerivativeSHA256            string `json:"derivative_sha256"`
	ModelID                     string `json:"model_id"`
	ModelSnapshot               string `json:"model_snapshot"`
	ModelIncluded               bool   `json:"model_included"`
	InstallStartsService        bool   `json:"install_starts_service"`
	PackageGeneration           string `json:"package_generation,omitempty"`
	ParentBundleVersion         string `json:"parent_bundle_version,omitempty"`
	ParentNodeSHA256            string `json:"parent_node_sha256,omitempty"`
	ParentConnectorSHA256       string `json:"parent_connector_sha256,omitempty"`
	ParentPackageSHA256         string `json:"parent_package_sha256,omitempty"`
	ParentPayloadManifestSHA256 string `json:"parent_payload_manifest_sha256,omitempty"`
	ParentMetadataSHA256        string `json:"parent_metadata_sha256,omitempty"`
}

type ManifestEntry struct {
	Kind   string
	Mode   os.FileMode
	Bytes  int64
	SHA256 string
	Path   string
}

type Artifact struct {
	Root          string
	Archive       string
	ArchiveSHA256 string
	Metadata      Metadata
	MetadataSHA   string
	PayloadSHA    string
	Entries       map[string]ManifestEntry
	authenticated bool
}

type ArtifactDigests struct {
	ArchiveSHA256  string
	PayloadSHA256  string
	MetadataSHA256 string
}

func (a *Artifact) Digests() ArtifactDigests {
	return ArtifactDigests{ArchiveSHA256: a.ArchiveSHA256, PayloadSHA256: a.PayloadSHA, MetadataSHA256: a.MetadataSHA}
}

func LoadArtifact(root, archive string, expected ArtifactDigests, expectedOwner int) (*Artifact, error) {
	root = filepath.Clean(root)
	archive = filepath.Clean(archive)
	if !filepath.IsAbs(root) || !filepath.IsAbs(archive) || !validArtifactDigests(expected) {
		return nil, errors.New("artifact paths must be absolute and archive/payload/metadata SHA-256 authority exact")
	}
	archiveInfo, err := os.Lstat(archive)
	if err != nil || !archiveInfo.Mode().IsRegular() || archiveInfo.Mode().Perm()&0022 != 0 || ownerID(archiveInfo) != expectedOwner || linkCount(archiveInfo) != 1 {
		return nil, errors.New("package archive tuple differs from transaction authority")
	}
	actualArchiveSHA, err := fileSHA256(archive, 0)
	if err != nil {
		return nil, fmt.Errorf("hash package archive: %w", err)
	}
	if actualArchiveSHA != expected.ArchiveSHA256 {
		return nil, errors.New("package archive digest does not match authority")
	}
	if err := verifyBundleManifest(root, expectedOwner); err != nil {
		return nil, err
	}
	metadataPath := filepath.Join(root, "metadata", "package.json")
	metadataBytes, err := readBounded(metadataPath, 64*1024)
	if err != nil {
		return nil, err
	}
	var metadata Metadata
	decoder := json.NewDecoder(strings.NewReader(string(metadataBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode package metadata: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("package metadata contains trailing value")
	}
	entries, err := parsePayloadManifest(filepath.Join(root, "PAYLOAD-MANIFEST.tsv"))
	if err != nil {
		return nil, err
	}
	if err := verifyPayloadCoverage(root, entries, expectedOwner); err != nil {
		return nil, err
	}
	metadataDigest := sha256.Sum256(metadataBytes)
	payloadSHA, err := fileSHA256(filepath.Join(root, "PAYLOAD-MANIFEST.tsv"), maxManifestBytes)
	if err != nil {
		return nil, err
	}
	metadataSHA := hex.EncodeToString(metadataDigest[:])
	if payloadSHA != expected.PayloadSHA256 || metadataSHA != expected.MetadataSHA256 {
		return nil, errors.New("extracted artifact does not match authenticated payload/metadata authority")
	}
	artifact := &Artifact{
		Root: root, Archive: archive, ArchiveSHA256: actualArchiveSHA,
		Metadata: metadata, MetadataSHA: metadataSHA,
		PayloadSHA: payloadSHA, Entries: entries, authenticated: true,
	}
	if err := artifact.validateCommon(); err != nil {
		return nil, err
	}
	return artifact, nil
}

func (a *Artifact) validateCommon() error {
	m := a.Metadata
	if m.Architecture != authority.Architecture || m.EXOVersion != authority.EXOVersion || m.EXOCommit != authority.EXOCommit || m.EXOTree != authority.EXOTree || m.DerivativeSHA256 != authority.DerivativeSHA256 || m.ModelID != authority.ModelID || m.ModelSnapshot != authority.ModelSnapshot || m.ModelIncluded || m.InstallStartsService {
		return errors.New("package provider, architecture, model, or activation authority differs")
	}
	for _, required := range []string{
		"root/opt/reach-exo/bin/reach-exo-node",
		"root/opt/reach-exo/host/reach-exo-connector-darwin-arm64",
		"root/usr/lib/systemd/system/reach-exo-node.service",
		"root/usr/lib/systemd/system/reach-exo-relay.service",
		"root/usr/lib/sysusers.d/reach-exo.conf",
		"root/usr/lib/tmpfiles.d/reach-exo.conf",
	} {
		if _, ok := a.Entries[required]; !ok {
			return fmt.Errorf("package payload omits %s", required)
		}
	}
	return nil
}

func (a *Artifact) ValidateParent() error {
	if !a.authenticated {
		return errors.New("rollback artifact lacks authenticated external authority")
	}
	if a.Metadata.BundleVersion != authority.ParentBundleVersion || a.Metadata.PackageGeneration != "" || a.Metadata.ParentBundleVersion != "" {
		return errors.New("rollback artifact is not exact parent A metadata")
	}
	if a.ArchiveSHA256 != authority.ParentPackageSHA256 || a.PayloadSHA != authority.ParentPayloadSHA256 || a.MetadataSHA != authority.ParentMetadataSHA256 {
		return errors.New("rollback artifact does not match exact parent A digests")
	}
	if got, err := a.entryDigest("root/opt/reach-exo/bin/reach-exo-node"); err != nil || got != authority.ParentNodeSHA256 {
		return errors.New("rollback artifact node does not match exact parent A")
	}
	if got, err := a.entryDigest("root/opt/reach-exo/host/reach-exo-connector-darwin-arm64"); err != nil || got != authority.ParentConnectorSHA256 {
		return errors.New("rollback artifact connector does not match exact parent A")
	}
	return nil
}

func (a *Artifact) ValidateCandidate() error {
	if !a.authenticated {
		return errors.New("candidate artifact lacks authenticated external authority")
	}
	m := a.Metadata
	if m.BundleVersion != authority.BundleVersion || m.PackageGeneration != authority.PackageGeneration || m.ParentBundleVersion != authority.ParentBundleVersion || m.ParentNodeSHA256 != authority.ParentNodeSHA256 || m.ParentConnectorSHA256 != authority.ParentConnectorSHA256 || m.ParentPackageSHA256 != authority.ParentPackageSHA256 || m.ParentPayloadManifestSHA256 != authority.ParentPayloadSHA256 || m.ParentMetadataSHA256 != authority.ParentMetadataSHA256 {
		return errors.New("candidate is not exact B with exact parent A")
	}
	for _, required := range []string{
		"root/opt/reach-exo/bin/reach-exo-package",
		"scripts/update.sh", "scripts/recover.sh", "scripts/rollback.sh",
	} {
		if _, ok := a.Entries[required]; !ok {
			return fmt.Errorf("candidate payload omits %s", required)
		}
	}
	return nil
}

func (a *Artifact) entryDigest(path string) (string, error) {
	entry, ok := a.Entries[path]
	if !ok || entry.Kind != "file" {
		return "", fmt.Errorf("missing regular artifact path %s", path)
	}
	return entry.SHA256, nil
}

func verifyBundleManifest(root string, expectedOwner int) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&0022 != 0 {
		return errors.New("artifact root is absent, non-directory, or group/world writable")
	}
	if ownerID(info) != expectedOwner {
		return errors.New("artifact root ownership differs from transaction authority")
	}
	manifestPath := filepath.Join(root, "MANIFEST.sha256")
	manifestInfo, statErr := os.Lstat(manifestPath)
	if statErr != nil || !manifestInfo.Mode().IsRegular() || ownerID(manifestInfo) != expectedOwner || manifestInfo.Mode().Perm()&0022 != 0 || linkCount(manifestInfo) != 1 {
		return errors.New("package MANIFEST.sha256 tuple differs")
	}
	data, err := readBounded(manifestPath, maxManifestBytes)
	if err != nil {
		return err
	}
	wanted := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxManifestBytes)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " || !validSHA(line[:64]) {
			return errors.New("invalid package MANIFEST.sha256 row")
		}
		path := strings.TrimPrefix(line[66:], "./")
		if !safeRelative(path) || path == "MANIFEST.sha256" {
			return errors.New("unsafe or recursive package manifest path")
		}
		if _, exists := wanted[path]; exists {
			return errors.New("duplicate package manifest path")
		}
		wanted[path] = line[:64]
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(wanted))
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.IsDir() {
			info, statErr := entry.Info()
			if statErr != nil || ownerID(info) != expectedOwner || info.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("artifact directory %s ownership or write mode differs", path)
			}
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || !safeRelative(filepath.ToSlash(relative)) {
			return errors.New("unsafe artifact path")
		}
		relative = filepath.ToSlash(relative)
		if relative == "MANIFEST.sha256" {
			return nil
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(path)
			resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
			within, relErr := filepath.Rel(root, resolved)
			within = filepath.ToSlash(within)
			if readErr != nil || relErr != nil || filepath.IsAbs(target) || within == ".." || strings.HasPrefix(within, "../") {
				return fmt.Errorf("artifact symlink %s escapes its package", relative)
			}
			return nil
		}
		expected, ok := wanted[relative]
		if !ok {
			return fmt.Errorf("artifact contains unmanifested path %s", relative)
		}
		actual, hashErr := pathDigest(path)
		if hashErr != nil {
			return hashErr
		}
		if actual != expected {
			return fmt.Errorf("artifact path %s digest differs", relative)
		}
		if ownerID(info) != expectedOwner || info.Mode().Perm()&0022 != 0 || linkCount(info) != 1 {
			return fmt.Errorf("artifact path %s ownership or write mode differs", relative)
		}
		seen[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(wanted) {
		return errors.New("artifact manifest names absent paths")
	}
	return nil
}

func verifyPayloadCoverage(root string, entries map[string]ManifestEntry, expectedOwner int) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "MANIFEST.sha256" || relative == "PAYLOAD-MANIFEST.tsv" {
			return nil
		}
		if _, ok := entries[relative]; !ok {
			return fmt.Errorf("payload manifest omits %s", relative)
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || ownerID(info) != expectedOwner || linkCount(info) != 1 {
			return fmt.Errorf("payload path %s has ambiguous link authority", relative)
		}
		return nil
	})
}

func parsePayloadManifest(path string) (map[string]ManifestEntry, error) {
	data, err := readBounded(path, maxManifestBytes)
	if err != nil {
		return nil, err
	}
	return parsePayloadRows(data, filepath.Dir(path))
}

func parsePayloadRows(data []byte, artifactRoot string) (map[string]ManifestEntry, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxManifestBytes)
	if !scanner.Scan() || scanner.Text() != "kind\tmode\tbytes\tsha256\tpath" {
		return nil, errors.New("payload manifest header differs")
	}
	entries := make(map[string]ManifestEntry)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 5 || (fields[0] != "file" && fields[0] != "symlink") || !validSHA(fields[3]) || !safeRelative(fields[4]) {
			return nil, errors.New("invalid payload manifest row")
		}
		mode, modeErr := strconv.ParseUint(fields[1], 8, 12)
		bytes, byteErr := strconv.ParseInt(fields[2], 10, 64)
		if modeErr != nil || byteErr != nil || bytes < 0 {
			return nil, errors.New("invalid payload manifest mode or size")
		}
		if _, exists := entries[fields[4]]; exists {
			return nil, errors.New("duplicate payload manifest path")
		}
		entry := ManifestEntry{Kind: fields[0], Mode: os.FileMode(mode), Bytes: bytes, SHA256: fields[3], Path: fields[4]}
		if artifactRoot != "" {
			actualPath := filepath.Join(artifactRoot, filepath.FromSlash(entry.Path))
			info, statErr := os.Lstat(actualPath)
			if statErr != nil || info.Mode().Perm() != entry.Mode || info.Size() != entry.Bytes {
				return nil, fmt.Errorf("payload path %s tuple differs", entry.Path)
			}
			actualDigest, digestErr := pathDigest(actualPath)
			if digestErr != nil || actualDigest != entry.SHA256 {
				return nil, fmt.Errorf("payload path %s digest differs", entry.Path)
			}
		}
		entries[entry.Path] = entry
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func sha256Bytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("authenticated file exceeds bound")
	}
	return data, nil
}

func fileSHA256(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	reader := io.Reader(file)
	if limit > 0 {
		reader = io.LimitReader(file, limit+1)
	}
	n, err := io.Copy(hash, reader)
	if err != nil {
		return "", err
	}
	if limit > 0 && n > limit {
		return "", errors.New("authenticated file exceeds bound")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func pathDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, readErr := os.Readlink(path)
		if readErr != nil {
			return "", readErr
		}
		digest := sha256.Sum256([]byte(target))
		return hex.EncodeToString(digest[:]), nil
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("authenticated payload object is not regular or symlink")
	}
	return fileSHA256(path, 0)
}

func safeRelative(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return path != "" && path == clean && clean != "." && !strings.HasPrefix(clean, "/") && !strings.HasPrefix(clean, "../") && !strings.Contains(clean, "/../") && !strings.ContainsRune(clean, '\x00')
}

func validSHA(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validArtifactDigests(value ArtifactDigests) bool {
	return validSHA(value.ArchiveSHA256) && validSHA(value.PayloadSHA256) && validSHA(value.MetadataSHA256)
}
