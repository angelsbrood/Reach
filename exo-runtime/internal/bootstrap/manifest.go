package bootstrap

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type fileManifestEntry struct {
	Path   string
	Bytes  int64
	Mode   os.FileMode
	SHA256 string
}

func fileDigest(path string, limit int64) (string, int64, error) {
	file, initial, err := openPrivateRegularFile(path, limit)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	read := int64(0)
	buffer := make([]byte, 32*1024)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			read += int64(count)
			if limit > 0 && read > limit {
				return "", read, errors.New("file exceeds bound")
			}
			_, _ = hash.Write(buffer[:count])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", read, readErr
		}
	}
	final, statErr := file.Stat()
	current, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !os.SameFile(initial, final) || !os.SameFile(initial, current) || final.Size() != read {
		return "", read, errors.New("file identity or size changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), read, nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, initial, err := openPrivateRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("private file read failed or exceeded its bound")
	}
	final, statErr := file.Stat()
	current, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !os.SameFile(initial, final) || !os.SameFile(initial, current) || final.Size() != int64(len(data)) {
		return nil, errors.New("private file identity or size changed while reading")
	}
	return data, nil
}

func openPrivateRegularFile(path string, limit int64) (*os.File, os.FileInfo, error) {
	initial, err := os.Lstat(path)
	if err != nil || !initial.Mode().IsRegular() || initial.Mode().Perm() != 0600 || ownerID(initial) != os.Geteuid() || linkCount(initial) != 1 || initial.Size() < 0 || (limit > 0 && initial.Size() > limit) {
		return nil, nil, errors.New("private file tuple differs")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(initial, opened) {
		file.Close()
		return nil, nil, errors.New("private file identity changed before open")
	}
	return file, initial, nil
}

func buildFileManifest(root string) ([]byte, []fileManifestEntry, error) {
	var entries []fileManifestEntry
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
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
		if relative == fileManifestName {
			return nil
		}
		if !safeRelative(relative) {
			return errors.New("unsafe manifest path")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || ownerID(info) != os.Geteuid() || linkCount(info) != 1 {
			return fmt.Errorf("manifest path %s has an unsafe tuple", relative)
		}
		digest, bytes, err := fileDigest(path, maxManifestBytes)
		if err != nil {
			return err
		}
		entries = append(entries, fileManifestEntry{Path: relative, Bytes: bytes, Mode: info.Mode().Perm(), SHA256: digest})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	var builder strings.Builder
	builder.WriteString("sha256\tbytes\tmode\tpath\n")
	for _, entry := range entries {
		fmt.Fprintf(&builder, "%s\t%d\t%04o\t%s\n", entry.SHA256, entry.Bytes, entry.Mode, entry.Path)
	}
	return []byte(builder.String()), entries, nil
}

func parseFileManifest(data []byte) ([]fileManifestEntry, error) {
	if len(data) > maxManifestBytes {
		return nil, errors.New("file manifest exceeds bound")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), maxManifestBytes)
	if !scanner.Scan() || scanner.Text() != "sha256\tbytes\tmode\tpath" {
		return nil, errors.New("file manifest header differs")
	}
	var entries []fileManifestEntry
	previous := ""
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 4 || !validLowerSHA256(fields[0]) || !safeRelative(fields[3]) || fields[3] == fileManifestName || fields[3] <= previous {
			return nil, errors.New("file manifest row is malformed, duplicate, or unsorted")
		}
		bytes, bytesErr := strconv.ParseInt(fields[1], 10, 64)
		mode, modeErr := strconv.ParseUint(fields[2], 8, 12)
		if bytesErr != nil || modeErr != nil || bytes < 0 || os.FileMode(mode) != 0600 {
			return nil, errors.New("file manifest size or mode differs")
		}
		entries = append(entries, fileManifestEntry{SHA256: fields[0], Bytes: bytes, Mode: os.FileMode(mode), Path: fields[3]})
		previous = fields[3]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("file manifest is empty")
	}
	return entries, nil
}

func authorityDigest(inventoryDigest, root string, exact ExactAuthority, topologyDigest string, fingerprints Fingerprints, fileManifestDigest string) string {
	fields := []string{
		commitmentDomain, strconv.Itoa(SchemaVersion), inventoryDigest, root,
		exact.PackageGeneration, exact.ArchiveSHA256, exact.PayloadSHA256, exact.MetadataSHA256,
		exact.NodeSHA256, exact.PackageCommandSHA256, exact.ConnectorSHA256,
		exact.ModelRepository, exact.ModelSnapshot, exact.ModelManifestSHA256,
		topologyDigest, fingerprints.CA, fingerprints.Coordinator, fingerprints.Worker,
		fingerprints.Connector, fileManifestDigest,
	}
	hash := sha256.New()
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = io.WriteString(hash, field)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
