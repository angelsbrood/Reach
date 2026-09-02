package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func LoadInventory(path string, now time.Time) (Inventory, []byte, string, error) {
	data, err := loadInventoryBytes(path)
	if err != nil {
		return Inventory{}, nil, "", err
	}
	return DecodeInventory(data, now)
}

func LoadInventoryForRecovery(path string) (Inventory, []byte, string, error) {
	data, err := loadInventoryBytes(path)
	if err != nil {
		return Inventory{}, nil, "", err
	}
	return DecodeInventoryForRecovery(data)
}

func loadInventoryBytes(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("inventory path must be absolute and canonical")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() > maxInventoryBytes || linkCount(pathInfo) != 1 || ownerID(pathInfo) != os.Geteuid() || pathInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("inventory must be a bounded current-user regular single-link file without group/world write")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open inventory: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() || info.Size() > maxInventoryBytes || linkCount(info) != 1 {
		return nil, errors.New("inventory must be a bounded regular single-link file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxInventoryBytes+1))
	if err != nil || len(data) > maxInventoryBytes {
		return nil, errors.New("inventory exceeds the bounded input limit")
	}
	return data, nil
}

func DecodeInventoryForRecovery(data []byte) (Inventory, []byte, string, error) {
	var value Inventory
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Inventory{}, nil, "", fmt.Errorf("decode inventory: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Inventory{}, nil, "", errors.New("inventory contains a trailing JSON value")
	}
	expiry, err := time.Parse(time.RFC3339, value.CertificateExpiry)
	if err != nil {
		return Inventory{}, nil, "", errors.New("certificate_expiry must be canonical UTC RFC3339 seconds")
	}
	if err := value.Validate(expiry.Add(-24 * time.Hour)); err != nil {
		return Inventory{}, nil, "", err
	}
	canonical, digest, err := canonicalInventory(value)
	if err != nil {
		return Inventory{}, nil, "", err
	}
	return value, canonical, digest, nil
}

func canonicalInventory(value Inventory) ([]byte, string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(digest[:]), nil
}

func DecodeInventory(data []byte, now time.Time) (Inventory, []byte, string, error) {
	var value Inventory
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Inventory{}, nil, "", fmt.Errorf("decode inventory: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Inventory{}, nil, "", errors.New("inventory contains a trailing JSON value")
	}
	if err := value.Validate(now); err != nil {
		return Inventory{}, nil, "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return Inventory{}, nil, "", err
	}
	digest := sha256.Sum256(canonical)
	return value, canonical, hex.EncodeToString(digest[:]), nil
}

func (i Inventory) Validate(now time.Time) error {
	if i.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if !safeName(i.Namespace) || len(i.Namespace) > 48 {
		return errors.New("namespace must be a safe lowercase name of at most 48 bytes")
	}
	if !validRootSpelling(i.AuthorityRoot) {
		return errors.New("authority_root must be an absolute canonical non-root path")
	}
	prefix, err := netip.ParsePrefix(i.PrivateNetwork)
	if err != nil || !prefix.Addr().Is4() || prefix.String() != i.PrivateNetwork || prefix.Addr() != prefix.Masked().Addr() || prefix.Bits() < 24 || prefix.Bits() > 29 || !prefix.Addr().IsPrivate() {
		return errors.New("private_network_cidr must be canonical RFC1918 IPv4 /24 through /29")
	}
	if i.GatewayMode != GatewayDirect && i.GatewayMode != GatewayTunnel {
		return errors.New("gateway_mode must be direct-gateway or loopback-tunnel")
	}
	if i.Coordinator.Name == i.Worker.Name || i.Coordinator.Address == i.Worker.Address || i.Coordinator.MACAddress == i.Worker.MACAddress {
		return errors.New("coordinator and worker names, addresses, and MACs must be distinct")
	}
	for role, node := range map[string]NodeInventory{"coordinator": i.Coordinator, "worker": i.Worker} {
		if !safeName(node.Name) || len(node.Name) > 63 {
			return fmt.Errorf("%s name is not a safe lowercase name", role)
		}
		if !safeInterface(node.Interface) {
			return fmt.Errorf("%s interface is not a canonical Linux interface", role)
		}
		if err := validCanonicalMAC(node.MACAddress); err != nil {
			return fmt.Errorf("%s MAC: %w", role, err)
		}
	}
	addresses := []string{i.Coordinator.Address, i.Worker.Address, i.ConnectorAddress}
	seen := map[netip.Addr]bool{}
	for _, text := range addresses {
		address, err := netip.ParseAddr(text)
		if err != nil || !address.Is4() || address.String() != text || !prefix.Contains(address) || !usableHost(prefix, address) {
			return errors.New("every endpoint must be a canonical distinct usable IPv4 host inside the private network")
		}
		if seen[address] {
			return errors.New("all three endpoint addresses must be distinct")
		}
		seen[address] = true
	}
	expiry, err := time.Parse(time.RFC3339, i.CertificateExpiry)
	if err != nil || expiry.Location() != time.UTC || expiry.Format(time.RFC3339) != i.CertificateExpiry {
		return errors.New("certificate_expiry must be canonical UTC RFC3339 seconds")
	}
	delta := expiry.Sub(now.UTC())
	if delta < 24*time.Hour || delta > 825*24*time.Hour {
		return errors.New("certificate_expiry must be at least 24 hours and at most 825 days after creation")
	}
	return nil
}

func validRootSpelling(root string) bool {
	return filepath.IsAbs(root) && filepath.Clean(root) == root && root != string(filepath.Separator) && filepath.Base(root) != "." && filepath.Base(root) != ".."
}

func validatePublicationParent(root string) error {
	if !validRootSpelling(root) {
		return errors.New("authority root spelling is unsafe")
	}
	parent := filepath.Dir(root)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("authority root parent must exist without symlink aliases")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || ownerID(info) != os.Geteuid() {
		return errors.New("authority root parent must be an owner-only directory owned by the current user")
	}
	return nil
}

func usableHost(prefix netip.Prefix, address netip.Addr) bool {
	network := addressUint32(prefix.Masked().Addr())
	value := addressUint32(address)
	hostBits := uint(32 - prefix.Bits())
	broadcast := network | uint32((uint64(1)<<hostBits)-1)
	return value > network && value < broadcast
}

func addressUint32(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func validCanonicalMAC(value string) error {
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 || parsed.String() != value || parsed[0]&1 != 0 {
		return errors.New("must be a canonical lowercase unicast EUI-48 address")
	}
	zero := true
	for _, value := range parsed {
		zero = zero && value == 0
	}
	if zero {
		return errors.New("zero MAC is forbidden")
	}
	return nil
}

func safeName(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	for _, runeValue := range value {
		if (runeValue < 'a' || runeValue > 'z') && (runeValue < '0' || runeValue > '9') && runeValue != '-' {
			return false
		}
	}
	return true
}

func safeInterface(value string) bool {
	if value == "" || len(value) > 15 || value == "." || value == ".." {
		return false
	}
	for _, runeValue := range value {
		if (runeValue < 'a' || runeValue > 'z') && (runeValue < 'A' || runeValue > 'Z') && (runeValue < '0' || runeValue > '9') && runeValue != '-' && runeValue != '_' && runeValue != '.' {
			return false
		}
	}
	return true
}

func ownerID(info os.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}

func linkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}
