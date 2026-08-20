// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var interfacePattern = regexp.MustCompile(`^utun[0-9]+$`)

type DarwinBackend struct {
	mu            sync.Mutex
	device        wireGuardDevice
	interfaceName string
	directRoute   bool
	relayAlias    string
	relayRoutes   []string
	applied       *Specification
	runCommand    systemCommandRunner
	commandOutput systemCommandOutputRunner
}

type wireGuardDevice interface {
	IpcGet() (string, error)
	IpcSetOperation(io.Reader) error
	Up() error
	Close()
}

type systemCommandRunner func(path string, arguments ...string) error
type systemCommandOutputRunner func(path string, arguments ...string) (string, error)

func NewDarwinBackend() *DarwinBackend {
	return &DarwinBackend{runCommand: fixedSystemCommand, commandOutput: fixedSystemCommandOutput}
}

func (backend *DarwinBackend) Apply(spec Specification) (string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if err := spec.Validate(); err != nil {
		return "", err
	}
	created := false
	if backend.device == nil {
		if err := backend.createInterface(spec); err != nil {
			return "", err
		}
		created = true
	}
	var prior *Specification
	if backend.applied != nil {
		copy := *backend.applied
		prior = &copy
	}
	if spec.Relay != nil {
		if err := backend.validateRelayRouteAuthority(spec, prior); err != nil {
			if created {
				backend.discardCreatedInterface()
			}
			return "", err
		}
	}
	if err := backend.applyAuthority(spec); err != nil {
		if created {
			backend.discardCreatedInterface()
			return "", err
		}
		if prior != nil {
			if restoreErr := backend.applyAuthority(*prior); restoreErr != nil {
				return "", errors.Join(err, fmt.Errorf("relay transaction rollback failed: %w", restoreErr))
			}
			backend.applied = prior
		}
		return "", err
	}
	copy := spec
	backend.applied = &copy
	return backend.interfaceName, nil
}

func (backend *DarwinBackend) createInterface(spec Specification) error {
	tunnel, err := tun.CreateTUN("utun", spec.MTU)
	if err != nil {
		return err
	}
	name, err := tunnel.Name()
	if err != nil || !interfacePattern.MatchString(name) {
		_ = tunnel.Close()
		return errors.New("unexpected interface identity")
	}
	backend.interfaceName = name
	backend.device = device.NewDevice(tunnel, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	privateKey, _ := DecodeKey(spec.PrivateKey)
	base := fmt.Sprintf("private_key=%s\nlisten_port=%d\n\n", hex.EncodeToString(privateKey), spec.Port)
	if err := backend.device.IpcSetOperation(strings.NewReader(base)); err != nil {
		backend.discardCreatedInterface()
		return err
	}
	if err := configureDarwinInterface(backend.interfaceName, spec, backend.runCommand); err != nil {
		backend.discardCreatedInterface()
		return err
	}
	backend.directRoute = true
	if err := backend.device.Up(); err != nil {
		backend.discardCreatedInterface()
		return err
	}
	return nil
}

func (backend *DarwinBackend) applyAuthority(spec Specification) error {
	// Relay packets must not cross a half-applied authority. Direct routes and
	// direct peers stay live throughout this transaction.
	retiredAlias := backend.relayAlias
	retiredRoutes := append([]string(nil), backend.relayRoutes...)
	if err := backend.removeRelayPath(); err != nil {
		return fmt.Errorf("could not quiesce relay path: %w", err)
	}
	if err := backend.verifyRetiredRelayPath(retiredAlias, retiredRoutes); err != nil {
		return fmt.Errorf("could not verify relay quiescence: %w", err)
	}
	if err := backend.applyPeerDiff(spec); err != nil {
		return fmt.Errorf("could not apply exact peer diff: %w", err)
	}
	if err := backend.verifyManifest(spec); err != nil {
		return fmt.Errorf("peer manifest verification failed: %w", err)
	}
	if spec.Relay != nil {
		if err := backend.installRelayPath(*spec.Relay); err != nil {
			return fmt.Errorf("could not publish relay path: %w", err)
		}
	}
	if err := backend.verifyRelayPath(spec.Relay); err != nil {
		return fmt.Errorf("relay path verification failed: %w", err)
	}
	return nil
}

type peerRuntimeState struct {
	Allowed   []string
	Endpoint  string
	Keepalive int
}

type interfaceRuntimeState struct {
	PrivateKey string
	ListenPort int
	Peers      map[string]peerRuntimeState
}

func (backend *DarwinBackend) state() (interfaceRuntimeState, error) {
	text, err := backend.device.IpcGet()
	if err != nil {
		return interfaceRuntimeState{}, err
	}
	state := interfaceRuntimeState{Peers: map[string]peerRuntimeState{}}
	var key string
	var peer peerRuntimeState
	flush := func() {
		if key == "" {
			return
		}
		sort.Strings(peer.Allowed)
		state.Peers[key] = peer
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch name {
		case "private_key":
			raw, decodeErr := hex.DecodeString(value)
			if decodeErr != nil || len(raw) != 32 {
				return interfaceRuntimeState{}, errors.New("invalid UAPI private key")
			}
			state.PrivateKey = base64.StdEncoding.EncodeToString(raw)
		case "listen_port":
			state.ListenPort, _ = strconv.Atoi(value)
		case "public_key":
			flush()
			raw, decodeErr := hex.DecodeString(value)
			if decodeErr != nil || len(raw) != 32 {
				return interfaceRuntimeState{}, errors.New("invalid UAPI public key")
			}
			key = base64.StdEncoding.EncodeToString(raw)
			peer = peerRuntimeState{}
		case "allowed_ip":
			if key != "" {
				peer.Allowed = append(peer.Allowed, value)
			}
		case "endpoint":
			if key != "" {
				peer.Endpoint = value
			}
		case "persistent_keepalive_interval":
			peer.Keepalive, _ = strconv.Atoi(value)
		}
	}
	flush()
	return state, scanner.Err()
}

func (backend *DarwinBackend) applyPeerDiff(spec Specification) error {
	actual, err := backend.state()
	if err != nil {
		return err
	}
	for _, mutation := range planPeerDiff(actual.Peers, spec.DesiredPeers()) {
		switch mutation.kind {
		case removePeerMutation:
			err = backend.removePeer(mutation.publicKey)
		case setPeerMutation:
			err = backend.setPeer(mutation.peer, mutation.updateOnly)
		case endpointPeerMutation:
			err = backend.updatePeerEndpoint(mutation.peer.PublicKey, mutation.peer.Endpoint)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type peerMutationKind uint8

const (
	removePeerMutation peerMutationKind = iota
	setPeerMutation
	endpointPeerMutation
)

type peerMutation struct {
	kind       peerMutationKind
	publicKey  string
	peer       DesiredPeer
	updateOnly bool
}

func planPeerDiff(actual map[string]peerRuntimeState, desired []DesiredPeer) []peerMutation {
	desiredByKey := make(map[string]DesiredPeer, len(desired))
	for _, peer := range desired {
		desiredByKey[peer.PublicKey] = peer
	}
	actualKeys := make([]string, 0, len(actual))
	for key := range actual {
		actualKeys = append(actualKeys, key)
	}
	sort.Strings(actualKeys)
	var mutations []peerMutation
	for _, key := range actualKeys {
		if _, exists := desiredByKey[key]; !exists {
			mutations = append(mutations, peerMutation{kind: removePeerMutation, publicKey: key})
		}
	}
	for _, peer := range desired {
		current, exists := actual[peer.PublicKey]
		wantAllowed := append([]string(nil), peer.Allowed...)
		sort.Strings(wantAllowed)
		staticMatches := exists && slicesEqual(current.Allowed, wantAllowed) && current.Keepalive == peer.Keepalive
		if staticMatches {
			if peer.Hub && current.Endpoint != peer.Endpoint {
				mutations = append(mutations, peerMutation{kind: endpointPeerMutation, peer: peer})
			}
			continue
		}
		// A changed hub route set deliberately removes and re-adds that peer.
		// This flushes its staged packets before new AllowedIPs become
		// authoritative. Unchanged direct peers never enter this branch.
		if exists && peer.Hub {
			mutations = append(mutations, peerMutation{kind: removePeerMutation, publicKey: peer.PublicKey})
			exists = false
		}
		mutations = append(mutations, peerMutation{kind: setPeerMutation, peer: peer, updateOnly: exists})
	}
	return mutations
}

func (backend *DarwinBackend) setPeer(peer DesiredPeer, updateOnly bool) error {
	publicKey, _ := DecodeKey(peer.PublicKey)
	var source strings.Builder
	fmt.Fprintf(&source, "public_key=%s\n", hex.EncodeToString(publicKey))
	if updateOnly {
		source.WriteString("update_only=true\n")
	}
	if peer.Endpoint != "" {
		fmt.Fprintf(&source, "endpoint=%s\n", peer.Endpoint)
	}
	source.WriteString("replace_allowed_ips=true\n")
	for _, route := range peer.Allowed {
		fmt.Fprintf(&source, "allowed_ip=%s\n", route)
	}
	fmt.Fprintf(&source, "persistent_keepalive_interval=%d\n\n", peer.Keepalive)
	return backend.device.IpcSetOperation(strings.NewReader(source.String()))
}

func (backend *DarwinBackend) updatePeerEndpoint(publicKey, endpoint string) error {
	key, _ := DecodeKey(publicKey)
	source := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n\n", hex.EncodeToString(key), endpoint)
	return backend.device.IpcSetOperation(strings.NewReader(source))
}

func (backend *DarwinBackend) removePeer(publicKey string) error {
	key, _ := DecodeKey(publicKey)
	source := fmt.Sprintf("public_key=%s\nremove=true\n\n", hex.EncodeToString(key))
	return backend.device.IpcSetOperation(strings.NewReader(source))
}

func (backend *DarwinBackend) verifyManifest(spec Specification) error {
	actual, err := backend.state()
	if err != nil {
		return err
	}
	if actual.PrivateKey != spec.PrivateKey || actual.ListenPort != spec.Port || len(actual.Peers) != len(spec.DesiredPeers()) {
		return errors.New("interface authority differs from specification")
	}
	for _, peer := range spec.DesiredPeers() {
		current, ok := actual.Peers[peer.PublicKey]
		wantAllowed := append([]string(nil), peer.Allowed...)
		sort.Strings(wantAllowed)
		if !ok || !slicesEqual(current.Allowed, wantAllowed) || current.Keepalive != peer.Keepalive {
			return errors.New("peer authority differs from specification")
		}
		if peer.Hub && current.Endpoint != peer.Endpoint {
			return errors.New("hub endpoint differs from specification")
		}
	}
	return nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (backend *DarwinBackend) installRelayPath(relay Relay) error {
	host := strings.TrimSuffix(relay.Address, "/32")
	if err := backend.runCommand("/sbin/ifconfig", backend.interfaceName, "inet", relay.Address, host, "alias"); err != nil {
		return err
	}
	backend.relayAlias = relay.Address
	for _, route := range relay.Routes {
		if err := backend.runCommand("/sbin/route", "-q", "-n", "add", "-inet", route, "-interface", backend.interfaceName); err != nil {
			_ = backend.removeRelayPath()
			return err
		}
		backend.relayRoutes = append(backend.relayRoutes, route)
	}
	return nil
}

func (backend *DarwinBackend) removeRelayPath() error {
	owners, err := backend.relayRouteOwners(backend.relayRoutes)
	if err != nil {
		return err
	}
	for _, route := range backend.relayRoutes {
		for owner := range owners[route] {
			if owner != backend.interfaceName {
				return errors.New("recorded relay route is owned by another interface")
			}
		}
	}

	deleteErrors := make(map[string]error)
	for index := len(backend.relayRoutes) - 1; index >= 0; index-- {
		route := backend.relayRoutes[index]
		if !owners[route][backend.interfaceName] {
			continue
		}
		if err := backend.runCommand(
			"/sbin/route", "-q", "-n", "delete", "-inet", route, "-interface", backend.interfaceName,
		); err != nil {
			deleteErrors[route] = err
		}
	}

	remainingOwners, inspectErr := backend.relayRouteOwners(backend.relayRoutes)
	if inspectErr != nil {
		result := error(inspectErr)
		for _, deleteErr := range deleteErrors {
			result = errors.Join(result, deleteErr)
		}
		return result
	}
	var result error
	remainingRoutes := make([]string, 0, len(backend.relayRoutes))
	for _, route := range backend.relayRoutes {
		owners := remainingOwners[route]
		if len(owners) == 0 {
			continue
		}
		remainingRoutes = append(remainingRoutes, route)
		if owners[backend.interfaceName] {
			result = errors.Join(result, deleteErrors[route], errors.New("relay route remained after interface-qualified deletion"))
		} else {
			result = errors.Join(result, errors.New("relay route moved to another interface during deletion"))
		}
	}
	backend.relayRoutes = remainingRoutes
	if len(remainingRoutes) != 0 {
		return result
	}
	if backend.relayAlias != "" {
		host := strings.TrimSuffix(backend.relayAlias, "/32")
		if err := backend.runCommand("/sbin/ifconfig", backend.interfaceName, "inet", host, "-alias"); err != nil {
			present, inspectErr := backend.relayAliasPresent(backend.relayAlias)
			if inspectErr != nil || present {
				result = errors.Join(result, err, inspectErr)
			} else {
				backend.relayAlias = ""
			}
		} else {
			backend.relayAlias = ""
		}
	}
	return result
}

func (backend *DarwinBackend) relayRouteOwners(routes []string) (map[string]map[string]bool, error) {
	wanted := make(map[string]string, len(routes))
	owners := make(map[string]map[string]bool, len(routes))
	for _, route := range routes {
		network, length, ok := parseDarwinRouteDestination(route)
		if !ok {
			return nil, errors.New("invalid relay route bookkeeping")
		}
		wanted[darwinRouteKey(network, length)] = route
		owners[route] = make(map[string]bool)
	}
	if len(routes) == 0 {
		return owners, nil
	}
	output, err := backend.commandOutput("/usr/sbin/netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	for _, current := range parseDarwinRoutes(output) {
		route, ok := wanted[darwinRouteKey(current.network, current.length)]
		if ok {
			owners[route][current.interfaceName] = true
		}
	}
	return owners, nil
}

func (backend *DarwinBackend) verifyRelayPath(relay *Relay) error {
	output, err := backend.commandOutput("/sbin/ifconfig", backend.interfaceName)
	if err != nil {
		return err
	}
	if mtu, ok := ifconfigMTU(output); !ok || mtu != InterfaceMTU {
		return errors.New("mesh interface MTU differs from authority")
	}
	if !ifconfigHasAddressAndNetmask(output, strings.TrimSuffix(HostAddress, "/24"), "0xffffff00") {
		return errors.New("direct mesh address or netmask differs from authority")
	}
	wantAddresses := map[string]bool{
		strings.TrimSuffix(HostAddress, "/24"): true,
	}
	if relay == nil {
		if backend.relayAlias != "" || len(backend.relayRoutes) != 0 {
			return errors.New("relay bookkeeping remained after removal")
		}
	} else {
		host := strings.TrimSuffix(relay.Address, "/32")
		wantAddresses[host] = true
		if !ifconfigHasAddressAndNetmask(output, host, "0xffffffff") {
			return errors.New("relay alias or netmask differs from authority")
		}
	}
	actualAddresses := ifconfigIPv4Addresses(output)
	for address := range actualAddresses {
		if !wantAddresses[address] {
			return errors.New("unowned IPv4 alias remains on mesh interface")
		}
	}
	for address := range wantAddresses {
		if !actualAddresses[address] {
			return errors.New("mesh interface address missing")
		}
	}

	wantRoutes := map[string]bool{}
	addRoute := func(route string) error {
		network, length, ok := parseDarwinRouteDestination(route)
		if !ok {
			return errors.New("invalid expected mesh route")
		}
		wantRoutes[darwinRouteKey(network, length)] = true
		return nil
	}
	if err := addRoute(MeshNetwork); err != nil {
		return err
	}
	// Darwin may render an interface-local host route in addition to the
	// configured direct network route. It carries no relay traffic but is part
	// of the complete allowed same-interface path manifest.
	if err := addRoute(strings.TrimSuffix(HostAddress, "/24") + "/32"); err != nil {
		return err
	}
	if relay != nil {
		if err := addRoute(relay.Address); err != nil {
			return err
		}
		for _, route := range relay.Routes {
			if err := addRoute(route); err != nil {
				return err
			}
		}
	}
	routesOutput, err := backend.commandOutput("/usr/sbin/netstat", "-rn", "-f", "inet")
	if err != nil {
		return err
	}
	actualRoutes := map[string]bool{}
	for _, route := range parseDarwinRoutes(routesOutput) {
		if route.interfaceName != backend.interfaceName {
			continue
		}
		key := darwinRouteKey(route.network, route.length)
		actualRoutes[key] = true
		if !wantRoutes[key] {
			return errors.New("unowned IPv4 route remains on mesh interface")
		}
	}
	directNetwork, directLength, _ := parseDarwinRouteDestination(MeshNetwork)
	if !actualRoutes[darwinRouteKey(directNetwork, directLength)] {
		return errors.New("direct mesh route missing")
	}
	if relay != nil {
		for _, route := range relay.Routes {
			network, length, _ := parseDarwinRouteDestination(route)
			if !actualRoutes[darwinRouteKey(network, length)] {
				return errors.New("relay route missing from mesh interface")
			}
		}
	}
	return nil
}

func (backend *DarwinBackend) verifyRetiredRelayPath(alias string, routes []string) error {
	if alias != "" {
		present, err := backend.relayAliasPresent(alias)
		if err != nil {
			return err
		}
		if present {
			return errors.New("retired relay alias remained")
		}
	}
	owners, err := backend.relayRouteOwners(routes)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if owners[route][backend.interfaceName] {
			return errors.New("retired relay route remained")
		}
	}
	return backend.verifyRelayPath(nil)
}

func (backend *DarwinBackend) relayAliasPresent(address string) (bool, error) {
	output, err := backend.commandOutput("/sbin/ifconfig", backend.interfaceName)
	if err != nil {
		return false, err
	}
	return ifconfigHasAddress(output, strings.TrimSuffix(address, "/32")), nil
}

func ifconfigHasAddress(output, address string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "inet" && fields[1] == address {
			return true
		}
	}
	return false
}

func ifconfigHasAddressAndNetmask(output, address, netmask string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "inet" || fields[1] != address {
			continue
		}
		for index := 2; index+1 < len(fields); index++ {
			if fields[index] == "netmask" && fields[index+1] == netmask {
				return true
			}
		}
	}
	return false
}

func ifconfigMTU(output string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for index := 0; index+1 < len(fields); index++ {
			if fields[index] == "mtu" {
				value, err := strconv.Atoi(fields[index+1])
				return value, err == nil
			}
		}
	}
	return 0, false
}

func ifconfigIPv4Addresses(output string) map[string]bool {
	addresses := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "inet" && net.ParseIP(fields[1]).To4() != nil {
			addresses[fields[1]] = true
		}
	}
	return addresses
}

type darwinRoute struct {
	network       uint32
	length        int
	text          string
	interfaceName string
}

func darwinRouteKey(network uint32, length int) string {
	return fmt.Sprintf("%08x/%d", network, length)
}

func (route darwinRoute) overlaps(network uint32, length int) bool {
	shared := route.length
	if length < shared {
		shared = length
	}
	mask := uint32(0xffffffff)
	if shared < 32 {
		mask <<= uint32(32 - shared)
	}
	return route.network&mask == network&mask
}

func parseDarwinRouteDestination(value string) (uint32, int, bool) {
	if value == "default" {
		return 0, 0, false
	}
	addressText := value
	length := -1
	if before, after, ok := strings.Cut(value, "/"); ok {
		addressText = before
		parsed, err := strconv.Atoi(after)
		if err != nil || parsed < 1 || parsed > 32 {
			return 0, 0, false
		}
		length = parsed
	}
	parts := strings.Split(addressText, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return 0, 0, false
	}
	octets := [4]byte{}
	for index, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 || strconv.Itoa(value) != part {
			return 0, 0, false
		}
		octets[index] = byte(value)
	}
	if length < 0 {
		length = len(parts) * 8
	}
	raw := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
	mask := uint32(0xffffffff)
	if length < 32 {
		mask <<= uint32(32 - length)
	}
	return raw & mask, length, true
}

func parseDarwinRoutes(output string) []darwinRoute {
	var routes []darwinRoute
	inInternet := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "Internet:" {
			inInternet = true
			continue
		}
		if strings.HasSuffix(line, ":") && line != "Internet:" {
			inInternet = false
		}
		fields := strings.Fields(line)
		if !inInternet || len(fields) < 4 || fields[0] == "Destination" || fields[0] == "default" {
			continue
		}
		network, length, ok := parseDarwinRouteDestination(fields[0])
		if !ok {
			continue
		}
		// `netstat -rn` may append an Expire column. Netif is the fourth
		// whitespace-delimited field in the fixed Darwin IPv4 table shape.
		routes = append(routes, darwinRoute{network: network, length: length, text: fields[0], interfaceName: fields[3]})
	}
	return routes
}

func (backend *DarwinBackend) validateRelayRouteAuthority(candidate Specification, prior *Specification) error {
	output, err := backend.commandOutput("/usr/sbin/netstat", "-rn", "-f", "inet")
	if err != nil {
		return errors.New("could not inspect active IPv4 routes")
	}
	ip, network, _ := net.ParseCIDR(candidate.Relay.Network)
	maskSize, _ := network.Mask.Size()
	octets := ip.To4()
	raw := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
	exempt := map[string]bool{}
	if prior != nil && prior.Relay != nil && prior.Relay.Network == candidate.Relay.Network {
		exempt[strings.TrimSuffix(prior.Relay.Address, "/32")] = true
		exempt[prior.Relay.Address] = true
		for _, route := range prior.Relay.Routes {
			exempt[route] = true
			exempt[strings.TrimSuffix(route, "/32")] = true
		}
	}
	for _, route := range parseDarwinRoutes(output) {
		if route.overlaps(raw, maskSize) {
			if route.interfaceName == backend.interfaceName && exempt[route.text] {
				continue
			}
			return errors.New("relay network overlaps an active IPv4 route")
		}
	}
	return nil
}

func (backend *DarwinBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	result := backend.removeRelayPath()
	if backend.directRoute {
		result = errors.Join(result, removeDarwinRoute(backend.runCommand))
		backend.directRoute = false
	}
	if backend.device != nil {
		backend.device.Close()
		backend.device = nil
		backend.interfaceName = ""
		backend.applied = nil
	}
	return result
}

func (backend *DarwinBackend) discardCreatedInterface() {
	_ = backend.removeRelayPath()
	if backend.directRoute {
		_ = removeDarwinRoute(backend.runCommand)
		backend.directRoute = false
	}
	if backend.device != nil {
		backend.device.Close()
		backend.device = nil
	}
	backend.interfaceName = ""
	backend.applied = nil
}

func configureDarwinInterface(interfaceName string, spec Specification, run systemCommandRunner) error {
	host := strings.TrimSuffix(spec.Address, "/24")
	commands := []struct {
		path      string
		arguments []string
	}{
		{path: "/sbin/ifconfig", arguments: []string{interfaceName, "inet", spec.Address, host, "alias"}},
		{path: "/sbin/ifconfig", arguments: []string{interfaceName, "mtu", strconv.Itoa(spec.MTU)}},
		{path: "/sbin/ifconfig", arguments: []string{interfaceName, "up"}},
		{path: "/sbin/route", arguments: []string{"-q", "-n", "add", "-inet", MeshNetwork, "-interface", interfaceName}},
	}
	for _, command := range commands {
		if err := run(command.path, command.arguments...); err != nil {
			return err
		}
	}
	return nil
}

func removeDarwinRoute(run systemCommandRunner) error {
	return run("/sbin/route", "-q", "-n", "delete", "-inet", MeshNetwork)
}

func fixedSystemCommand(path string, arguments ...string) error {
	_, err := fixedSystemCommandOutput(path, arguments...)
	return err
}

func fixedSystemCommandOutput(path string, arguments ...string) (string, error) {
	operationContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(operationContext, path, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("system operation failed: %w: %s", err, bytes.TrimSpace(output))
	}
	return string(output), nil
}
