// SPDX-License-Identifier: MIT

package mesh

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeWireGuardDevice struct {
	state      interfaceRuntimeState
	operations []string
}

func (device *fakeWireGuardDevice) IpcGet() (string, error) {
	privateKey, _ := base64.StdEncoding.DecodeString(device.state.PrivateKey)
	var output strings.Builder
	fmt.Fprintf(&output, "private_key=%s\nlisten_port=%d\n", hex.EncodeToString(privateKey), device.state.ListenPort)
	keys := make([]string, 0, len(device.state.Peers))
	for key := range device.state.Peers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		publicKey, _ := base64.StdEncoding.DecodeString(key)
		peer := device.state.Peers[key]
		fmt.Fprintf(&output, "public_key=%s\n", hex.EncodeToString(publicKey))
		for _, route := range peer.Allowed {
			fmt.Fprintf(&output, "allowed_ip=%s\n", route)
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&output, "endpoint=%s\n", peer.Endpoint)
		}
		fmt.Fprintf(&output, "persistent_keepalive_interval=%d\n", peer.Keepalive)
	}
	return output.String(), nil
}

func (device *fakeWireGuardDevice) IpcSetOperation(reader io.Reader) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	operation := string(data)
	device.operations = append(device.operations, operation)
	var key string
	var remove, replaceAllowed bool
	var allowed []string
	var endpoint *string
	var keepalive *int
	scanner := bufio.NewScanner(strings.NewReader(operation))
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch name {
		case "private_key":
			raw, decodeErr := hex.DecodeString(value)
			if decodeErr != nil {
				return decodeErr
			}
			device.state.PrivateKey = base64.StdEncoding.EncodeToString(raw)
		case "listen_port":
			device.state.ListenPort, _ = strconv.Atoi(value)
		case "public_key":
			raw, decodeErr := hex.DecodeString(value)
			if decodeErr != nil {
				return decodeErr
			}
			key = base64.StdEncoding.EncodeToString(raw)
		case "remove":
			remove = value == "true"
		case "replace_allowed_ips":
			replaceAllowed = value == "true"
		case "allowed_ip":
			allowed = append(allowed, value)
		case "endpoint":
			copy := value
			endpoint = &copy
		case "persistent_keepalive_interval":
			value, parseErr := strconv.Atoi(value)
			if parseErr != nil {
				return parseErr
			}
			keepalive = &value
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if key == "" {
		return nil
	}
	if remove {
		delete(device.state.Peers, key)
		return nil
	}
	peer := device.state.Peers[key]
	if replaceAllowed {
		peer.Allowed = append([]string(nil), allowed...)
	}
	if endpoint != nil {
		peer.Endpoint = *endpoint
	}
	if keepalive != nil {
		peer.Keepalive = *keepalive
	}
	device.state.Peers[key] = peer
	return nil
}

func (*fakeWireGuardDevice) Up() error { return nil }
func (*fakeWireGuardDevice) Close()    {}

type fakeDarwinNetwork struct {
	interfaceName string
	aliases       map[string]bool
	routes        map[string]string
	commands      []string
	queries       []string
	directRoute   bool
	directNetmask string
	mtu           int
	failRouteAdd  bool
	commandDelay  time.Duration
	afterDelete   func(string)
}

func newFakeDarwinNetwork(interfaceName string) *fakeDarwinNetwork {
	return &fakeDarwinNetwork{
		interfaceName: interfaceName,
		aliases:       map[string]bool{},
		routes:        map[string]string{},
		directRoute:   true,
		directNetmask: "0xffffff00",
		mtu:           InterfaceMTU,
	}
}

func (network *fakeDarwinNetwork) run(path string, arguments ...string) error {
	network.commands = append(network.commands, strings.Join(append([]string{path}, arguments...), " "))
	if network.commandDelay > 0 {
		time.Sleep(network.commandDelay)
	}
	if path == "/sbin/ifconfig" && len(arguments) >= 4 && arguments[1] == "inet" {
		if arguments[len(arguments)-1] == "alias" {
			network.aliases[strings.TrimSuffix(arguments[2], "/32")] = true
		} else if arguments[len(arguments)-1] == "-alias" {
			delete(network.aliases, arguments[2])
		}
		return nil
	}
	if path == "/sbin/route" && len(arguments) >= 5 {
		switch arguments[2] {
		case "add":
			if network.failRouteAdd {
				network.failRouteAdd = false
				return errors.New("injected relay route failure")
			}
			owner := network.interfaceName
			if len(arguments) >= 7 && arguments[5] == "-interface" {
				owner = arguments[6]
			}
			network.routes[arguments[4]] = owner
		case "delete":
			if len(arguments) >= 7 && arguments[5] == "-interface" {
				if network.routes[arguments[4]] != arguments[6] {
					return errors.New("route owner differs")
				}
			}
			delete(network.routes, arguments[4])
			if network.afterDelete != nil {
				network.afterDelete(arguments[4])
			}
		}
	}
	return nil
}

func (network *fakeDarwinNetwork) output(path string, arguments ...string) (string, error) {
	network.queries = append(network.queries, strings.Join(append([]string{path}, arguments...), " "))
	switch path {
	case "/sbin/ifconfig":
		var output strings.Builder
		fmt.Fprintf(&output, "%s: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu %d\n", network.interfaceName, network.mtu)
		fmt.Fprintf(&output, "inet 10.86.0.1 netmask %s\n", network.directNetmask)
		keys := make([]string, 0, len(network.aliases))
		for address := range network.aliases {
			keys = append(keys, address)
		}
		sort.Strings(keys)
		for _, address := range keys {
			fmt.Fprintf(&output, "inet %s netmask 0xffffffff\n", address)
		}
		return output.String(), nil
	case "/usr/sbin/netstat":
		var output strings.Builder
		output.WriteString("Internet:\nDestination Gateway Flags Netif Expire\n")
		if network.directRoute {
			fmt.Fprintf(&output, "10.86/24 %s USc %s\n", network.interfaceName, network.interfaceName)
		}
		keys := make([]string, 0, len(network.routes))
		for route := range network.routes {
			keys = append(keys, route)
		}
		sort.Strings(keys)
		for _, route := range keys {
			fmt.Fprintf(&output, "%s %s UH %s\n", strings.TrimSuffix(route, "/32"), strings.TrimSuffix(route, "/32"), network.routes[route])
		}
		return output.String(), nil
	case "/sbin/route":
		if len(arguments) >= 3 && arguments[0] == "-n" && arguments[1] == "get" {
			if owner, ok := network.routes[arguments[2]+"/32"]; ok {
				return "interface: " + owner + "\n", nil
			}
			return "", errors.New("route absent")
		}
	}
	return "", errors.New("unexpected fake system query")
}

func relayCandidate(t *testing.T, direct Specification, generation uint64) Specification {
	t.Helper()
	_, hubPublic := testKeypair(t)
	direct.Version = RelaySpecificationVersion
	direct.Generation = generation
	direct.Relay = &Relay{
		Network: "10.87.0.0/24", Address: "10.87.0.1/32",
		HubPublicKey: hubPublic, Endpoint: "192.0.2.10:51821",
		Keepalive: RelayKeepalive, Routes: []string{"10.87.0.2/32"},
	}
	return direct
}

func fakeLiveDarwinBackend(spec Specification) (*DarwinBackend, *fakeWireGuardDevice, *fakeDarwinNetwork) {
	state := interfaceRuntimeState{
		PrivateKey: spec.PrivateKey,
		ListenPort: spec.Port,
		Peers:      map[string]peerRuntimeState{},
	}
	for _, peer := range spec.DesiredPeers() {
		state.Peers[peer.PublicKey] = peerRuntimeState{
			Allowed: append([]string(nil), peer.Allowed...), Endpoint: peer.Endpoint, Keepalive: peer.Keepalive,
		}
	}
	// This learned roaming endpoint is runtime state, not direct authority.
	direct := state.Peers[spec.Peers[0].PublicKey]
	direct.Endpoint = "198.51.100.20:60000"
	state.Peers[spec.Peers[0].PublicKey] = direct
	device := &fakeWireGuardDevice{state: state}
	network := newFakeDarwinNetwork("utun-test")
	backend := &DarwinBackend{
		device: device, interfaceName: "utun-test", directRoute: true,
		runCommand: network.run, commandOutput: network.output,
	}
	copy := spec
	backend.applied = &copy
	if spec.Relay != nil {
		backend.relayAlias = spec.Relay.Address
		backend.relayRoutes = append([]string(nil), spec.Relay.Routes...)
		network.aliases[strings.TrimSuffix(spec.Relay.Address, "/32")] = true
		for _, route := range spec.Relay.Routes {
			network.routes[route] = network.interfaceName
		}
	}
	return backend, device, network
}

func TestPeerDiffPreservesUnchangedDirectRuntimeAndUpdatesHubEndpointInPlace(t *testing.T) {
	direct := DesiredPeer{PublicKey: "direct", Allowed: []string{"10.86.0.2/32"}, Keepalive: 25}
	hub := DesiredPeer{
		PublicKey: "hub", Allowed: []string{"10.87.0.2/32"}, Endpoint: "192.0.2.11:51821",
		Keepalive: RelayKeepalive, Hub: true,
	}
	actual := map[string]peerRuntimeState{
		"direct": {Allowed: []string{"10.86.0.2/32"}, Endpoint: "198.51.100.20:60000", Keepalive: 25},
		"hub":    {Allowed: []string{"10.87.0.2/32"}, Endpoint: "192.0.2.10:51821", Keepalive: RelayKeepalive},
	}
	mutations := planPeerDiff(actual, []DesiredPeer{direct, hub})
	if len(mutations) != 1 || mutations[0].kind != endpointPeerMutation || mutations[0].peer.PublicKey != "hub" {
		t.Fatalf("mutations = %+v", mutations)
	}
}

func TestPeerDiffRecreatesOnlyHubWhenAllowedRoutesChange(t *testing.T) {
	direct := DesiredPeer{PublicKey: "direct", Allowed: []string{"10.86.0.2/32"}, Keepalive: 25}
	hub := DesiredPeer{
		PublicKey: "hub", Allowed: []string{"10.88.0.2/32"}, Endpoint: "192.0.2.10:51821",
		Keepalive: RelayKeepalive, Hub: true,
	}
	actual := map[string]peerRuntimeState{
		"direct": {Allowed: []string{"10.86.0.2/32"}, Endpoint: "198.51.100.20:60000", Keepalive: 25},
		"hub":    {Allowed: []string{"10.87.0.2/32"}, Endpoint: "192.0.2.10:51821", Keepalive: RelayKeepalive},
	}
	mutations := planPeerDiff(actual, []DesiredPeer{direct, hub})
	if len(mutations) != 2 || mutations[0].kind != removePeerMutation || mutations[0].publicKey != "hub" ||
		mutations[1].kind != setPeerMutation || mutations[1].peer.PublicKey != "hub" || mutations[1].updateOnly {
		t.Fatalf("mutations = %+v", mutations)
	}
}

func TestPeerDiffRemovesAbsentPeersAndUpdatesChangedDirectPeerWithoutFullReplacement(t *testing.T) {
	direct := DesiredPeer{PublicKey: "direct", Allowed: []string{"10.86.0.2/32"}, Keepalive: 25}
	actual := map[string]peerRuntimeState{
		"direct": {Allowed: []string{"10.86.0.2/32"}, Keepalive: 0},
		"stale":  {Allowed: []string{"10.86.0.3/32"}},
	}
	mutations := planPeerDiff(actual, []DesiredPeer{direct})
	if len(mutations) != 2 || mutations[0].kind != removePeerMutation || mutations[0].publicKey != "stale" ||
		mutations[1].kind != setPeerMutation || !mutations[1].updateOnly || mutations[1].peer.PublicKey != "direct" {
		t.Fatalf("mutations = %+v", mutations)
	}
}

func TestDarwinRouteParserUsesNetifColumnAndCanonicalizesAbbreviatedNetworks(t *testing.T) {
	output := `
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
10.86/24           utun0              USc                 utun0
10.87.0.2          10.87.0.2          UH                  utun8       42
default            192.168.8.1        UGScg                 en0

Internet6:
`
	routes := parseDarwinRoutes(output)
	if len(routes) != 2 || routes[0].length != 24 || routes[0].interfaceName != "utun0" ||
		routes[1].length != 32 || routes[1].interfaceName != "utun8" {
		t.Fatalf("routes = %+v", routes)
	}
}

func TestDarwinRelayTransactionPublishesPathAfterPeerAuthorityAndPreservesDirectRuntime(t *testing.T) {
	active := testSpecification(t, 1)
	candidate := relayCandidate(t, active, 2)
	backend, device, network := fakeLiveDarwinBackend(active)
	if _, err := backend.Apply(candidate); err != nil {
		t.Fatal(err)
	}
	direct := device.state.Peers[active.Peers[0].PublicKey]
	if direct.Endpoint != "198.51.100.20:60000" {
		t.Fatalf("direct roaming endpoint changed: %+v", direct)
	}
	directKey, _ := base64.StdEncoding.DecodeString(active.Peers[0].PublicKey)
	for _, operation := range device.operations {
		if strings.Contains(operation, hex.EncodeToString(directKey)) {
			t.Fatalf("unchanged direct peer was mutated: %q", operation)
		}
	}
	if len(network.commands) != 2 ||
		!strings.Contains(network.commands[0], "ifconfig utun-test inet 10.87.0.1/32") ||
		!strings.Contains(network.commands[1], "route -q -n add -inet 10.87.0.2/32") {
		t.Fatalf("relay publication order = %v", network.commands)
	}
	if !network.aliases["10.87.0.1"] || network.routes["10.87.0.2/32"] != network.interfaceName {
		t.Fatalf("relay path missing: aliases=%v routes=%v", network.aliases, network.routes)
	}
}

func TestDarwinRelayFailureRestoresPriorAuthorityAndLeavesNoPublishedPath(t *testing.T) {
	active := testSpecification(t, 4)
	candidate := relayCandidate(t, active, 5)
	backend, device, network := fakeLiveDarwinBackend(active)
	network.failRouteAdd = true
	if _, err := backend.Apply(candidate); err == nil || !strings.Contains(err.Error(), "injected relay route failure") {
		t.Fatalf("relay failure = %v", err)
	}
	if backend.applied == nil || backend.applied.PublicDigest() != active.PublicDigest() {
		t.Fatalf("backend authority = %+v", backend.applied)
	}
	if len(device.state.Peers) != 1 || device.state.Peers[candidate.Relay.HubPublicKey].Allowed != nil {
		t.Fatalf("candidate hub survived rollback: %+v", device.state.Peers)
	}
	if len(network.aliases) != 0 || len(network.routes) != 0 || backend.relayAlias != "" || len(backend.relayRoutes) != 0 {
		t.Fatalf("failed relay remained visible: aliases=%v routes=%v bookkeeping=%q/%v", network.aliases, network.routes, backend.relayAlias, backend.relayRoutes)
	}
	if device.state.Peers[active.Peers[0].PublicKey].Endpoint != "198.51.100.20:60000" {
		t.Fatal("rollback disturbed the unchanged direct peer")
	}
}

func TestDarwinRelayRemovalQuiescesPathBeforeRemovingOnlyTheHub(t *testing.T) {
	direct := testSpecification(t, 7)
	active := relayCandidate(t, direct, 7)
	removed := direct
	removed.Generation = 8
	backend, device, network := fakeLiveDarwinBackend(active)
	if _, err := backend.Apply(removed); err != nil {
		t.Fatal(err)
	}
	if len(network.commands) < 2 ||
		!strings.Contains(network.commands[0], "route -q -n delete -inet 10.87.0.2/32 -interface utun-test") ||
		!strings.Contains(network.commands[1], "ifconfig utun-test inet 10.87.0.1 -alias") {
		t.Fatalf("relay quiescence order = %v", network.commands)
	}
	if len(network.aliases) != 0 || len(network.routes) != 0 || backend.relayAlias != "" || len(backend.relayRoutes) != 0 {
		t.Fatalf("relay removal leaked state: aliases=%v routes=%v", network.aliases, network.routes)
	}
	if len(device.state.Peers) != 1 || device.state.Peers[direct.Peers[0].PublicKey].Endpoint != "198.51.100.20:60000" {
		t.Fatalf("removal disturbed direct peer: %+v", device.state.Peers)
	}
	hubKey, _ := base64.StdEncoding.DecodeString(active.Relay.HubPublicKey)
	if len(device.operations) != 1 || !strings.Contains(device.operations[0], hex.EncodeToString(hubKey)) || !strings.Contains(device.operations[0], "remove=true") {
		t.Fatalf("peer operations = %q", device.operations)
	}
}

func TestDarwinRelayRemovalRefusesRouteMovedToAnotherInterfaceWithoutMutation(t *testing.T) {
	direct := testSpecification(t, 7)
	active := relayCandidate(t, direct, 7)
	removed := direct
	removed.Generation = 8
	backend, device, network := fakeLiveDarwinBackend(active)
	network.routes["10.87.0.2/32"] = "utun-foreign"

	if _, err := backend.Apply(removed); err == nil || !strings.Contains(err.Error(), "owned by another interface") {
		t.Fatalf("moved route removal = %v", err)
	}
	if network.routes["10.87.0.2/32"] != "utun-foreign" {
		t.Fatalf("foreign route was changed: %v", network.routes)
	}
	if len(network.commands) != 0 {
		t.Fatalf("path mutated before ownership refusal: %v", network.commands)
	}
	if len(device.operations) != 0 {
		t.Fatalf("peer authority mutated before ownership refusal: %q", device.operations)
	}
	if backend.applied == nil || backend.applied.PublicDigest() != active.PublicDigest() ||
		backend.relayAlias != active.Relay.Address || len(backend.relayRoutes) != len(active.Relay.Routes) {
		t.Fatalf("prior relay authority was not retained: applied=%+v alias=%q routes=%v", backend.applied, backend.relayAlias, backend.relayRoutes)
	}
}

func TestDarwinRelayRemovalRefusesForeignOwnerAppearingAfterQualifiedDeletion(t *testing.T) {
	direct := testSpecification(t, 7)
	active := relayCandidate(t, direct, 7)
	removed := direct
	removed.Generation = 8
	backend, device, network := fakeLiveDarwinBackend(active)
	network.afterDelete = func(route string) {
		network.afterDelete = nil
		network.routes[route] = "utun-foreign"
	}

	if _, err := backend.Apply(removed); err == nil || !strings.Contains(err.Error(), "moved to another interface during deletion") {
		t.Fatalf("late foreign route removal = %v", err)
	}
	if network.routes["10.87.0.2/32"] != "utun-foreign" {
		t.Fatalf("late foreign route was changed: %v", network.routes)
	}
	if len(device.operations) != 0 {
		t.Fatalf("peer authority mutated after failed route teardown: %q", device.operations)
	}
	if backend.applied == nil || backend.applied.PublicDigest() != active.PublicDigest() ||
		backend.relayAlias != active.Relay.Address || len(backend.relayRoutes) != len(active.Relay.Routes) {
		t.Fatalf("prior relay authority was not retained: applied=%+v alias=%q routes=%v", backend.applied, backend.relayAlias, backend.relayRoutes)
	}
}

func maximumRelaySpecification(t *testing.T, generation uint64, relayOctet int) Specification {
	t.Helper()
	spec := testSpecification(t, generation)
	spec.Version = RelaySpecificationVersion
	spec.Peers = make([]Peer, 0, MaximumPeers)
	routes := make([]string, 0, MaximumPeers)
	for ordinal := 2; ordinal <= 254; ordinal++ {
		_, publicKey := testKeypair(t)
		spec.Peers = append(spec.Peers, Peer{
			PublicKey: publicKey,
			AllowedIP: fmt.Sprintf("10.86.0.%d/32", ordinal),
			Keepalive: 25,
		})
		routes = append(routes, fmt.Sprintf("10.%d.0.%d/32", relayOctet, ordinal))
	}
	_, hubPublicKey := testKeypair(t)
	spec.Relay = &Relay{
		Network:      fmt.Sprintf("10.%d.0.0/24", relayOctet),
		Address:      fmt.Sprintf("10.%d.0.1/32", relayOctet),
		HubPublicKey: hubPublicKey,
		Endpoint:     "192.0.2.10:51821",
		Keepalive:    RelayKeepalive,
		Routes:       routes,
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestMaximumRelayUpdateSettlesAfterFormerFiveSecondDeadlineWithConstantInspection(t *testing.T) {
	active := maximumRelaySpecification(t, 9, 87)
	candidate := active
	candidate.Generation = 10
	relay := *active.Relay
	relay.Network = "10.88.0.0/24"
	relay.Address = "10.88.0.1/32"
	relay.Routes = make([]string, 0, MaximumPeers)
	for ordinal := 2; ordinal <= 254; ordinal++ {
		relay.Routes = append(relay.Routes, fmt.Sprintf("10.88.0.%d/32", ordinal))
	}
	candidate.Relay = &relay
	if err := candidate.Validate(); err != nil {
		t.Fatal(err)
	}

	backend, device, network := fakeLiveDarwinBackend(active)
	network.commandDelay = 11 * time.Millisecond
	started := time.Now()
	if _, err := backend.Apply(candidate); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed <= 5*time.Second {
		t.Fatalf("maximum update did not cross former deadline: %s", elapsed)
	}

	var additions, deletions int
	for _, command := range network.commands {
		switch {
		case strings.Contains(command, "route -q -n add -inet 10.88.0."):
			additions++
		case strings.Contains(command, "route -q -n delete -inet 10.87.0."):
			deletions++
			if !strings.Contains(command, "-interface utun-test") {
				t.Fatalf("unscoped route deletion: %q", command)
			}
		}
	}
	if additions != MaximumPeers || deletions != MaximumPeers {
		t.Fatalf("route mutation counts add=%d delete=%d", additions, deletions)
	}
	var routeSnapshots int
	for _, query := range network.queries {
		if strings.Contains(query, "/usr/sbin/netstat -rn -f inet") {
			routeSnapshots++
		}
	}
	if routeSnapshots > 8 {
		t.Fatalf("route inspection scaled with peers: %d snapshots", routeSnapshots)
	}
	for _, operation := range device.operations {
		for _, peer := range active.Peers {
			key, _ := base64.StdEncoding.DecodeString(peer.PublicKey)
			if strings.Contains(operation, hex.EncodeToString(key)) {
				t.Fatal("maximum relay update mutated an unchanged direct peer")
			}
		}
	}
}

func TestDarwinRelayTransactionRefusesUnownedSameInterfacePathBeforePeerMutation(t *testing.T) {
	active := testSpecification(t, 1)
	candidate := relayCandidate(t, active, 2)
	backend, device, network := fakeLiveDarwinBackend(active)
	network.aliases["10.99.0.1"] = true
	network.routes["10.99.0.2/32"] = network.interfaceName

	if _, err := backend.Apply(candidate); err == nil || !strings.Contains(err.Error(), "unowned IPv4") {
		t.Fatalf("unowned path failure = %v", err)
	}
	if len(device.operations) != 0 {
		t.Fatalf("peer authority mutated before path drift refusal: %q", device.operations)
	}
}

func TestDarwinSameGenerationRevalidationRejectsUnownedAliasAndRoute(t *testing.T) {
	active := testSpecification(t, 4)
	backend, _, network := fakeLiveDarwinBackend(active)
	network.aliases["10.99.0.1"] = true
	if _, err := backend.Apply(active); err == nil || !strings.Contains(err.Error(), "unowned IPv4 alias") {
		t.Fatalf("unowned alias revalidation = %v", err)
	}

	delete(network.aliases, "10.99.0.1")
	network.routes["10.99.0.2/32"] = network.interfaceName
	if _, err := backend.Apply(active); err == nil || !strings.Contains(err.Error(), "unowned IPv4 route") {
		t.Fatalf("unowned route revalidation = %v", err)
	}

	delete(network.routes, "10.99.0.2/32")
	network.directRoute = false
	if _, err := backend.Apply(active); err == nil || !strings.Contains(err.Error(), "direct mesh route missing") {
		t.Fatalf("missing direct route revalidation = %v", err)
	}

	network.directRoute = true
	network.directNetmask = "0xffffffff"
	if _, err := backend.Apply(active); err == nil || !strings.Contains(err.Error(), "netmask differs") {
		t.Fatalf("direct netmask revalidation = %v", err)
	}

	network.directNetmask = "0xffffff00"
	network.mtu = 1400
	if _, err := backend.Apply(active); err == nil || !strings.Contains(err.Error(), "MTU differs") {
		t.Fatalf("MTU revalidation = %v", err)
	}
}
