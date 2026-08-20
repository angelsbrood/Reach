// SPDX-License-Identifier: MIT

package mesh

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictSpecificationRoundTrip(t *testing.T) {
	spec := testSpecification(t, 7)
	decoded, err := DecodeSpecification(encodedSpecification(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicDigest() != spec.PublicDigest() || decoded.Generation != 7 {
		t.Fatal("round trip changed public contract")
	}
}

func TestStrictSpecificationRejectsUnknownDuplicateAndTrailing(t *testing.T) {
	spec := testSpecification(t, 1)
	data := encodedSpecification(t, spec)
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["command"] = "/bin/sh"
	unknown, _ := json.Marshal(object)
	duplicate := []byte(strings.Replace(string(data), `"version": 1`, `"version": 1, "version": 1`, 1))
	for name, input := range map[string][]byte{
		"unknown":   unknown,
		"duplicate": duplicate,
		"trailing":  append(data, []byte(`{}`)...),
	} {
		if _, err := DecodeSpecification(input); err == nil {
			t.Fatalf("%s input accepted", name)
		}
	}
}

func TestSpecificationBoundsAndAgreement(t *testing.T) {
	base := testSpecification(t, 1)
	cases := map[string]func(*Specification){
		"zero generation": func(value *Specification) { value.Generation = 0 },
		"wrong address":   func(value *Specification) { value.Address = "10.86.1.1/24" },
		"wrong port":      func(value *Specification) { value.Port = ListenPort + 1 },
		"wrong mtu":       func(value *Specification) { value.MTU = InterfaceMTU + 1 },
		"empty peers":     func(value *Specification) { value.Peers = nil },
		"bad route":       func(value *Specification) { value.Peers[0].AllowedIP = "10.86.0.1/32" },
		"broad route":     func(value *Specification) { value.Peers[0].AllowedIP = "10.86.0.0/24" },
		"keepalive":       func(value *Specification) { value.Peers[0].Keepalive = MaximumKeepalive + 1 },
		"host mismatch":   func(value *Specification) { _, value.PublicKey = testKeypair(t) },
	}
	for name, mutate := range cases {
		value := base
		value.Peers = append([]Peer(nil), base.Peers...)
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestDuplicateKeysAndRoutesAreRejected(t *testing.T) {
	base := testSpecification(t, 1)
	duplicateKey := base
	duplicateKey.Peers = append(duplicateKey.Peers, Peer{
		PublicKey: base.Peers[0].PublicKey,
		AllowedIP: "10.86.0.3/32",
	})
	if err := duplicateKey.Validate(); err == nil {
		t.Fatal("duplicate peer key accepted")
	}
	_, secondKey := testKeypair(t)
	duplicateRoute := base
	duplicateRoute.Peers = append(duplicateRoute.Peers, Peer{
		PublicKey: secondKey,
		AllowedIP: base.Peers[0].AllowedIP,
	})
	if err := duplicateRoute.Validate(); err == nil {
		t.Fatal("duplicate route accepted")
	}
	_, orderedKey := testKeypair(t)
	outOfOrder := base
	outOfOrder.Peers = []Peer{
		{PublicKey: orderedKey, AllowedIP: "10.86.0.3/32"},
		base.Peers[0],
	}
	if err := outOfOrder.Validate(); err == nil {
		t.Fatal("out-of-order peer routes accepted")
	}
}

func TestPublicDigestIsDeterministicAndSecretFree(t *testing.T) {
	spec := testSpecification(t, 9)
	digest := spec.PublicDigest()
	changedSecret := spec
	changedSecret.PrivateKey = strings.Repeat("A", len(spec.PrivateKey))
	if changedSecret.PublicDigest() != digest {
		t.Fatal("private key affected public digest")
	}
	changedPeer := spec
	changedPeer.Peers = append([]Peer(nil), spec.Peers...)
	changedPeer.Peers[0].Keepalive++
	if changedPeer.PublicDigest() == digest {
		t.Fatal("public peer policy did not affect digest")
	}
}

func TestRelaySpecificationRoundTripsAndSeparatesComponentDigests(t *testing.T) {
	spec := testRelaySpecification(t, 7)
	data, err := EncodeSpecification(spec)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSpecification(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicDigest() != spec.PublicDigest() || decoded.DirectDigest() != spec.DirectDigest() || decoded.RelayDigest() != spec.RelayDigest() {
		t.Fatal("relay round trip changed authority digests")
	}
	endpointOnly := spec
	copyRelay := *spec.Relay
	endpointOnly.Relay = &copyRelay
	endpointOnly.Relay.Endpoint = "192.0.2.11:51821"
	if endpointOnly.DirectDigest() != spec.DirectDigest() || endpointOnly.RelayDigest() == spec.RelayDigest() || endpointOnly.PublicDigest() == spec.PublicDigest() {
		t.Fatal("relay-only update changed the wrong digest domain")
	}
	if strings.Contains(string(data), `"replace_peers"`) {
		t.Fatal("encoded specification contains a backend mutation command")
	}
}

func TestVersionTwoWithoutRelayReadsAsDirectOnlyAuthority(t *testing.T) {
	spec := testSpecification(t, 3)
	spec.Version = RelaySpecificationVersion
	data, err := EncodeSpecification(spec)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSpecification(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Relay != nil || decoded.PublicDigest() != testSpecificationDigestForDirect(spec) {
		t.Fatal("version 2 direct-only authority changed semantics")
	}
}

func testSpecificationDigestForDirect(spec Specification) string {
	spec.Version = SpecificationVersion
	spec.Relay = nil
	return spec.PublicDigest()
}

func TestRelayDigestFixturesMatchSwift(t *testing.T) {
	spec := Specification{
		Version: RelaySpecificationVersion, Generation: 7,
		PublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		Address:   HostAddress, Port: ListenPort, MTU: InterfaceMTU,
		Peers: []Peer{
			{PublicKey: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=", AllowedIP: "10.86.0.2/32", Keepalive: 25},
			{PublicKey: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", AllowedIP: "10.86.0.3/32"},
		},
		Relay: &Relay{
			Network: "10.87.0.0/24", Address: "10.87.0.1/32",
			HubPublicKey: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=",
			Endpoint:     "192.0.2.10:51821", Keepalive: RelayKeepalive,
			Routes: []string{"10.87.0.2/32", "10.87.0.3/32"},
		},
	}
	if got := spec.DirectDigest(); got != "a8fba25b3a72a2a4e8ca6f54b7e1197fa012b98d58e206d2e248aa19f282fb85" {
		t.Fatalf("direct digest = %s", got)
	}
	if got := spec.RelayDigest(); got != "06bf5967403e04a3c31d38cc44d717d737cf1adab22dd738a2e0c22fdff72a1a" {
		t.Fatalf("relay digest = %s", got)
	}
	if got := spec.PublicDigest(); got != "dce04eda846843be63dba3b8d739a2160094af8d59b1bb641e37d33839778fdb" {
		t.Fatalf("public digest = %s", got)
	}
}

func TestRelaySpecificationStrictlyRejectsPartialUnknownAndUnsafePolicy(t *testing.T) {
	base := testRelaySpecification(t, 2)
	data, err := EncodeSpecification(base)
	if err != nil {
		t.Fatal(err)
	}
	partial := bytes.Replace(data, []byte(`"routes": [`), []byte(`"missingRoutes": [`), 1)
	unknown := bytes.Replace(data, []byte(`"network":`), []byte(`"unknown":true,"network":`), 1)
	duplicate := bytes.Replace(data, []byte(`"network":`), []byte(`"network":"10.87.0.0/24","network":`), 1)
	for name, input := range map[string][]byte{"partial": partial, "unknown": unknown, "duplicate": duplicate} {
		if _, err := DecodeSpecification(input); err == nil {
			t.Fatalf("%s relay object accepted", name)
		}
	}

	cases := map[string]func(*Specification){
		"public prefix": func(value *Specification) {
			value.Relay.Network = "198.51.100.0/24"
			value.Relay.Address = "198.51.100.1/32"
			value.Relay.Routes[0] = "198.51.100.2/32"
		},
		"direct overlap": func(value *Specification) {
			value.Relay.Network = MeshNetwork
			value.Relay.Address = "10.86.0.1/32"
			value.Relay.Routes[0] = "10.86.0.2/32"
		},
		"dns endpoint":       func(value *Specification) { value.Relay.Endpoint = "hub.example:51821" },
		"privileged port":    func(value *Specification) { value.Relay.Endpoint = "192.0.2.10:443" },
		"recursive endpoint": func(value *Specification) { value.Relay.Endpoint = "10.87.0.9:51821" },
		"host key reuse":     func(value *Specification) { value.Relay.HubPublicKey = value.PublicKey },
		"device key reuse":   func(value *Specification) { value.Relay.HubPublicKey = value.Peers[0].PublicKey },
		"route mismatch":     func(value *Specification) { value.Relay.Routes[0] = "10.87.0.3/32" },
		"keepalive":          func(value *Specification) { value.Relay.Keepalive = 24 },
	}
	for name, mutate := range cases {
		value := base
		copyRelay := *base.Relay
		copyRelay.Routes = append([]string(nil), base.Relay.Routes...)
		value.Relay = &copyRelay
		mutate(&value)
		if err := value.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestDesiredRelayPeerIsAdditiveAndOrderedAfterDirectPeers(t *testing.T) {
	spec := testRelaySpecification(t, 1)
	peers := spec.DesiredPeers()
	if len(peers) != 2 || peers[0].Hub || !peers[1].Hub {
		t.Fatalf("desired peers = %+v", peers)
	}
	if peers[1].Endpoint != spec.Relay.Endpoint || peers[1].Keepalive != RelayKeepalive || !slicesEqual(peers[1].Allowed, spec.Relay.Routes) {
		t.Fatal("hub peer lost relay policy")
	}
}
