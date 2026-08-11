// SPDX-License-Identifier: MIT

package mesh

import (
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
