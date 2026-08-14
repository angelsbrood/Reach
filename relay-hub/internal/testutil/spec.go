// SPDX-License-Identifier: MIT

package testutil

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"systems.reach/relay-hub/internal/config"
)

func Key(seed byte) (private, public string) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	derived, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(derived)
}

func numberedKey(seed int) (private, public string) {
	raw := sha256.Sum256([]byte(fmt.Sprintf("reach-relay-test-key-%d", seed)))
	derived, err := curve25519.X25519(raw[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(raw[:]), base64.StdEncoding.EncodeToString(derived)
}

func Spec(generation uint64, devices int) config.Specification {
	private, public := Key(1)
	_, host := Key(40)
	s := config.Specification{Version: 1, Generation: generation, PrivateKey: private, PublicKey: public, ListenPort: 51888, MTU: config.MTU, RelayPrefix: "10.87.0.0/24", Host: config.Peer{PublicKey: host, Address: "10.87.0.1/32"}}
	for i := 0; i < devices; i++ {
		_, key := numberedKey(i)
		s.Devices = append(s.Devices, config.Peer{PublicKey: key, Address: fmt.Sprintf("10.87.0.%d/32", i+2)})
	}
	return s
}
