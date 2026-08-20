// SPDX-License-Identifier: MIT

package mesh

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStatusSeparatesDirectAndRelayReadiness(t *testing.T) {
	direct := testSpecification(t, 3)
	directStatus := ReadyStatus(direct, "utun7")
	if !directStatus.Ready || !directStatus.Direct.Ready || !directStatus.Relay.Ready || directStatus.Relay.Configured {
		t.Fatalf("direct status = %+v", directStatus)
	}
	if directStatus.Direct.Digest != direct.DirectDigest() || directStatus.Direct.PeerCount != len(direct.Peers) {
		t.Fatal("direct status lost component authority")
	}

	relay := testRelaySpecification(t, 4)
	relayStatus := ReadyStatus(relay, "utun7")
	if !relayStatus.Ready || !relayStatus.Direct.Ready || !relayStatus.Relay.Ready || !relayStatus.Relay.Configured {
		t.Fatalf("relay status = %+v", relayStatus)
	}
	if relayStatus.Relay.Digest != relay.RelayDigest() || relayStatus.Relay.Address != relay.Relay.Address ||
		relayStatus.Relay.RouteCount != len(relay.Relay.Routes) || relayStatus.Relay.HubPeerCount != 1 {
		t.Fatal("relay status lost component authority")
	}

	updating := UpdatingStatus(relay, "utun7")
	if updating.Ready || !updating.Direct.Ready || updating.Relay.Ready || updating.Error != "updating" {
		t.Fatalf("updating status = %+v", updating)
	}
}

func TestUnavailableStatusRetainsBoundedAuthorityWithoutClaimingReadiness(t *testing.T) {
	spec := testRelaySpecification(t, 5)
	status := UnavailableStatus(&spec, "interface unavailable")
	if status.Ready || status.Direct.Ready || status.Relay.Ready || !status.Relay.Configured {
		t.Fatalf("unavailable status = %+v", status)
	}
	if status.Generation != spec.Generation || status.PublicDigest != spec.PublicDigest() ||
		status.Direct.Digest != spec.DirectDigest() || status.Relay.Digest != spec.RelayDigest() {
		t.Fatal("unavailable status lost recovery authority")
	}
}

func TestRelayStatusIsPrivacySafe(t *testing.T) {
	spec := testRelaySpecification(t, 1)
	data, err := json.Marshal(ReadyStatus(spec, "utun7"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{spec.PrivateKey, spec.PublicKey, spec.Peers[0].PublicKey, spec.Relay.HubPublicKey, spec.Relay.Endpoint} {
		if strings.Contains(text, secret) {
			t.Fatalf("status disclosed configuration material: %q", secret)
		}
	}
	if !strings.Contains(text, spec.Relay.Address) {
		t.Fatal("privacy-safe relay address was omitted")
	}
}
