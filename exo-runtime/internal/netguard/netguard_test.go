package netguard

import (
	"strings"
	"testing"

	"reach.dev/exo-runtime/internal/config"
)

func TestRenderConstrainsAPIAndServiceEgress(t *testing.T) {
	value := config.Node{Role: "coordinator", PrivateAddress: "192.168.108.2", PeerAddress: "192.168.108.3", ConnectorAddress: "192.168.108.1", PrivateNetworkCIDR: "192.168.108.0/24", PeerMAC: "52:55:55:00:00:03"}
	rules := Render(value, 997)
	for _, expected := range []string{
		`ip saddr 192.168.108.3 tcp dport { 52414, 52415 } accept`,
		`ip6 saddr fe80::5055:55ff:fe00:3 tcp dport { 52414, 52415 } accept`,
		`iifname != "lo" tcp dport 52415 reject`,
		`ip saddr 192.168.108.1 tcp dport 53421 accept`,
		`ip saddr != 192.168.108.1 tcp dport 53421 reject`,
		`ip saddr != 192.168.108.3 tcp dport 49153-65535 reject`,
		`meta skuid 997 ip daddr 192.168.108.3 accept`,
		`meta skuid 997 ip6 daddr fe80::5055:55ff:fe00:3 accept`,
		`meta skuid 997 ip daddr 192.168.108.1 accept`,
		`meta skuid 997 ip6 daddr ff12::e0a1:de89 udp dport 52413 accept`,
		`meta skuid 997 reject`,
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("missing rule %q", expected)
		}
	}
	peerAllow := strings.Index(rules, `ip saddr 192.168.108.3 tcp dport { 52414, 52415 } accept`)
	blanketReject := strings.Index(rules, `iifname != "lo" tcp dport 52415 reject`)
	if peerAllow < 0 || blanketReject < 0 || peerAllow > blanketReject {
		t.Fatal("exact peer API authority does not precede the blanket API refusal")
	}
	if strings.Contains(rules, "0.0.0.0/0") {
		t.Fatal("rules contain widened public authority")
	}
	if strings.Contains(rules, "224.0.0.0/4") || strings.Contains(rules, "255.255.255.255") {
		t.Fatal("rules contain unused broad IPv4 discovery authority")
	}
}

func TestCoordinatorGatewayFirstMatchDistinguishesConnectorPeerAndUnrelated(t *testing.T) {
	value := config.Node{Role: "coordinator", PrivateAddress: "192.168.108.2", PeerAddress: "192.168.108.3", ConnectorAddress: "192.168.108.1", PrivateNetworkCIDR: "192.168.108.0/24", PeerMAC: "52:55:55:00:00:03"}
	rules := Render(value, 997)
	connectorAllow := strings.Index(rules, `ip saddr 192.168.108.1 tcp dport 53421 accept`)
	connectorReject := strings.Index(rules, `ip saddr != 192.168.108.1 tcp dport 53421 reject`)
	peerHighPortReject := strings.Index(rules, `ip saddr != 192.168.108.3 tcp dport 49153-65535 reject`)
	if connectorAllow < 0 || connectorReject < 0 || peerHighPortReject < 0 {
		t.Fatal("gateway first-match rules are incomplete")
	}
	if connectorAllow > connectorReject || connectorAllow > peerHighPortReject {
		t.Fatal("exact connector gateway authority does not precede every matching rejection")
	}

	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "connector", source: value.ConnectorAddress, want: "accept"},
		{name: "peer", source: value.PeerAddress, want: "reject"},
		{name: "unrelated", source: "192.168.108.99", want: "reject"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := firstGatewayVerdict(rules, test.source, value.ConnectorAddress, value.PeerAddress); got != test.want {
				t.Fatalf("gateway verdict for %s = %q, want %q", test.source, got, test.want)
			}
		})
	}
}

func TestCoordinatorDoesNotWidenConnectorOrPeerAuthority(t *testing.T) {
	value := config.Node{Role: "coordinator", PrivateAddress: "192.168.108.2", PeerAddress: "192.168.108.3", ConnectorAddress: "192.168.108.1", PrivateNetworkCIDR: "192.168.108.0/24", PeerMAC: "52:55:55:00:00:03"}
	rules := Render(value, 997)
	connectorAllows := []string{}
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip saddr "+value.ConnectorAddress+" ") && strings.HasSuffix(line, " accept") {
			connectorAllows = append(connectorAllows, line)
		}
	}
	wantConnectorAllows := []string{"ip saddr 192.168.108.1 tcp dport 53421 accept"}
	if strings.Join(connectorAllows, "\n") != strings.Join(wantConnectorAllows, "\n") {
		t.Fatalf("connector ingress authority = %q, want sole gateway exception %q", connectorAllows, wantConnectorAllows)
	}
	for _, forbidden := range []string{
		`ip saddr 192.168.108.1 tcp dport 52415 accept`,
		`ip saddr 192.168.108.1 tcp dport 52414 accept`,
		`ip saddr 192.168.108.1 tcp dport 53420 accept`,
		`ip saddr 192.168.108.1 tcp dport 49153-65535 accept`,
		`ip saddr 192.168.108.1 udp`,
	} {
		if strings.Contains(rules, forbidden) {
			t.Fatalf("connector gained forbidden authority %q", forbidden)
		}
	}

	for _, preserved := range []string{
		`ip saddr 192.168.108.3 tcp dport { 52414, 52415 } accept`,
		`ip saddr != 192.168.108.3 tcp dport { 52414, 53420 } reject`,
		`ip saddr != 192.168.108.3 tcp dport 49153-65535 reject`,
	} {
		if !strings.Contains(rules, preserved) {
			t.Fatalf("peer authority lost preserved rule %q", preserved)
		}
	}
	if strings.Contains(rules, `ip saddr 192.168.108.3 tcp dport 53421 accept`) {
		t.Fatal("peer gained connector gateway authority")
	}
}

func firstGatewayVerdict(rules, source, connector, peer string) string {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case "ip saddr " + connector + " tcp dport 53421 accept":
			if source == connector {
				return "accept"
			}
		case "ip saddr != " + connector + " tcp dport 53421 reject":
			if source != connector {
				return "reject"
			}
		case "ip saddr != " + peer + " tcp dport 49153-65535 reject":
			if source != peer {
				return "reject"
			}
		}
	}
	return "no-match"
}

func TestWorkerDoesNotAdmitConnectorAddress(t *testing.T) {
	value := config.Node{Role: "worker", PrivateAddress: "192.168.108.3", PeerAddress: "192.168.108.2", ConnectorAddress: "192.168.108.1", PrivateNetworkCIDR: "192.168.108.0/24", PeerMAC: "52:55:55:00:00:02"}
	rules := Render(value, 997)
	if strings.Contains(rules, "ip saddr 192.168.108.1 tcp dport 53421 accept") {
		t.Fatal("worker admitted connector-side gateway ingress")
	}
	if strings.Contains(rules, "meta skuid 997 ip daddr 192.168.108.1 accept") {
		t.Fatal("worker admitted connector-side egress")
	}
}
