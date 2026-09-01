// Package netguard renders and applies the service-UID-scoped runtime egress seal.
package netguard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"reach.dev/exo-runtime/internal/authority"
	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/linklocal"
)

func Render(value config.Node, uid uint64) string {
	peerLinkLocal, err := linklocal.FromMAC(value.PeerMAC)
	if err != nil {
		peerLinkLocal = "invalid"
	}
	gatewayRule := ""
	gatewayOutput := ""
	if value.Role == "coordinator" {
		gatewayRule = fmt.Sprintf("    ip saddr %s tcp dport %d accept\n    ip saddr != %s tcp dport %d reject\n",
			value.ConnectorAddress, authority.GatewayPort,
			value.ConnectorAddress, authority.GatewayPort)
		gatewayOutput = fmt.Sprintf("    meta skuid %d ip daddr %s accept\n", uid, value.ConnectorAddress)
	}
	return fmt.Sprintf(`table inet reach_exo {
  chain input {
    type filter hook input priority -20; policy accept;
    iifname "lo" accept
    ip saddr %s tcp dport { %d, %d } accept
    ip6 saddr %s tcp dport { %d, %d } accept
    iifname != "lo" tcp dport %d reject
%s    ip saddr != %s tcp dport { %d, %d } reject
    ip saddr != %s tcp dport 49153-65535 reject
    ip saddr != %s udp dport %d drop
    ip6 saddr != %s tcp dport { %d, %d } reject
    ip6 saddr != %s tcp dport 49153-65535 reject
    ip6 saddr != %s udp dport %d drop
  }
  chain output {
    type filter hook output priority -20; policy accept;
    meta skuid %d oifname "lo" accept
    meta skuid %d ip daddr %s accept
    meta skuid %d ip daddr %s accept
    meta skuid %d ip6 daddr %s accept
%s    meta skuid %d ip daddr %s udp dport %d accept
    meta skuid %d ip6 daddr ff12::e0a1:de89 udp dport %d accept
    meta skuid %d ip6 daddr ::1 accept
    meta skuid %d reject
  }
}
`, value.PeerAddress, authority.ProviderZenohPort, authority.ProviderAPIPort,
		peerLinkLocal, authority.ProviderZenohPort, authority.ProviderAPIPort,
		authority.ProviderAPIPort, gatewayRule,
		value.PeerAddress, authority.ProviderZenohPort, authority.ControlPort,
		value.PeerAddress,
		value.PeerAddress, authority.ProviderDiscoverPort,
		peerLinkLocal, authority.ProviderZenohPort, authority.ControlPort,
		peerLinkLocal,
		peerLinkLocal, authority.ProviderDiscoverPort,
		uid,
		uid, value.PrivateAddress,
		uid, value.PeerAddress,
		uid, peerLinkLocal,
		gatewayOutput,
		uid, value.PrivateNetworkCIDR, authority.ProviderDiscoverPort,
		uid, authority.ProviderDiscoverPort,
		uid,
		uid)
}

func Apply(value config.Node) error {
	if os.Geteuid() != 0 {
		return errors.New("netguard apply requires root")
	}
	account, err := user.Lookup(authority.ServiceUser)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return err
	}
	_ = removeTable()
	command := exec.Command("/usr/sbin/nft", "-f", "-")
	command.Stdin = strings.NewReader(Render(value, uid))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("apply nftables guard: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func Remove() error {
	if os.Geteuid() != 0 {
		return errors.New("netguard remove requires root")
	}
	return removeTable()
}

func removeTable() error {
	command := exec.Command("/usr/sbin/nft", "delete", "table", "inet", "reach_exo")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err := command.Run()
	if err != nil && !strings.Contains(stderr.String(), "No such file or directory") {
		return fmt.Errorf("remove nftables guard: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
