#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -Eeuo pipefail

phase="${1:?phase required}"
if [[ "${phase}" == capacity-addendum ]]; then
    evidence=/var/tmp/reach-relay-linux-capacity-evidence
    work=/root/reach-relay-linux-capacity
    keys=/etc/wireguard/reach-relay-linux-capacity
else
    evidence=/var/tmp/reach-relay-linux-evidence
    work=/root/reach-relay-linux-acceptance
    keys=/etc/wireguard/reach-relay-linux-acceptance
fi
unit=reach-relay-hub.service
port=51888
device3_relay=10.87.0.3

mkdir -p "${evidence}"
chmod 0700 "${evidence}"

fail() { echo "FAIL ${phase}: $*" >&2; exit 1; }
trap 'fail "runner line ${LINENO}"' ERR

wait_ready() {
    local generation=$1
    for _ in $(seq 1 300); do
        if systemctl is-active --quiet "${unit}" \
            && jq -e --argjson generation "${generation}" '.ready == true and .generation == $generation' /run/reach-relay-hub/status.json >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    systemctl show "${unit}" -p ActiveState -p SubState -p Result -p MainPID -p NRestarts >&2 || true
    journalctl -u "${unit}" --no-pager -n 30 -o short-monotonic >&2 || true
    return 1
}

wait_pid_change() {
    local prior=$1
    for _ in $(seq 1 300); do
        local current
        current=$(systemctl show -p MainPID --value "${unit}")
        if systemctl is-active --quiet "${unit}" && [[ "${current}" != 0 && "${current}" != "${prior}" ]]; then
            echo "${current}"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

atomic_install() {
    local source=$1 destination=$2 owner=$3 group=$4 mode=$5
    local temporary="${destination}.candidate.$$"
    install -o "${owner}" -g "${group}" -m "${mode}" "${source}" "${temporary}"
    sync -f "${temporary}"
    mv -f "${temporary}" "${destination}"
    sync -f "$(dirname "${destination}")"
}

backup_operator_files() {
    local directory=/etc/reach-relay-hub
    test ! -e "${directory}/.config.backup"
    test ! -e "${directory}/.routes.backup"
    install -o root -g root -m 0600 "${directory}/config.json" "${directory}/.config.backup"
    install -o root -g root -m 0600 "${directory}/routes.json" "${directory}/.routes.backup"
    sync -f "${directory}/.config.backup"
    sync -f "${directory}/.routes.backup"
    sync -f "${directory}"
}

discard_operator_backups() {
    rm -f /etc/reach-relay-hub/.config.backup /etc/reach-relay-hub/.routes.backup
    sync -f /etc/reach-relay-hub
}

restore_operator_backups() {
    atomic_install /etc/reach-relay-hub/.config.backup /etc/reach-relay-hub/config.json root reach-relay 0640
    atomic_install /etc/reach-relay-hub/.routes.backup /etc/reach-relay-hub/routes.json root reach-relay 0640
    discard_operator_backups
}

refresh_status() {
    local pid before
    pid=$(systemctl show -p MainPID --value "${unit}")
    before=$(jq -r '.updatedAt' /run/reach-relay-hub/status.json)
    kill -USR1 "${pid}"
    for _ in $(seq 1 100); do
        if [[ $(jq -r '.updatedAt' /run/reach-relay-hub/status.json) != "${before}" ]]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

peer_metric() {
    local role=$1 ordinal=$2 field=$3
    jq -r --arg role "${role}" --argjson ordinal "${ordinal}" --arg field "${field}" \
        '[.peers[] | select(.role == $role and .ordinal == $ordinal) | .[$field]][0] // 0' \
        /run/reach-relay-hub/status.json
}

hub_counter_snapshot() {
    jq -c '[.peers | sort_by(.role,.ordinal)[] | {role,ordinal,receiveBytes,transmitBytes}]' /run/reach-relay-hub/status.json
}

firewall_counter() {
    local comment=$1
    nft -j list chain inet reach_relay input | jq -r --arg comment "${comment}" '[.. | objects | select(.comment? == $comment) | .expr[]? | select(.counter?) | .counter.packets][0] // 0'
}

prove_firewall_drop() {
    local label=$1 comment=$2 before after counters_before counters_after
    shift 2
    refresh_status
    counters_before=$(hub_counter_snapshot)
    before=$(firewall_counter "${comment}")
    "$@" >/dev/null 2>&1 || true
    sleep 0.2
    after=$(firewall_counter "${comment}")
    (( after > before )) || fail "${label} firewall counter did not move"
    refresh_status
    counters_after=$(hub_counter_snapshot)
    [[ "${counters_after}" == "${counters_before}" ]] || fail "${label} reached a hub peer"
    printf '%s comment=%s before=%s after=%s peer_counters_unchanged=true\n' "${label}" "${comment}" "${before}" "${after}" >>"${evidence}/L5-firewall-probes.txt"
}

expect_direct_refusal() {
    local label=$1 configuration=$2 routes=$3
    local state=/var/tmp/reach-relay-hub-l2-state runtime=/var/tmp/reach-relay-hub-l2-runtime
    rm -rf "${state}" "${runtime}"
    if runuser -u reach-relay -- /usr/lib/reach-relay-hub/reach-relay-hub \
        --config "${configuration}" \
        --routes "${routes}" \
        --state "${state}" \
        --status "${runtime}/status.json" \
        >"${work}/l2-${label}.log" 2>&1; then
        fail "${label} accepted"
    fi
    test ! -e "${state}/active.json" || fail "${label} created active authority"
    test ! -e "${state}/pending.json" || fail "${label} created pending authority"
    rm -rf "${state}" "${runtime}"
}

expect_forbidden_system_operation() {
    local label=$1
    shift
    local output="${work}/forbidden-${label}.txt" status
    if runuser -u reach-relay -- "$@" >"${output}" 2>&1; then
        fail "${label} operation unexpectedly succeeded"
    else
        status=$?
    fi
    {
        printf '%s exit=%s\n' "${label}" "${status}"
        sed -n '1,5p' "${output}"
    } >>"${evidence}/A2-forbidden-operations.txt"
}

refuse_and_restore() {
    local label=$1 configuration=$2 routes=$3
    local pid prior_pid
    pid=$(systemctl show -p MainPID --value "${unit}")
    backup_operator_files
    atomic_install "${configuration}" /etc/reach-relay-hub/config.json root reach-relay 0640
    atomic_install "${routes}" /etc/reach-relay-hub/routes.json root reach-relay 0640
    systemctl reload "${unit}"
    for _ in $(seq 1 100); do
        jq -e '.ready == true and .generation == 2 and .error == "update refused"' /run/reach-relay-hub/status.json >/dev/null 2>&1 && break
        sleep 0.1
    done
    jq -e '.ready == true and .generation == 2 and .error == "update refused"' /run/reach-relay-hub/status.json >/dev/null || fail "${label} refusal status missing"
    [[ $(systemctl show -p MainPID --value "${unit}") == "${pid}" ]] || fail "${label} refusal changed PID"
    record_status "L7-${label}-refused"
    forward_three
    refresh_status
    record_status "L7-${label}-live"
    record_counters "L7-${label}-live"
    restore_operator_backups
    if [[ "${label}" == live-route ]]; then
        ip route del blackhole 10.87.0.0/24 table 200
    fi
    prior_pid=${pid}
    systemctl restart "${unit}"
    wait_ready 2 || fail "${label} restored disk intent did not restart"
    pid=$(systemctl show -p MainPID --value "${unit}")
    [[ "${pid}" != "${prior_pid}" ]] || fail "${label} controlled restart retained PID"
    refresh_client_peers
    forward_three
    refresh_status
    record_status "L7-${label}-restored"
    record_counters "L7-${label}-restored"
    systemctl reset-failed "${unit}"
    printf '%s refused=true pid_preserved=true disk_restored=true restart_verified=true\n' "${label}" >>"${evidence}/L7-refusals.txt"
}

record_status() {
    local name=$1
    jq '{schemaVersion,helperVersion,pid,generation,publicDigest,ready,peerCount,updatedAt,error,peers}' /run/reach-relay-hub/status.json >"${evidence}/${name}-status.json"
    chmod 0600 "${evidence}/${name}-status.json"
}

record_process() {
    local name=$1 pid
    pid=$(systemctl show -p MainPID --value "${unit}")
    {
        systemctl show "${unit}" -p ActiveState -p SubState -p Result -p MainPID -p NRestarts -p FragmentPath
        awk '/^(Uid|Gid|CapEff|CapAmb|Threads):/ {print}' "/proc/${pid}/status"
        systemctl show "${unit}" -p User -p Group -p NoNewPrivileges -p PrivateDevices -p PrivateTmp -p ProtectSystem -p ProtectHome -p RestrictAddressFamilies -p RestrictNamespaces -p RestrictSUIDSGID -p MemoryMax -p TasksMax -p LimitNOFILE -p LimitCORE
    } >"${evidence}/${name}-service.txt"
    chmod 0600 "${evidence}/${name}-service.txt"
}

record_counters() {
    local name=$1
    {
        for namespace in rr-host rr-device2 rr-device3; do
            if ip netns list | awk '{print $1}' | grep -qx "${namespace}"; then
                ip netns exec "${namespace}" wg show wg0 dump | awk -v role="${namespace}" 'NR == 2 {printf "%s handshake=%s receive=%s transmit=%s\n", role, ($5 > 0 ? "present" : "absent"), $6, $7}'
            fi
        done
    } >"${evidence}/${name}-counters.txt"
    chmod 0600 "${evidence}/${name}-counters.txt"
}

cleanup_network() {
    ip netns del rr-host >/dev/null 2>&1 || true
    ip netns del rr-device2 >/dev/null 2>&1 || true
    ip netns del rr-device3 >/dev/null 2>&1 || true
    ip netns del rr-denied >/dev/null 2>&1 || true
    ip netns del rr-intruder >/dev/null 2>&1 || true
    ip netns del rr-eth0 >/dev/null 2>&1 || true
    tc qdisc del dev rr-eth0-root clsact >/dev/null 2>&1 || true
    ip link del rr-eth0-root >/dev/null 2>&1 || true
    ip link del rr-denied-root >/dev/null 2>&1 || true
    ip link del rr-allowed >/dev/null 2>&1 || true
}

create_network() {
    cleanup_network
    ip link add rr-allowed type bridge
    ip address add 192.0.2.1/28 dev rr-allowed
    ip link set rr-allowed up
    for pair in host device2 device3 intruder; do
        root_link="rr-${pair}-root"
        if [[ "${pair}" == intruder ]]; then root_link=rr-int-root; fi
        ip netns add "rr-${pair}"
        ip link add "rr-${pair}0" type veth peer name "${root_link}"
        ip link set "rr-${pair}0" netns "rr-${pair}"
        ip link set "${root_link}" master rr-allowed
        ip link set "${root_link}" up
        ip -n "rr-${pair}" link set lo up
    done
    ip -n rr-host address add 192.0.2.2/28 dev rr-host0
    ip -n rr-device2 address add 192.0.2.3/28 dev rr-device20
    ip -n rr-device3 address add 192.0.2.4/28 dev rr-device30
    ip -n rr-intruder address add 192.0.2.6/28 dev rr-intruder0
    ip -n rr-host link set rr-host0 up
    ip -n rr-device2 link set rr-device20 up
    ip -n rr-device3 link set rr-device30 up
    ip -n rr-intruder link set rr-intruder0 up

    # This lane reaches the wildcard socket through a distinct root interface,
    # rather than another source attached to the allowed bridge.
    ip netns add rr-denied
    ip link add rr-denied0 type veth peer name rr-denied-root
    ip link set rr-denied0 netns rr-denied
    ip address add 198.51.100.1/30 dev rr-denied-root
    ip link set rr-denied-root up
    ip -n rr-denied link set lo up
    ip -n rr-denied address add 198.51.100.2/30 dev rr-denied0
    ip -n rr-denied link set rr-denied0 up

    local hub_public
    hub_public=$(<"${keys}/hub.public")
    ip -n rr-host link add wg0 type wireguard
    ip netns exec rr-host wg set wg0 private-key "${keys}/host.private" peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.2/32,${device3_relay}/32
    ip -n rr-host address add 10.87.0.1/32 dev wg0
    ip -n rr-host link set wg0 mtu 1280 up
    ip -n rr-host route add 10.87.0.2/32 dev wg0
    ip -n rr-host route add "${device3_relay}/32" dev wg0

    ip -n rr-device2 link add wg0 type wireguard
    ip netns exec rr-device2 wg set wg0 private-key "${keys}/device2.private" peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.1/32,${device3_relay}/32,10.87.0.254/32
    ip -n rr-device2 address add 10.87.0.2/32 dev wg0
    ip -n rr-device2 link set wg0 mtu 1280 up
    ip -n rr-device2 route add 10.87.0.1/32 dev wg0
    ip -n rr-device2 route add "${device3_relay}/32" dev wg0
    ip -n rr-device2 route add 10.87.0.254/32 dev wg0

    ip -n rr-device3 link add wg0 type wireguard
    ip netns exec rr-device3 wg set wg0 private-key "${keys}/device3.private" peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.1/32
    ip -n rr-device3 address add "${device3_relay}/32" dev wg0
    ip -n rr-device3 link set wg0 mtu 1280 up
    ip -n rr-device3 route add 10.87.0.1/32 dev wg0

    for namespace in rr-host rr-device2 rr-device3 rr-intruder rr-denied; do
        if ip -n "${namespace}" route show default | grep -q .; then
            fail "default route in ${namespace}"
        fi
    done
}

refresh_client_peers() {
    local hub_public
    hub_public=$(<"${keys}/hub.public")
    ip netns exec rr-host wg set wg0 peer "${hub_public}" remove
    ip netns exec rr-host wg set wg0 peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.2/32,${device3_relay}/32
    ip netns exec rr-device2 wg set wg0 peer "${hub_public}" remove
    ip netns exec rr-device2 wg set wg0 peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.1/32,${device3_relay}/32,10.87.0.254/32
    ip netns exec rr-device3 wg set wg0 peer "${hub_public}" remove
    ip netns exec rr-device3 wg set wg0 peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.1/32
}

forward_two() {
    for _ in $(seq 1 20); do
        if ip netns exec rr-host ping -q -c 1 -W 1 -I 10.87.0.1 10.87.0.2 >/dev/null 2>&1 \
            && ip netns exec rr-device2 ping -q -c 1 -W 1 -I 10.87.0.2 10.87.0.1 >/dev/null 2>&1; then
            ip netns exec rr-host ping -q -c 3 -W 2 -I 10.87.0.1 10.87.0.2 >/dev/null
            ip netns exec rr-device2 ping -q -c 3 -W 2 -I 10.87.0.2 10.87.0.1 >/dev/null
            return 0
        fi
        sleep 0.2
    done
    return 1
}

forward_three() {
    forward_two
    for _ in $(seq 1 20); do
        # A changed /32 deliberately recreates the hub peer and therefore
        # discards its learned roaming endpoint. Let the synthetic device
        # establish that endpoint before proving traffic in the reverse
        # direction.
        if ip netns exec rr-device3 ping -q -c 1 -W 1 -I "${device3_relay}" 10.87.0.1 >/dev/null 2>&1 \
            && ip netns exec rr-host ping -q -c 1 -W 1 -I 10.87.0.1 "${device3_relay}" >/dev/null 2>&1; then
            ip netns exec rr-host ping -q -c 3 -W 2 -I 10.87.0.1 "${device3_relay}" >/dev/null
            ip netns exec rr-device3 ping -q -c 3 -W 2 -I "${device3_relay}" 10.87.0.1 >/dev/null
            return 0
        fi
        sleep 0.2
    done
    return 1
}

case "${phase}" in
calibration-reset)
    # Recover only the disposable fixture after a pre-acceptance stop. This
    # returns the VM to the same post-provisioning state from which `offline`
    # begins; it is never part of an accepted L0-L12 run.
    systemctl stop "${unit}" >/dev/null 2>&1 || true
    systemctl disable "${unit}" >/dev/null 2>&1 || true
    cleanup_network
    stock=/var/tmp/reach-relay-linux-nftables-stock.conf
    if [[ -f "${stock}" ]]; then
        cp "${stock}" /etc/nftables.conf
        nft -f /etc/nftables.conf
    else
        nft delete table inet reach_relay >/dev/null 2>&1 || true
        nft delete table inet reach_offline >/dev/null 2>&1 || true
    fi
    systemctl disable nftables.service >/dev/null 2>&1 || true
    dpkg --purge reach-relay-hub >/dev/null 2>&1 || true
    rm -rf /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub "${work}" "${keys}" "${evidence}"
    rm -f "${stock}" /var/tmp/reach-relay-linux-offline.txt
    userdel reach-relay >/dev/null 2>&1 || true
    groupdel reach-relay >/dev/null 2>&1 || true
    systemctl daemon-reload
    systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
    echo "calibration reset complete"
    ;;
offline)
    # Provisioning is complete. Preserve the stock ruleset, then keep only
    # Lima's local control subnet and DHCP reachable on eth0. Every build,
    # package, and runtime cell after this point is therefore offline while
    # SSH control and the host-side eth0 refusal probe remain possible.
    stock=/var/tmp/reach-relay-linux-nftables-stock.conf
    test ! -e "${stock}" || fail "offline stock rules already exist"
    cp /etc/nftables.conf "${stock}"
    chmod 0600 "${stock}"
    subnet=$(ip -4 route show dev eth0 scope link | awk 'NR == 1 {print $1}')
    [[ "${subnet}" == */* ]] || fail "missing Lima control subnet"
    cp "${stock}" /etc/nftables.conf
    cat >>/etc/nftables.conf <<NFT

table inet reach_offline {
  chain output {
    type filter hook output priority raw; policy accept;
    oifname "eth0" udp sport 68 udp dport 67 counter accept comment "reach offline dhcp"
    oifname "eth0" ip daddr ${subnet} counter accept comment "reach offline control subnet"
    oifname "eth0" counter drop comment "reach offline external egress"
  }
}
NFT
    nft -f /etc/nftables.conf
    systemctl enable nftables.service >/dev/null
    before=$(nft -j list chain inet reach_offline output | jq -r '[.. | objects | select(.comment? == "reach offline external egress") | .expr[]? | select(.counter?) | .counter.packets][0] // 0')
    bash -c 'printf x >/dev/udp/1.1.1.1/53' >/dev/null 2>&1 || true
    after=$(nft -j list chain inet reach_offline output | jq -r '[.. | objects | select(.comment? == "reach offline external egress") | .expr[]? | select(.counter?) | .counter.packets][0] // 0')
    (( after > before )) || fail "offline egress counter did not move"
    echo "offline control_subnet=${subnet} external_counter_before=${before} external_counter_after=${after}" >/var/tmp/reach-relay-linux-offline.txt
    chmod 0600 /var/tmp/reach-relay-linux-offline.txt
    echo "offline policy installed"
    ;;
prepare-packages)
    # All inputs were copied before the offline policy was installed. Build
    # two independent B archives and run the Linux-only netlink/package tests
    # while external egress is blocked.
    test -f /tmp/relay-hub/tests/linux/build-package.sh || fail "source snapshot missing"
    test -f /tmp/reach-relay-linux-new-arm64 || fail "candidate binary missing"
    test -f /tmp/pkg-build/a1.deb || fail "compatibility package missing"
    test -x /tmp/netroutes.test || fail "netlink test binary missing"
    test -x /tmp/package.test || fail "package test binary missing"
    cp /tmp/pkg-build/a1.deb /tmp/pkg-build/a2.deb
    rm -rf /tmp/a-extract
    dpkg-deb --extract /tmp/pkg-build/a1.deb /tmp/a-extract
    cp /tmp/a-extract/usr/lib/reach-relay-hub/reach-relay-hub /tmp/bin-ld
    chmod 0555 /tmp/bin-ld
    [[ $(sha256sum /tmp/bin-ld | awk '{print $1}') == cbd0cdd1fa0d29340234893bdd53e377f2bfdb3a18f928c131ea63e7800d76c4 ]] || fail "compatibility binary hash"
    [[ $(sha256sum /tmp/reach-relay-linux-new-arm64 | awk '{print $1}') == e5060d147bb4f8f2de22017e58474c27bd52afa01696f50256ae02843f066a6f ]] || fail "candidate binary hash"
    for archive in b1 b2; do
        SOURCE_DATE_EPOCH=1786678355 /tmp/relay-hub/tests/linux/build-package.sh \
            /tmp/relay-hub /tmp/reach-relay-linux-new-arm64 0.2.0-b arm64 "/tmp/pkg-build/${archive}.deb"
    done
    cmp /tmp/pkg-build/a1.deb /tmp/pkg-build/a2.deb
    cmp /tmp/pkg-build/b1.deb /tmp/pkg-build/b2.deb
    for run in 1 2 3; do
        (cd /tmp/relay-hub/internal/netroutes && /tmp/netroutes.test -test.v) >"/tmp/linux-netroutes-${run}.txt" 2>&1
        (cd /tmp/relay-hub/package && /tmp/package.test -test.v) >"/tmp/linux-package-${run}.txt" 2>&1
    done
    echo "offline package preparation complete"
    ;;
initial)
    if [[ -f "${work}/nftables-original.conf" ]]; then
        cp "${work}/nftables-original.conf" /etc/nftables.conf
        nft -f /etc/nftables.conf
    else
        nft delete table inet reach_relay >/dev/null 2>&1 || true
    fi
    rm -rf "${evidence}" "${work}" "${keys}"
    mkdir -p "${evidence}" "${work}" "${keys}"
    chmod 0700 "${evidence}" "${work}" "${keys}"
    cleanup_network
    systemctl stop "${unit}" >/dev/null 2>&1 || true
    systemctl disable "${unit}" >/dev/null 2>&1 || true
    dpkg --purge reach-relay-hub >/dev/null 2>&1 || true
    userdel reach-relay >/dev/null 2>&1 || true
    groupdel reach-relay >/dev/null 2>&1 || true
    rm -rf /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub

    {
        uname -a
        cat /etc/os-release
        systemctl --version | head -1
        dpkg-query -W -f='${Package} ${Version}\n' iproute2 wireguard-tools nftables jq dpkg-dev iputils-ping procps file binutils
        sha256sum /tmp/pkg-build/a1.deb /tmp/pkg-build/a2.deb /tmp/pkg-build/b1.deb /tmp/pkg-build/b2.deb /tmp/bin-ld /tmp/reach-relay-linux-new-arm64
        cat /var/tmp/reach-relay-linux-offline.txt
        nft list table inet reach_offline
    } >"${evidence}/L0-provenance.txt"
    chmod 0600 "${evidence}/L0-provenance.txt"
    cp /tmp/linux-netroutes-*.txt /tmp/linux-package-*.txt "${evidence}/"
    chmod 0600 "${evidence}"/linux-*.txt

    dpkg-deb --contents /tmp/pkg-build/b1.deb >"${work}/b1-contents.txt"
    {
        dpkg-deb --info /tmp/pkg-build/b1.deb
        cat "${work}/b1-contents.txt"
    } >"${evidence}/L1-package.txt"
    chmod 0600 "${evidence}/L1-package.txt"
    sed -n '1p' "${work}/b1-contents.txt" | grep -q '^drwxr-xr-x root/root .* \./$' || fail "package root mode"
    grep -q ' ./usr/share/doc/reach-relay-hub/route-inventory.md$' "${work}/b1-contents.txt" || fail "route inventory omitted"
    rm -rf "${work}/control-archive"
    dpkg-deb --control /tmp/pkg-build/b1.deb "${work}/control-archive"
    [[ $(find "${work}/control-archive" -mindepth 1 -maxdepth 1 -type f -printf '%f\n') == control ]] || fail "control archive contains maintainer hooks"
    dpkg -i /tmp/pkg-build/b1.deb >"${evidence}/L1-install.txt"
    ! systemctl is-active --quiet "${unit}" || fail "package auto-started"
    ! systemctl is-enabled --quiet "${unit}" || fail "package auto-enabled"
    ! getent passwd reach-relay >/dev/null || fail "package created account"
    test ! -e /etc/reach-relay-hub || fail "package created operator state"
    test ! -e /var/lib/reach-relay-hub || fail "package created service state"
    [[ -z $(find /var/lib/dpkg/info -maxdepth 1 -type f -name 'reach-relay-hub.*' ! -name '*.list' ! -name '*.md5sums' -print -quit) ]] || fail "maintainer script installed"

    systemd-sysusers /usr/lib/sysusers.d/reach-relay-hub.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/reach-relay-hub.conf
    test ! -e /var/lib/reach-relay-hub || fail "package tooling created state directory"
    test ! -e /run/reach-relay-hub || fail "package tooling created runtime directory"

    umask 077
    for peer in hub replacement host device2 device3; do
        wg genkey >"${keys}/${peer}.private"
        wg pubkey <"${keys}/${peer}.private" >"${keys}/${peer}.public"
    done
    hub_private=$(<"${keys}/hub.private")
    hub_public=$(<"${keys}/hub.public")
    replacement_private=$(<"${keys}/replacement.private")
    replacement_public=$(<"${keys}/replacement.public")
    host_public=$(<"${keys}/host.public")
    device2_public=$(<"${keys}/device2.public")
    device3_public=$(<"${keys}/device3.public")
    jq -n --arg privateKey "${hub_private}" --arg publicKey "${hub_public}" --arg hostKey "${host_public}" --arg device2Key "${device2_public}" --arg device3Key "${device3_public}" \
        '{version:1,generation:1,privateKey:$privateKey,publicKey:$publicKey,listenPort:51888,mtu:1280,relayPrefix:"10.87.0.0/24",host:{publicKey:$hostKey,address:"10.87.0.1/32"},devices:[{publicKey:$device2Key,address:"10.87.0.2/32"},{publicKey:$device3Key,address:"10.87.0.3/32"}]}' >"${work}/config-1.json"
    jq -n --arg privateKey "${hub_private}" --arg publicKey "${hub_public}" --arg hostKey "${host_public}" --arg device2Key "${device2_public}" --arg device3Key "${device3_public}" \
        '{version:1,generation:2,privateKey:$privateKey,publicKey:$publicKey,listenPort:51888,mtu:1280,relayPrefix:"10.87.0.0/24",host:{publicKey:$hostKey,address:"10.87.0.1/32"},devices:[{publicKey:$device2Key,address:"10.87.0.2/32"},{publicKey:$device3Key,address:"10.87.0.4/32"}]}' >"${work}/config-2.json"
    jq '.generation=3' "${work}/config-2.json" >"${work}/config-3.json"
    jq '.devices = [.devices[0]]' "${work}/config-2.json" >"${work}/config-reused.json"
    jq '.generation=3 | .listenPort=51889' "${work}/config-2.json" >"${work}/config-frozen-port.json"
    jq --arg privateKey "${replacement_private}" --arg publicKey "${replacement_public}" '.generation=3 | .privateKey=$privateKey | .publicKey=$publicKey' "${work}/config-2.json" >"${work}/config-frozen-key.json"
    jq '.generation=3 | .relayPrefix="10.88.0.0/24" | .host.address="10.88.0.1/32" | .devices[0].address="10.88.0.2/32" | .devices[1].address="10.88.0.4/32"' "${work}/config-2.json" >"${work}/config-frozen-prefix.json"
    jq '.generation=3 | .host.address="10.87.0.9/32"' "${work}/config-2.json" >"${work}/config-frozen-host.json"
    printf '%s\n' '{"version":1,"prefixes":[]}' >"${work}/routes.json"
    printf '%s\n' '{"version":1,"prefixes":["10.87.0.0/24"]}' >"${work}/routes-overlap.json"
    printf '%s\n' '{"version":1,"prefixes":[],"unknown":true}' >"${work}/routes-malformed.json"
    atomic_install "${work}/config-1.json" /etc/reach-relay-hub/config.json root reach-relay 0640
    atomic_install "${work}/routes.json" /etc/reach-relay-hub/routes.json root reach-relay 0640

    # L2: refusals execute directly as the service user and cannot consume the
    # systemd start budget.
    install -o root -g reach-relay -m 0644 "${work}/config-1.json" /etc/reach-relay-hub/unsafe-mode.json
    expect_direct_refusal mode /etc/reach-relay-hub/unsafe-mode.json /etc/reach-relay-hub/routes.json
    install -o reach-relay -g reach-relay -m 0640 "${work}/config-1.json" /etc/reach-relay-hub/unsafe-owner.json
    expect_direct_refusal owner /etc/reach-relay-hub/unsafe-owner.json /etc/reach-relay-hub/routes.json
    install -o root -g root -m 0640 "${work}/config-1.json" /etc/reach-relay-hub/unsafe-group.json
    expect_direct_refusal group /etc/reach-relay-hub/unsafe-group.json /etc/reach-relay-hub/routes.json
    install -o root -g reach-relay -m 0640 "${work}/config-1.json" /etc/reach-relay-hub/hardlink.json
    ln /etc/reach-relay-hub/hardlink.json /etc/reach-relay-hub/hardlink-second.json
    expect_direct_refusal hardlink /etc/reach-relay-hub/hardlink.json /etc/reach-relay-hub/routes.json
    jq '.unknown=true' "${work}/config-1.json" >"${work}/unknown.json"
    install -o root -g reach-relay -m 0640 "${work}/unknown.json" /etc/reach-relay-hub/unknown.json
    expect_direct_refusal unknown-json /etc/reach-relay-hub/unknown.json /etc/reach-relay-hub/routes.json
    install -o root -g reach-relay -m 0640 "${work}/routes.json" /etc/reach-relay-hub/oversized-routes.json
    truncate -s 65537 /etc/reach-relay-hub/oversized-routes.json
    expect_direct_refusal oversized /etc/reach-relay-hub/config.json /etc/reach-relay-hub/oversized-routes.json
    jq '.listenPort=443' "${work}/config-1.json" >"${work}/privileged.json"
    install -o root -g reach-relay -m 0640 "${work}/privileged.json" /etc/reach-relay-hub/privileged-installed.json
    expect_direct_refusal privileged-port /etc/reach-relay-hub/privileged-installed.json /etc/reach-relay-hub/routes.json
    ln -s /etc/reach-relay-hub/routes.json /etc/reach-relay-hub/routes-link.json
    expect_direct_refusal symlink /etc/reach-relay-hub/config.json /etc/reach-relay-hub/routes-link.json
    install -o root -g reach-relay -m 0640 "${work}/routes-overlap.json" /etc/reach-relay-hub/routes-overlap-installed.json
    expect_direct_refusal reserved-route /etc/reach-relay-hub/config.json /etc/reach-relay-hub/routes-overlap-installed.json
    ip route add blackhole 10.87.0.0/24 table 200
    expect_direct_refusal active-route /etc/reach-relay-hub/config.json /etc/reach-relay-hub/routes.json
    ip route del blackhole 10.87.0.0/24 table 200
    rm -f /etc/reach-relay-hub/unsafe-mode.json /etc/reach-relay-hub/unsafe-owner.json /etc/reach-relay-hub/unsafe-group.json /etc/reach-relay-hub/hardlink.json /etc/reach-relay-hub/hardlink-second.json /etc/reach-relay-hub/unknown.json /etc/reach-relay-hub/oversized-routes.json /etc/reach-relay-hub/privileged-installed.json /etc/reach-relay-hub/routes-link.json /etc/reach-relay-hub/routes-overlap-installed.json /run/reach-relay-hub/l2-status.json
    echo 'unsafe input refusals: mode, owner, group, hardlink, unknown JSON, oversized routes, privileged port, symlink, reserved-route conflict, active-route conflict' >"${evidence}/L2-refusals.txt"
    chmod 0600 "${evidence}/L2-refusals.txt"

    cp /etc/nftables.conf "${work}/nftables-original.conf"
    cat >"${work}/firewall.nft" <<'NFT'
table inet reach_relay {
  chain input {
    type filter hook input priority -100; policy accept;
    iifname "rr-allowed" udp dport 51888 ip saddr { 192.0.2.2, 192.0.2.3, 192.0.2.4 } counter accept comment "reach relay peers"
    iifname "rr-allowed" udp dport 51888 counter drop comment "reach relay denied allowed ingress"
    iifname "lo" ip daddr 127.0.0.1 udp dport 51888 counter drop comment "reach relay denied loopback ipv4"
    iifname "lo" ip6 daddr ::1 udp dport 51888 counter drop comment "reach relay denied loopback ipv6"
    iifname "eth0" udp dport 51888 counter drop comment "reach relay denied eth0"
    udp dport 51888 counter drop comment "reach relay denied fallback"
  }
}
NFT
    install -o root -g root -m 0600 "${work}/firewall.nft" /etc/reach-relay-hub/firewall.nft
    printf '\ninclude "/etc/reach-relay-hub/firewall.nft"\n' >>/etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable nftables.service >/dev/null
    create_network

    systemctl daemon-reload
    systemd-analyze verify /usr/lib/systemd/system/reach-relay-hub.service
    systemctl enable --now "${unit}" >"${evidence}/L3-start.txt"
    wait_ready 1 || fail "generation 1 did not become ready"
    pid=$(systemctl show -p MainPID --value "${unit}")
    [[ $(ps -o user= -p "${pid}" | tr -d ' ') == reach-relay ]] || fail "service ran as root"
    [[ $(awk '/^CapEff:/ {print $2}' "/proc/${pid}/status") == 0000000000000000 ]] || fail "effective capability present"
    [[ $(awk '/^CapAmb:/ {print $2}' "/proc/${pid}/status") == 0000000000000000 ]] || fail "ambient capability present"
    [[ $(stat -c '%a' /run/reach-relay-hub/status.json) == 600 ]] || fail "status mode"
    [[ $(stat -c '%U:%G:%a' /var/lib/reach-relay-hub) == reach-relay:reach-relay:700 ]] || fail "state directory authority"
    [[ $(stat -c '%U:%G:%a' /run/reach-relay-hub) == reach-relay:reach-relay:700 ]] || fail "runtime directory authority"
    systemctl show "${unit}" -p ExecReload -p StateDirectoryMode -p RuntimeDirectoryMode >"${evidence}/L3-unit-contract.txt"
    grep -q '/usr/bin/kill -HUP' "${evidence}/L3-unit-contract.txt" || fail "systemd reload contract missing"
    grep -q 'StateDirectoryMode=0700' "${evidence}/L3-unit-contract.txt" || fail "state directory mode not effective"
    grep -q 'RuntimeDirectoryMode=0700' "${evidence}/L3-unit-contract.txt" || fail "runtime directory mode not effective"
    [[ $(sha256sum /usr/lib/reach-relay-hub/reach-relay-hub | awk '{print $1}') == e5060d147bb4f8f2de22017e58474c27bd52afa01696f50256ae02843f066a6f ]] || fail "installed B hash"
    [[ $(sha256sum "/proc/${pid}/exe" | awk '{print $1}') == e5060d147bb4f8f2de22017e58474c27bd52afa01696f50256ae02843f066a6f ]] || fail "running B hash"
    {
        stat -c '%U %G %a %h %n' /usr/lib/reach-relay-hub/reach-relay-hub /usr/lib/systemd/system/reach-relay-hub.service /etc/reach-relay-hub/config.json /etc/reach-relay-hub/routes.json /var/lib/reach-relay-hub /var/lib/reach-relay-hub/active.json /run/reach-relay-hub /run/reach-relay-hub/status.json
        sha256sum /usr/lib/reach-relay-hub/reach-relay-hub "/proc/${pid}/exe"
        ss -H -lunp | awk -v port=":${port}" '$4 ~ port {print}'
    } >"${evidence}/L3-files.txt"
    chmod 0600 "${evidence}/L3-files.txt"
    systemd-analyze security "${unit}" >"${evidence}/L3-security.txt"
    record_process L3
    record_status L3

    for run in 1 2 3; do
        forward_three
        refresh_status
        record_status "L4-forward-${run}"
        record_counters "L4-forward-${run}"
    done

    # L5: device-to-device, spoofed source, unknown destination, and denied
    # underlay traffic all fail at the hub while the source peer is observed.
    refresh_status
    device2_receive_before=$(peer_metric device 2 receiveBytes)
    device3_transmit_before=$(peer_metric device 3 transmitBytes)
    if ip netns exec rr-device2 ping -q -c 1 -W 1 -I 10.87.0.2 10.87.0.3 >/dev/null 2>&1; then fail "device isolation failed"; fi
    refresh_status
    (( $(peer_metric device 2 receiveBytes) > device2_receive_before )) || fail "device isolation source counter did not move"
    (( $(peer_metric device 3 transmitBytes) == device3_transmit_before )) || fail "device isolation destination counter moved"

    refresh_status
    device2_receive_before=$(peer_metric device 2 receiveBytes)
    host_transmit_before=$(peer_metric host 1 transmitBytes)
    ip -n rr-device2 address add 10.87.0.3/32 dev lo
    if ip netns exec rr-device2 ping -q -c 1 -W 1 -I 10.87.0.3 10.87.0.1 >/dev/null 2>&1; then fail "spoof accepted"; fi
    ip -n rr-device2 address del 10.87.0.3/32 dev lo
    refresh_status
    (( $(peer_metric device 2 receiveBytes) > device2_receive_before )) || fail "spoof source counter did not move"
    (( $(peer_metric host 1 transmitBytes) == host_transmit_before )) || fail "spoof destination counter moved"

    refresh_status
    device2_receive_before=$(peer_metric device 2 receiveBytes)
    host_transmit_before=$(peer_metric host 1 transmitBytes)
    device3_transmit_before=$(peer_metric device 3 transmitBytes)
    if ip netns exec rr-device2 ping -q -c 1 -W 1 -I 10.87.0.2 10.87.0.254 >/dev/null 2>&1; then fail "unknown destination accepted"; fi
    refresh_status
    (( $(peer_metric device 2 receiveBytes) > device2_receive_before )) || fail "unknown destination source counter did not move"
    (( $(peer_metric host 1 transmitBytes) == host_transmit_before )) || fail "unknown destination host counter moved"
    (( $(peer_metric device 3 transmitBytes) == device3_transmit_before )) || fail "unknown destination device counter moved"

    : >"${evidence}/L5-firewall-probes.txt"
    prove_firewall_drop allowed-ingress "reach relay denied allowed ingress" ip netns exec rr-intruder bash -c 'printf x >/dev/udp/192.0.2.1/51888'
    prove_firewall_drop separate-interface "reach relay denied fallback" ip netns exec rr-denied bash -c 'printf x >/dev/udp/198.51.100.1/51888'
    prove_firewall_drop loopback-ipv4 "reach relay denied loopback ipv4" bash -c 'printf x >/dev/udp/127.0.0.1/51888'
    prove_firewall_drop loopback-ipv6 "reach relay denied loopback ipv6" bash -c 'printf x >/dev/udp/::1/51888'
    chmod 0600 "${evidence}/L5-firewall-probes.txt"
    forward_three
    refresh_status
    record_status L5-internal
    record_counters L5-internal

    # L6: atomically move device 3 from .3/32 to .4/32 while preserving the
    # service PID and unchanged host/device2 runtime state.
    refresh_status
    host_receive_before=$(peer_metric host 1 receiveBytes)
    host_transmit_before=$(peer_metric host 1 transmitBytes)
    device2_receive_before=$(peer_metric device 2 receiveBytes)
    device2_transmit_before=$(peer_metric device 2 transmitBytes)
    backup_operator_files
    atomic_install "${work}/config-2.json" /etc/reach-relay-hub/config.json root reach-relay 0640
    systemctl reload "${unit}"
    wait_ready 2 || fail "generation 2 did not become ready"
    discard_operator_backups
    [[ $(systemctl show -p MainPID --value "${unit}") == "${pid}" ]] || fail "reload changed PID"

    refresh_status
    (( $(peer_metric host 1 receiveBytes) >= host_receive_before )) || fail "host receive counter regressed"
    (( $(peer_metric host 1 transmitBytes) >= host_transmit_before )) || fail "host transmit counter regressed"
    (( $(peer_metric device 2 receiveBytes) >= device2_receive_before )) || fail "device2 receive counter regressed"
    (( $(peer_metric device 2 transmitBytes) >= device2_transmit_before )) || fail "device2 transmit counter regressed"

    host_receive_before=$(peer_metric host 1 receiveBytes)
    device2_transmit_before=$(peer_metric device 2 transmitBytes)
    device3_transmit_before=$(peer_metric device 4 transmitBytes)
    if ip netns exec rr-host ping -q -c 1 -W 1 -I 10.87.0.1 10.87.0.3 >/dev/null 2>&1; then fail "old device3 address survived"; fi
    refresh_status
    (( $(peer_metric host 1 receiveBytes) > host_receive_before )) || fail "old address source counter did not move"
    (( $(peer_metric device 2 transmitBytes) == device2_transmit_before )) || fail "old address reached device2"
    (( $(peer_metric device 4 transmitBytes) == device3_transmit_before )) || fail "old address reached moved device3"

    hub_public=$(<"${keys}/hub.public")
    ip netns exec rr-host wg set wg0 peer "${hub_public}" remove
    ip netns exec rr-host wg set wg0 peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.2/32,10.87.0.4/32
    ip -n rr-host route del 10.87.0.3/32 dev wg0
    ip -n rr-host route add 10.87.0.4/32 dev wg0
    ip netns exec rr-device2 wg set wg0 peer "${hub_public}" remove
    ip netns exec rr-device2 wg set wg0 peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.1/32,10.87.0.4/32,10.87.0.254/32
    ip -n rr-device2 route del 10.87.0.3/32 dev wg0
    ip -n rr-device2 route add 10.87.0.4/32 dev wg0
    ip -n rr-device3 address del 10.87.0.3/32 dev wg0
    ip -n rr-device3 address add 10.87.0.4/32 dev wg0
    ip -n rr-device3 route add 10.87.0.1/32 dev wg0
    # The hub intentionally remove/re-adds a peer whose /32 changes, so its
    # prior WireGuard session is no longer valid. Recreate the synthetic
    # client's hub peer as well to model a new handshake after that authority
    # change rather than waiting for the old keypair's rekey horizon.
    ip netns exec rr-device3 wg set wg0 peer "${hub_public}" remove
    ip netns exec rr-device3 wg set wg0 peer "${hub_public}" endpoint 192.0.2.1:${port} persistent-keepalive 25 allowed-ips 10.87.0.1/32
    device3_relay=10.87.0.4
    forward_three
    if ip netns exec rr-device2 ping -q -c 1 -W 1 -I 10.87.0.2 10.87.0.3 >/dev/null 2>&1; then fail "configured devices bypassed isolation"; fi
    if ip -n rr-host route get 10.87.0.3 >/dev/null 2>&1; then fail "old device3 route retained"; fi
    refresh_status
    record_status L6
    record_counters L6

    # L7: every declared refusal class preserves the live generation, restores
    # both disk authorities from same-directory backups, and survives a
    # controlled restart from those restored bytes.
    : >"${evidence}/L7-refusals.txt"
    refuse_and_restore reused-generation "${work}/config-reused.json" "${work}/routes.json"
    refuse_and_restore frozen-port "${work}/config-frozen-port.json" "${work}/routes.json"
    refuse_and_restore frozen-key "${work}/config-frozen-key.json" "${work}/routes.json"
    refuse_and_restore frozen-prefix "${work}/config-frozen-prefix.json" "${work}/routes.json"
    refuse_and_restore frozen-host "${work}/config-frozen-host.json" "${work}/routes.json"
    refuse_and_restore malformed-routes "${work}/config-3.json" "${work}/routes-malformed.json"
    ip route add blackhole 10.87.0.0/24 table 200
    refuse_and_restore live-route "${work}/config-3.json" "${work}/routes.json"
    chmod 0600 "${evidence}/L7-refusals.txt"
    record_status L7
    record_counters L7

    # L8: three automatic SIGKILL recoveries. The fixture removes and re-adds
    # only its synthetic client peer after each restart, producing a fresh
    # handshake without waiting for WireGuard's old-keypair rekey horizon.
    for crash in 1 2 3; do
        old_pid=$(systemctl show -p MainPID --value "${unit}")
        kill -KILL "${old_pid}"
        new_pid=$(wait_pid_change "${old_pid}") || fail "crash ${crash} did not recover"
        wait_ready 2 || fail "crash ${crash} recovered without authority"
        refresh_client_peers
        forward_three
        refresh_status
        record_status "L8-crash-${crash}"
        record_counters "L8-crash-${crash}"
        echo "crash=${crash} pid_changed=true synthetic_client_rehandshake=true nrestarts=$(systemctl show -p NRestarts --value "${unit}")" >>"${evidence}/L8-crashes.txt"
        if [[ "${crash}" == 2 ]]; then sleep 61; fi
    done
    chmod 0600 "${evidence}/L8-crashes.txt"
    record_process L8

    # L10: controlled B -> A -> B. A writes its historical state-directory
    # status; B removes that safe legacy file while restoring /run authority.
    dpkg -i /tmp/pkg-build/a1.deb >"${evidence}/L10-install-a.txt"
    systemctl daemon-reload
    systemctl restart "${unit}"
    for _ in $(seq 1 300); do
        if systemctl is-active --quiet "${unit}" && jq -e '.ready == true and .generation == 2' /var/lib/reach-relay-hub/status.json >/dev/null 2>&1; then break; fi
        sleep 0.1
    done
    jq -e '.ready == true and .generation == 2' /var/lib/reach-relay-hub/status.json >/dev/null || fail "A compatibility start failed"
    [[ $(sha256sum /usr/lib/reach-relay-hub/reach-relay-hub | awk '{print $1}') == cbd0cdd1fa0d29340234893bdd53e377f2bfdb3a18f928c131ea63e7800d76c4 ]] || fail "A hash mismatch"
    refresh_client_peers
    forward_three
    dpkg -i /tmp/pkg-build/b1.deb >"${evidence}/L10-install-b.txt"
    systemctl daemon-reload
    systemctl restart "${unit}"
    wait_ready 2 || fail "B compatibility return failed"
    [[ ! -e /var/lib/reach-relay-hub/status.json ]] || fail "historical status survived B recovery"
    [[ $(sha256sum /usr/lib/reach-relay-hub/reach-relay-hub | awk '{print $1}') == e5060d147bb4f8f2de22017e58474c27bd52afa01696f50256ae02843f066a6f ]] || fail "B hash mismatch"
    refresh_client_peers
    forward_three
    refresh_status
    record_status L10
    record_counters L10
    sha256sum /usr/lib/reach-relay-hub/reach-relay-hub /tmp/pkg-build/a1.deb /tmp/pkg-build/b1.deb >"${evidence}/L10-hashes.txt"
    chmod 0600 "${evidence}/L10-hashes.txt"
    echo "initial complete"
    ;;

firewall-host-check)
    # VZ plain mode does not route the guest's NAT address onto macOS. Inject a
    # packet from a distinct namespace into the real eth0 ingress with tc;
    # nftables must classify that exact interface and no WireGuard peer may
    # observe it.
    wait_ready 2 || fail "service unavailable for eth0 firewall check"
    ip netns add rr-eth0
    ip link add rr-eth0-ns type veth peer name rr-eth0-root
    ip link set rr-eth0-ns netns rr-eth0
    ip -n rr-eth0 link set lo up
    ip -n rr-eth0 address add 203.0.113.2/30 dev rr-eth0-ns
    ip -n rr-eth0 link set rr-eth0-ns up
    ip link set rr-eth0-root up
    eth0_mac=$(cat /sys/class/net/eth0/address)
    eth0_address=$(ip -4 -o address show dev eth0 | awk 'NR == 1 {split($4,address,"/"); print address[1]}')
    [[ -n "${eth0_address}" ]] || fail "eth0 address missing"
    ip -n rr-eth0 neigh add 203.0.113.1 lladdr "${eth0_mac}" dev rr-eth0-ns
    ip -n rr-eth0 route add "${eth0_address}/32" via 203.0.113.1 dev rr-eth0-ns
    tc qdisc add dev rr-eth0-root clsact
    tc filter add dev rr-eth0-root ingress matchall action skbedit ptype host action mirred ingress redirect dev eth0
    refresh_status
    counters_before=$(hub_counter_snapshot)
    before=$(firewall_counter "reach relay denied eth0")
    ip netns exec rr-eth0 bash -c "printf x >/dev/udp/${eth0_address}/51888" >/dev/null 2>&1 || true
    sleep 0.2
    after=$(firewall_counter "reach relay denied eth0")
    (( after > before )) || fail "eth0 firewall counter did not move"
    refresh_status
    [[ $(hub_counter_snapshot) == "${counters_before}" ]] || fail "eth0 probe reached a hub peer"
    tc -s filter show dev rr-eth0-root ingress >"${evidence}/L5-eth0-injection.txt"
    printf 'eth0-injected-ingress comment=%s before=%s after=%s peer_counters_unchanged=true\n' "reach relay denied eth0" "${before}" "${after}" >>"${evidence}/L5-firewall-probes.txt"
    ip netns del rr-eth0
    tc qdisc del dev rr-eth0-root clsact >/dev/null 2>&1 || true
    ip link del rr-eth0-root >/dev/null 2>&1 || true
    device3_relay=10.87.0.4
    forward_three
    refresh_status
    record_status L5
    record_counters L5
    nft -a list chain inet reach_relay input >"${evidence}/L5-firewall.txt"
    chmod 0600 "${evidence}/L5-firewall.txt" "${evidence}/L5-firewall-probes.txt" "${evidence}/L5-eth0-injection.txt"
    echo "firewall host check complete"
    ;;

post-reboot-1|post-reboot-2)
    systemctl is-active --quiet "${unit}" || fail "service absent after reboot"
    wait_ready 2 || fail "authority absent after reboot"
    [[ $(stat -c '%U:%G:%a' /var/lib/reach-relay-hub) == reach-relay:reach-relay:700 ]] || fail "state directory mode changed after reboot"
    [[ $(stat -c '%U:%G:%a' /run/reach-relay-hub) == reach-relay:reach-relay:700 ]] || fail "runtime directory mode changed after reboot"
    device3_relay=10.87.0.4
    create_network
    forward_three
    refresh_status
    record_process "L9-${phase}"
    record_status "L9-${phase}"
    record_counters "L9-${phase}"
    stat -c '%U %G %a %n' /var/lib/reach-relay-hub /run/reach-relay-hub >"${evidence}/L9-${phase}-directory-modes.txt"
    chmod 0600 "${evidence}/L9-${phase}-directory-modes.txt"
    cat /proc/sys/kernel/random/boot_id >"${evidence}/L9-${phase}-boot-id.txt"
    chmod 0600 "${evidence}/L9-${phase}-boot-id.txt"
    echo "${phase} complete"
    ;;

capacity-addendum)
    # Bounded S30 addendum: install the exact accepted B package, start the
    # hardened unit with the maximum 253-device manifest, prove its resource
    # and privilege boundaries, then shrink in place to the real encrypted
    # three-peer fixture before complete teardown.
    expected_binary=e5060d147bb4f8f2de22017e58474c27bd52afa01696f50256ae02843f066a6f
    expected_package=252c490ad7e9a9c406287b2d90c5bb8314c6dec1edf0ccec2abf08b1bdb83775
    stock=/var/tmp/reach-relay-linux-nftables-stock.conf
    package_root=/tmp/pkg-capacity

    test -f "${stock}" || fail "offline stock rules missing"
    test -f /tmp/relay-hub/tests/linux/build-package.sh || fail "source snapshot missing"
    test -f /tmp/reach-relay-linux-new-arm64 || fail "candidate binary missing"
    [[ $(sha256sum /tmp/reach-relay-linux-new-arm64 | awk '{print $1}') == "${expected_binary}" ]] || fail "candidate binary hash"

    systemctl stop "${unit}" >/dev/null 2>&1 || true
    systemctl disable "${unit}" >/dev/null 2>&1 || true
    cleanup_network
    dpkg --purge reach-relay-hub >/dev/null 2>&1 || true
    userdel reach-relay >/dev/null 2>&1 || true
    groupdel reach-relay >/dev/null 2>&1 || true
    rm -rf /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub "${work}" "${keys}" "${evidence}" "${package_root}"
    mkdir -p "${evidence}/artifacts" "${work}" "${keys}" "${package_root}"
    chmod 0700 "${evidence}" "${evidence}/artifacts" "${work}" "${keys}" "${package_root}"

    for archive in b1 b2; do
        SOURCE_DATE_EPOCH=1786678355 /tmp/relay-hub/tests/linux/build-package.sh \
            /tmp/relay-hub /tmp/reach-relay-linux-new-arm64 0.2.0-b arm64 "${package_root}/${archive}.deb"
    done
    cmp "${package_root}/b1.deb" "${package_root}/b2.deb"
    [[ $(sha256sum "${package_root}/b1.deb" | awk '{print $1}') == "${expected_package}" ]] || fail "B package hash"
    install -m 0600 "${package_root}/b1.deb" "${evidence}/artifacts/reach-relay-hub-b-arm64.deb"
    {
        sha256sum /tmp/reach-relay-linux-new-arm64 "${package_root}/b1.deb" "${package_root}/b2.deb"
        dpkg-deb --info "${package_root}/b1.deb"
        dpkg-deb --contents "${package_root}/b1.deb"
        cat /var/tmp/reach-relay-linux-offline.txt
    } >"${evidence}/A0-provenance-package.txt"
    chmod 0600 "${evidence}/A0-provenance-package.txt"

    dpkg -i "${package_root}/b1.deb" >"${evidence}/A0-install.txt"
    ! systemctl is-active --quiet "${unit}" || fail "package auto-started"
    ! systemctl is-enabled --quiet "${unit}" || fail "package auto-enabled"
    systemd-sysusers /usr/lib/sysusers.d/reach-relay-hub.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/reach-relay-hub.conf

    umask 077
    for peer in hub host device2 device3; do
        wg genkey >"${keys}/${peer}.private"
        wg pubkey <"${keys}/${peer}.private" >"${keys}/${peer}.public"
    done
    hub_private=$(<"${keys}/hub.private")
    hub_public=$(<"${keys}/hub.public")
    host_public=$(<"${keys}/host.public")
    : >"${work}/devices.jsonl"
    for ordinal in $(seq 2 254); do
        case "${ordinal}" in
        2) public=$(<"${keys}/device2.public") ;;
        3) public=$(<"${keys}/device3.public") ;;
        *) public=$(wg genkey | wg pubkey) ;;
        esac
        jq -cn --arg publicKey "${public}" --arg address "10.87.0.${ordinal}/32" \
            '{publicKey:$publicKey,address:$address}' >>"${work}/devices.jsonl"
    done
    jq -n \
        --arg privateKey "${hub_private}" \
        --arg publicKey "${hub_public}" \
        --arg hostKey "${host_public}" \
        --slurpfile devices "${work}/devices.jsonl" \
        '{version:1,generation:1,privateKey:$privateKey,publicKey:$publicKey,listenPort:51888,mtu:1280,relayPrefix:"10.87.0.0/24",host:{publicKey:$hostKey,address:"10.87.0.1/32"},devices:$devices}' \
        >"${work}/config-capacity.json"
    jq '.generation=2 | .devices=[.devices[] | select(.address == "10.87.0.2/32" or .address == "10.87.0.3/32")]' \
        "${work}/config-capacity.json" >"${work}/config-small.json"
    jq -e '.generation == 1 and (.devices | length) == 253' "${work}/config-capacity.json" >/dev/null || fail "capacity manifest cardinality"
    jq -e '.generation == 2 and (.devices | length) == 2' "${work}/config-small.json" >/dev/null || fail "small manifest cardinality"
    printf '%s\n' '{"version":1,"prefixes":[]}' >"${work}/routes.json"
    atomic_install "${work}/config-capacity.json" /etc/reach-relay-hub/config.json root reach-relay 0640
    atomic_install "${work}/routes.json" /etc/reach-relay-hub/routes.json root reach-relay 0640

    cp /etc/nftables.conf "${work}/nftables-original.conf"
    cat >"${work}/firewall.nft" <<'NFT'
table inet reach_relay {
  chain input {
    type filter hook input priority -100; policy accept;
    iifname "rr-allowed" udp dport 51888 ip saddr { 192.0.2.2, 192.0.2.3, 192.0.2.4 } counter accept comment "reach relay peers"
    iifname "rr-allowed" udp dport 51888 counter drop comment "reach relay denied allowed ingress"
    iifname "lo" ip daddr 127.0.0.1 udp dport 51888 counter drop comment "reach relay denied loopback ipv4"
    iifname "lo" ip6 daddr ::1 udp dport 51888 counter drop comment "reach relay denied loopback ipv6"
    iifname "eth0" udp dport 51888 counter drop comment "reach relay denied eth0"
    udp dport 51888 counter drop comment "reach relay denied fallback"
  }
}
NFT
    install -o root -g root -m 0600 "${work}/firewall.nft" /etc/reach-relay-hub/firewall.nft
    printf '\ninclude "/etc/reach-relay-hub/firewall.nft"\n' >>/etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable nftables.service >/dev/null

    systemctl daemon-reload
    systemd-analyze verify /usr/lib/systemd/system/reach-relay-hub.service
    systemctl enable --now "${unit}" >"${evidence}/A1-start.txt"
    wait_ready 1 || fail "capacity generation did not become ready"
    pid=$(systemctl show -p MainPID --value "${unit}")
    [[ $(sha256sum /usr/lib/reach-relay-hub/reach-relay-hub | awk '{print $1}') == "${expected_binary}" ]] || fail "installed B hash"
    [[ $(sha256sum "/proc/${pid}/exe" | awk '{print $1}') == "${expected_binary}" ]] || fail "running B hash"
    [[ $(ps -o user= -p "${pid}" | tr -d ' ') == reach-relay ]] || fail "capacity service ran as root"
    [[ $(awk '/^CapEff:/ {print $2}' "/proc/${pid}/status") == 0000000000000000 ]] || fail "capacity effective capability present"
    [[ $(awk '/^CapAmb:/ {print $2}' "/proc/${pid}/status") == 0000000000000000 ]] || fail "capacity ambient capability present"
    [[ $(awk '/^NoNewPrivs:/ {print $2}' "/proc/${pid}/status") == 1 ]] || fail "no-new-privileges absent"
    [[ $(awk '/^Seccomp:/ {print $2}' "/proc/${pid}/status") == 2 ]] || fail "system-call filter absent"
    jq -e '.ready == true and .generation == 1 and .peerCount == 254 and (.peers | length) == 254' /run/reach-relay-hub/status.json >/dev/null || fail "capacity status cardinality"

    control_group=$(systemctl show -p ControlGroup --value "${unit}")
    memory_current=$(<"/sys/fs/cgroup${control_group}/memory.current")
    memory_max=$(<"/sys/fs/cgroup${control_group}/memory.max")
    tasks_current=$(<"/sys/fs/cgroup${control_group}/pids.current")
    tasks_max=$(<"/sys/fs/cgroup${control_group}/pids.max")
    fd_count=$(find "/proc/${pid}/fd" -mindepth 1 -maxdepth 1 | wc -l)
    [[ "${memory_max}" == 268435456 ]] || fail "unexpected MemoryMax ${memory_max}"
    [[ "${tasks_max}" == 128 ]] || fail "unexpected TasksMax ${tasks_max}"
    [[ $(systemctl show -p LimitNOFILE --value "${unit}") == 1024 ]] || fail "unexpected LimitNOFILE"
    [[ $(systemctl show -p LimitCORE --value "${unit}") == 0 ]] || fail "unexpected LimitCORE"
    (( memory_current < memory_max )) || fail "capacity memory limit exhausted"
    (( tasks_current < tasks_max )) || fail "capacity task limit exhausted"
    (( fd_count < 1024 )) || fail "capacity file-descriptor limit exhausted"
    [[ $(readlink "/proc/${pid}/ns/net") == "$(readlink /proc/1/ns/net)" ]] || fail "service entered an unexpected network namespace"
    {
        systemctl show "${unit}" \
            -p ActiveState -p SubState -p MainPID -p NRestarts -p ControlGroup \
            -p MemoryCurrent -p MemoryPeak -p MemoryMax -p TasksCurrent -p TasksMax \
            -p LimitNOFILE -p LimitCORE -p NoNewPrivileges -p RestrictNamespaces \
            -p PrivateDevices -p RestrictAddressFamilies
        printf 'cgroup_memory_current=%s\n' "${memory_current}"
        printf 'cgroup_memory_max=%s\n' "${memory_max}"
        printf 'cgroup_tasks_current=%s\n' "${tasks_current}"
        printf 'cgroup_tasks_max=%s\n' "${tasks_max}"
        printf 'open_fd_count=%s\n' "${fd_count}"
        awk '/^(Name|Uid|Gid|Threads|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters):/ {print}' "/proc/${pid}/status"
        grep -E 'Max open files|Max core file size' "/proc/${pid}/limits"
        printf 'service_netns=%s\n' "$(readlink "/proc/${pid}/ns/net")"
        printf 'init_netns=%s\n' "$(readlink /proc/1/ns/net)"
    } >"${evidence}/A1-capacity-resources.txt"
    chmod 0600 "${evidence}/A1-capacity-resources.txt"
    : >"${evidence}/A1-capacity-fds.txt"
    for descriptor in "/proc/${pid}"/fd/*; do
        target=$(readlink "${descriptor}" || true)
        target=$(printf '%s' "${target}" | sed -E 's/socket:\[[0-9]+\]/socket:[redacted]/g; s/anon_inode:\[[^]]+\]/anon_inode:[redacted]/g')
        printf '%s %s\n' "$(basename "${descriptor}")" "${target}" >>"${evidence}/A1-capacity-fds.txt"
    done
    chmod 0600 "${evidence}/A1-capacity-fds.txt"
    record_status A1-capacity
    record_process A1-capacity

    : >"${evidence}/A2-forbidden-operations.txt"
    expect_forbidden_system_operation link /usr/sbin/ip link add rr-forbidden type dummy
    expect_forbidden_system_operation route /usr/sbin/ip route add blackhole 203.0.113.252/32
    expect_forbidden_system_operation namespace /usr/sbin/ip netns add rr-forbidden
    expect_forbidden_system_operation firewall /usr/sbin/nft add table inet rr_forbidden
    chmod 0600 "${evidence}/A2-forbidden-operations.txt"
    if ip link show rr-forbidden >/dev/null 2>&1; then fail "forbidden link was created"; fi
    if ip route show table all | grep -q '203.0.113.252'; then fail "forbidden route was created"; fi
    if ip netns list | awk '{print $1}' | grep -qx rr-forbidden; then fail "forbidden namespace was created"; fi
    if nft list table inet rr_forbidden >/dev/null 2>&1; then fail "forbidden firewall table was created"; fi
    systemctl is-active --quiet "${unit}" || fail "negative operations stopped service"
    jq -e '.ready == true and .generation == 1 and .peerCount == 254' /run/reach-relay-hub/status.json >/dev/null || fail "negative operations changed readiness"

    # Restore the small real topology through the same in-place manager path.
    atomic_install "${work}/config-small.json" /etc/reach-relay-hub/config.json root reach-relay 0640
    systemctl reload "${unit}"
    wait_ready 2 || fail "small generation did not become ready"
    [[ $(systemctl show -p MainPID --value "${unit}") == "${pid}" ]] || fail "capacity shrink changed PID"
    jq -e '.ready == true and .generation == 2 and .peerCount == 3 and (.peers | length) == 3' /run/reach-relay-hub/status.json >/dev/null || fail "small status cardinality"
    device3_relay=10.87.0.3
    create_network
    for run in 1 2 3; do
        forward_three
        refresh_status
        record_status "A3-forward-${run}"
        record_counters "A3-forward-${run}"
    done
    record_process A3-small
    {
        printf 'capacity_generation=1 capacity_devices=253 capacity_peers=254\n'
        printf 'small_generation=2 small_devices=2 small_peers=3\n'
        printf 'pid_preserved=%s\n' "${pid}"
        printf 'encrypted_forwarding_runs=3\n'
    } >"${evidence}/A3-restoration.txt"
    chmod 0600 "${evidence}/A3-restoration.txt"

    # Remove every installed and mutable guest item, retaining only the
    # privacy-safe addendum evidence for host extraction before VM deletion.
    systemctl stop "${unit}"
    systemctl disable "${unit}" >/dev/null
    cleanup_network
    cp "${work}/nftables-original.conf" /etc/nftables.conf
    nft -f /etc/nftables.conf
    cp "${stock}" /etc/nftables.conf
    nft -f /etc/nftables.conf
    rm -f "${stock}" /var/tmp/reach-relay-linux-offline.txt
    systemctl disable nftables.service >/dev/null || true
    dpkg --purge reach-relay-hub >"${evidence}/A4-purge.txt"
    rm -rf /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub "${work}" "${keys}" "${package_root}" /var/tmp/reach-relay-linux-evidence
    systemctl daemon-reload
    systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
    userdel reach-relay >/dev/null 2>&1 || true
    groupdel reach-relay >/dev/null 2>&1 || true
    ! dpkg-query -W reach-relay-hub >/dev/null 2>&1 || fail "package receipt retained"
    ! systemctl is-active --quiet "${unit}" || fail "service retained"
    [[ $(systemctl show -p MainPID --value "${unit}" 2>/dev/null || echo 0) == 0 ]] || fail "process retained"
    ! ss -H -lun | grep -q ":${port} " || fail "listener retained"
    ! ip netns list | grep -Eq 'rr-host|rr-device2|rr-device3|rr-intruder|rr-denied|rr-eth0|rr-forbidden' || fail "namespace retained"
    ! ip link show rr-allowed >/dev/null 2>&1 || fail "bridge retained"
    ! nft list table inet reach_relay >/dev/null 2>&1 || fail "firewall retained"
    ! nft list table inet reach_offline >/dev/null 2>&1 || fail "offline policy retained"
    ! getent passwd reach-relay >/dev/null || fail "account retained"
    ! getent group reach-relay >/dev/null || fail "group retained"
    for path in /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub /usr/lib/reach-relay-hub /usr/lib/systemd/system/reach-relay-hub.service /usr/lib/sysusers.d/reach-relay-hub.conf /usr/lib/tmpfiles.d/reach-relay-hub.conf; do
        [[ ! -e "${path}" ]] || fail "path retained: ${path}"
    done
    {
        echo 'capacity=passed'
        echo 'small-encrypted-topology=passed-3-of-3'
        echo 'package=absent'
        echo 'service=absent'
        echo 'listener=absent'
        echo 'network-fixture=absent'
        echo 'firewall=absent'
        echo 'offline-policy=absent'
        echo 'operator-and-runtime-state=absent'
        echo 'account=absent'
    } >"${evidence}/A4-teardown.txt"
    chmod 0600 "${evidence}/A4-teardown.txt"
    find "${evidence}" -type f -exec chmod 0600 {} +
    count=$(find "${evidence}" -type f | wc -l)
    bytes=$(du -sb "${evidence}" | awk '{print $1}')
    (( count < 50 )) || fail "addendum evidence file overflow"
    (( bytes < 52428800 )) || fail "addendum evidence byte overflow"
    echo "capacity addendum complete files=${count} bytes=${bytes}"
    ;;

teardown)
    # L11/L12: finish on B, then remove every installed/operator/runtime item.
    wait_ready 2 || fail "final B authority absent before removal"
    [[ $(sha256sum /usr/lib/reach-relay-hub/reach-relay-hub | awk '{print $1}') == e5060d147bb4f8f2de22017e58474c27bd52afa01696f50256ae02843f066a6f ]] || fail "final B hash mismatch"
    device3_relay=10.87.0.4
    forward_three
    refresh_status
    record_process L11
    record_status L11
    record_counters L11
    pid=$(systemctl show -p MainPID --value "${unit}")
    {
        dpkg-query -W -f='package=${Package} version=${Version} status=${db:Status-Status}\n' reach-relay-hub
        sha256sum /usr/lib/reach-relay-hub/reach-relay-hub "/proc/${pid}/exe"
        systemctl show "${unit}" -p ActiveState -p SubState -p MainPID -p NRestarts -p UnitFileState
    } >"${evidence}/L11-final.txt"
    chmod 0600 "${evidence}/L11-final.txt"
    systemctl stop "${unit}"
    systemctl disable "${unit}" >/dev/null
    cleanup_network
    cp "${work}/nftables-original.conf" /etc/nftables.conf
    nft -f /etc/nftables.conf
    stock=/var/tmp/reach-relay-linux-nftables-stock.conf
    test -f "${stock}" || fail "offline stock rules missing"
    cp "${stock}" /etc/nftables.conf
    nft -f /etc/nftables.conf
    rm -f "${stock}" /var/tmp/reach-relay-linux-offline.txt
    systemctl disable nftables.service >/dev/null || true
    dpkg --purge reach-relay-hub >"${evidence}/L12-purge.txt"
    rm -rf /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub "${work}" "${keys}"
    systemctl daemon-reload
    systemctl reset-failed "${unit}" >/dev/null 2>&1 || true
    userdel reach-relay >/dev/null 2>&1 || true
    groupdel reach-relay >/dev/null 2>&1 || true
    ! dpkg-query -W reach-relay-hub >/dev/null 2>&1 || fail "package receipt retained"
    ! systemctl is-active --quiet "${unit}" || fail "service retained"
    [[ $(systemctl show -p MainPID --value "${unit}" 2>/dev/null || echo 0) == 0 ]] || fail "process retained"
    ! ss -H -lun | grep -q ":${port} " || fail "listener retained"
    ! ip netns list | grep -Eq 'rr-host|rr-device2|rr-device3|rr-intruder|rr-denied|rr-eth0' || fail "namespace retained"
    ! ip link show rr-allowed >/dev/null 2>&1 || fail "bridge retained"
    ! ip link show rr-denied-root >/dev/null 2>&1 || fail "denied interface retained"
    ! ip link show rr-eth0-root >/dev/null 2>&1 || fail "eth0 probe interface retained"
    ! nft list table inet reach_relay >/dev/null 2>&1 || fail "firewall retained"
    ! nft list table inet reach_offline >/dev/null 2>&1 || fail "offline policy retained"
    ! getent passwd reach-relay >/dev/null || fail "account retained"
    ! getent group reach-relay >/dev/null || fail "group retained"
    for path in /etc/reach-relay-hub /var/lib/reach-relay-hub /run/reach-relay-hub /usr/lib/reach-relay-hub /usr/lib/systemd/system/reach-relay-hub.service /usr/lib/sysusers.d/reach-relay-hub.conf /usr/lib/tmpfiles.d/reach-relay-hub.conf; do
        [[ ! -e "${path}" ]] || fail "path retained: ${path}"
    done
    {
        echo 'package=absent'
        echo 'service=absent'
        echo 'listener=absent'
        echo 'network-fixture=absent'
        echo 'firewall=absent'
        echo 'offline-policy=absent'
        echo 'operator-and-runtime-state=absent'
        echo 'account=absent'
    } >"${evidence}/L12-teardown.txt"
    chmod 0600 "${evidence}/L12-teardown.txt"
    find "${evidence}" -type f -exec chmod 0600 {} +
    count=$(find "${evidence}" -type f | wc -l)
    bytes=$(du -sb "${evidence}" | awk '{print $1}')
    (( count < 200 )) || fail "evidence file overflow"
    (( bytes < 52428800 )) || fail "evidence byte overflow"
    echo "teardown complete files=${count} bytes=${bytes}"
    ;;
*)
    fail "unknown phase"
    ;;
esac
