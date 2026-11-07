# Rule 03: Routing, Netfilter & Proxy Cores

This rule specifies the network packet handling, firewall integration, and proxy core requirements for PassWall 2.

---

## 1. Firewall Coexistence: firewall4 (nftables) vs firewall3 (iptables)
OpenWrt 22.03+ transitioned to `firewall4` utilizing `nftables`, while older releases (21.02) rely on `firewall3` utilizing `iptables`.
- **Dual Compatibility**:
  - PassWall 2 scripts must detect and support both `fw4` (`nftables`) and `fw3` (`iptables`).
  - Check firewall engine dynamically before injecting rules:
    ```sh
    if command -v fw4 >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    else
        FIREWALL_BACKEND="iptables"
    fi
    ```
- **Clean Rule Cleanup**:
  - Always tear down custom chains, sets, and tables cleanly upon service stop or restart (`/etc/init.d/passwall2 stop`).
  - Never leave orphaned `nftables` tables or dangling `iptables` mangle rules that hijack port 53 or 80/443 after service termination.

## 2. Transparent Proxying Modes
- **TPROXY (TCP/UDP)**:
  - Requires `iptables-mod-tproxy` or `nftables` with socket matching.
  - Requires marked routing: `ip rule add fwmark <mark> table <table_id>` and `ip route add local 0.0.0.0/0 dev lo table <table_id>`.
  - Preserves original destination IP and port; preferred for UDP and TCP on modern kernels.
- **REDIRECT**:
  - Rewrites destination to local socket (`127.0.0.1:<port>`).
  - Works only for TCP on IPv4; requires `SO_ORIGINAL_DST` to recover destination.
- **TUN Interface**:
  - Used for Sing-Box / Xray TUN mode or specific encapsulation needs.
  - Requires strict MTU configuration (usually 1500 - encapsulation overhead, e.g. 1400 or 1280 for IPv6) to avoid packet fragmentation.

## 3. DNS Interception & Leak Prevention
- Transparent DNS hijacking intercepts UDP/TCP port 53 traffic from LAN.
- Integration with `chinadns-ng`, `dnsmasq`, or core internal DNS:
  - Separate domestic/clean queries from foreign/proxy queries.
  - Ensure local router queries do not loop back into the proxy core (`anti-loop` protection).
  - Use `ipset` or `nftables set` to dynamically route resolved IPs.

## 4. Proxy Core Integration
- Supported cores: **Xray-core**, **Sing-Box**, **Shadowsocks-Rust**, **Haproxy**, **Trojan-Go**, **NaiveProxy**.
- PassWall 2 generates JSON configurations on-the-fly in `/var/etc/passwall2/`.
- Ensure generated core configurations:
  - Validate JSON schema correctness before launching daemon processes.
  - Use non-overlapping local listening ports for SOCKS5, HTTP, and TPROXY inbounds.
  - Cleanly terminate background processes with `kill` and fallback to `kill -9` if unresponsive after timeout.
