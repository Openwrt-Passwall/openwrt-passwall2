# PassWall2

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02%2B-blue)](https://openwrt.org/)
[![LuCI](https://img.shields.io/badge/LuCI-17.01%2B-green)](https://github.com/openwrt/luci)

PassWall2 is a powerful LuCI web interface application for OpenWrt that provides advanced proxy functionality. It's a comprehensive solution for network traffic management, proxy services, and access control on OpenWrt-based routers.

## 🛠️ Installation

### ⚠️ Pre-installation

```bash
# find it in releases,base of your router Arch
```
**Visit [GitHub Releases](https://github.com/Openwrt-Passwall/openwrt-passwall2/releases/latest) to download the correct package for your system.**

Choose the package format based on your **router's OpenWrt package manager**:

### For OpenWrt with OPKG 

1. **Download the IPK package** from the releases page  
   Look for `luci-app-passwall2_{VERSION}_all.ipk` in the Assets section.  
   > **Note:** If you need localization (Chinese/Persian), download the corresponding language package as well (e.g., `luci-i18n-passwall2-zh-cn...` or `...-fa...`).

2. **Upload to your router** (via SCP, LuCI upload, or wget):
   ```bash
   # Replace {VERSION} with the actual version (e.g., 26.2.5-1)
   wget https://github.com/Openwrt-Passwall/openwrt-passwall2/releases/download/{VERSION}/luci-app-passwall2_{VERSION}_all.ipk
   ```

3. **Install:**
   ```bash
   opkg update
   opkg install luci-app-passwall2_*.ipk
   ```
   
   > If installation fails due to missing dependencies (e.g., `xray-core`), you need to add the PassWall packages feed to `/etc/opkg/customfeeds.conf`.

### For OpenWrt with APK 

1. **Download the APK package** from the releases page  
   Look for `luci-app-passwall2_{VERSION}_all.apk` in the Assets section.
   > **Note:** If you need localization (Chinese/Persian), download the corresponding language package as well (e.g., `luci-i18n-passwall2-zh-cn...` or `...-fa...`).

2. **Upload to your router** (via SCP, LuCI upload, or wget):
   ```bash
   # Replace {VERSION} with the actual version (e.g., 26.2.5-1)
   wget https://github.com/Openwrt-Passwall/openwrt-passwall2/releases/download/{VERSION}/luci-app-passwall2_{VERSION}_all.apk
   ```

3. **Install:**
   ```bash
   apk add --allow-untrusted luci-app-passwall2_*.apk
   ```
   
   > ⚠️ **Security Note:** `--allow-untrusted` bypasses package signature verification. 

> **How to check your package manager:** Run `opkg --version` or `apk --version` to see which one your router uses.

### Restart LuCI
```bash
/etc/init.d/rpcd restart
```

### 🧩 Add PassWall2 APK repository (recommended)
**Instead of installing .apk packages manually**, you can add the PassWall2 APK repository and signing key to enable installation and updates via apk.

1. Add repository signing key

```bash
wget -O passwall.pub https://sourceforge.net/projects/openwrt-passwall-build/files/apk.pub
mv passwall.pub /etc/apk/keys/
```

2. Add PassWall2 repositories

```bash
. /etc/openwrt_release

release="${DISTRIB_RELEASE%.*}"
arch="$DISTRIB_ARCH"

wget -O /etc/apk/keys/passwall.pub \
  https://sourceforge.net/projects/openwrt-passwall-build/files/apk.pub

cat >> /etc/apk/repositories.d/customfeeds.list <<EOF
https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-${release}/${arch}/passwall_packages/packages.adb
https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-${release}/${arch}/passwall_luci/packages.adb
https://sourceforge.net/projects/openwrt-passwall-build/files/releases/packages-${release}/${arch}/passwall2/packages.adb
EOF
```

3. Update package index

```bash
apk update
```

4. Install optional dependency packages (depending on your configuration) and PassWall2 from repository

```bash
apk add tcping geoview # add other dependencies

apk add luci-app-passwall2
```


## 📋 System Requirements

### OpenWrt Version
- OpenWrt 21.02 or later
- LuCI 17.01 or later

### Hardware Requirements
- **Minimum 256MB RAM**
- Sufficient storage for packages (varies by protocol selection)

### Core Dependencies
The following packages should be resolved automatically by the package manager (if available in your feeds):

- `coreutils`, `coreutils-base64`, `coreutils-nohup`
- `curl`, `ip-full`, `libuci-lua`, `lua`, `luci-compat`, `luci-lib-jsonc`
- `resolveip`, `tcping`, `unzip`
- `geoview`, `v2ray-geoip`, `v2ray-geosite` (geo-routing data)

> **Note:** Actual dependencies may vary based on selected features and your OpenWrt build. Ensure you have the necessary feeds configured.

### Optional Protocol Packages
Selected during installation based on your needs:
- Xray
- Sing-Box
- Shadowsocks-Rust
- ShadowsocksR
- HAProxy

## 🚀 Features

### Multi-Protocol Support
- **Xray** (HTTP, Socks, Shadowsocks, VMess, VLESS, Trojan, Hysteria2, WireGuard)
- **Sing-Box** (HTTP, Socks, SSH, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria, Hysteria2, WireGuard, AnyTLS)
- **Shadowsocks-Rust**
- **ShadowsocksR** legacy support
- **HAProxy** The Reliable, High Performance TCP/HTTP Load Balancer

### Traffic Management
- **Load Balancing**: Distribute traffic across multiple nodes
- **Smart Routing**: Domain-based and geo-based routing rules
- **DNS Control**: Advanced DNS filtering and DoH/DoT support
- **Transparent Proxy**: Seamless network-wide proxy

### Node Management
- **Subscription Support**: Import nodes from subscription URLs
- **Node Testing**: Built-in latency and connectivity testing
- **Failover Support**: Automatic failover to backup nodes
- **QR Code**: Generate and scan QR codes for node sharing

### Access Control
- **Per-Device Rules**: Configure proxy settings per device
- **Domain/IP Filtering**: Whitelist/blacklist support
- **Time-based Rules**: Schedule proxy usage
- **DNS Ad Blocking**: Block ads/trackers network-wide at the DNS stage — see [DNS Ad Blocking](#-dns-ad-blocking)

## 🛡️ DNS Ad Blocking

PassWall2 can block advertisements and trackers at the **DNS resolution stage** on the router. The protection applies **network-wide** to every connected device and covers **both domestic and foreign traffic** — it is not tied to any proxy node or protocol.

### How it works

1. **DNS-layer interception.** When a client queries an ad/tracker domain, dnsmasq answers with a NULL address (`address=/domain/#`, which resolves to `0.0.0.0` for A and `::` for AAAA) **before** any routing or proxy decision is made. The domain therefore never resolves and the ad resource cannot load. Because the block happens at DNS time, it works regardless of whether the traffic would later go direct or through a proxy node.
2. **Global rule source.** The source is a single global setting (stored under `@global_rules[0].enable_adblock`, not per-node). The chosen list is downloaded, normalized, and written to `/usr/share/passwall2/adblock.conf`.
3. **Injection into dnsmasq.** On service start, the rule file is copied into each dnsmasq instance as `002-address.conf` (loaded via the instance's `conf-dir`), so the blocking rules take effect immediately for all DNS queries handled by PassWall2.

> **Why a restart is needed after changing/updating rules:** sing-box / xray only read the geo and rule files when the process starts, so selecting a new adblock source or pulling updated rules triggers a service restart to regenerate the DNS configuration. (This differs from tools such as `dae`, where a `reload` is sufficient.)

### Built-in rule sources

| Source | Format | URL |
| --- | --- | --- |
| **NEO DEV HOST** | dnsmasq (`address=`) | `https://raw.githubusercontent.com/neodevpro/neodevhost/master/dnsmasq.conf` |
| **anti-AD** | dnsmasq (`address=`) | `https://anti-ad.net/anti-ad-for-dnsmasq.conf` |
| **AdGuard DNS Filter** | AdBlock filter | `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt` |
| **Custom URL** | Auto-detected | Paste any other rule-source URL (both AdGuardHome and dnsmasq formats are supported) |

The format is auto-detected: if at least half of the lines are `address=` entries it is treated as dnsmasq format (kept as-is, with an AAAA `::` block added for IPv4-only rules); otherwise it is parsed as an AdBlock filter list and converted to `address=/domain/#` rules. A source quality gate rejects lists with fewer than 10 rules or with less than 50% valid domains, so a wrong or broken source fails safe.

### Configuration

- **Enable:** `Services` → `PassWall2` → `Basic Settings` → **Shunt Rules** tab → **Adblock** dropdown. Pick a built-in source, paste your own URL, or select **Close** to disable.
- **Automatic updates:** `Services` → `PassWall2` → **Rule Update** page → tick **Adblock rules**, then set the update schedule (daily / weekly / loop interval). Updates run through the same cron/loop engine as the geoip/geosite updates.

## ⚙️ Configuration

### Basic Setup

1. **Access LuCI Interface:**
   - Navigate to `Services` → `PassWall2`

2. **Add Your First Node:**
   - Go to `Node List` → `Add Node`
   - Select protocol and fill in server details

3. **Configure Basic Settings:**
   - Select your default node
   - Configure DNS settings
   - Enable transparent proxy

4. **Apply Configuration:**
   - Click `Save & Apply`

## 🌐 Language Support

PassWall2 supports multiple languages:
- 🇨🇳 Chinese (Simplified/Traditional)
- 🇮🇷 Persian (فارسی)

Language files are organized in `luci-app-passwall2/po/` subdirectories.

## 🔧 Troubleshooting

### Common Issues

**Service Won't Start**
```bash
logread | grep passwall2
```
Check system logs, verify node configuration, and ensure required packages are installed.

**DNS Issues**
- Disable built-in DNS in browsers (Chrome: Settings → Privacy → Security → Disable "Use secure DNS")
- Clear DNS cache after reboot: `ipconfig /flushdns` (Windows) or toggle airplane mode (mobile)

**Connection Problems**
- Test node connectivity
- Check firewall rules
- Verify transparent proxy settings

### Debug Mode

Enable debug logging in `Other Settings` and check:
- Main log: `/tmp/log/passwall2.log`
- Server log: `/tmp/log/passwall2_server.log`

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

**Note**: This software is intended for legal use only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.

---

## Stargazers over time
[![Stargazers over time](https://starchart.cc/Openwrt-Passwall/openwrt-passwall2.svg?variant=adaptive)](https://starchart.cc/Openwrt-Passwall/openwrt-passwall2)
