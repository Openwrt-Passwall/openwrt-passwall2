# PassWall2（广告过滤增强版 / Ad-Blocking Fork）

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02%2B-blue)](https://openwrt.org/)
[![LuCI](https://img.shields.io/badge/LuCI-17.01%2B-green)](https://github.com/openwrt/luci)

> **📌 本仓库说明 / About this fork**
>
> 本仓库 = 上游官方 **[Openwrt-Passwall/openwrt-passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2)** + **DNS 层广告过滤功能补充**。
> 除广告过滤外，其余功能、界面与代码均与官方保持同步；广告过滤的具体实现与用法见下方「广告过滤功能」一节。
>
> *This repository is the upstream official release **plus a DNS-stage ad-blocking supplement**. All other features, UI and code track upstream; see "广告过滤功能 / DNS Ad Blocking" below for the added capability.*

---

# 📘 中文版（优先阅读 / Read First）

## 简介

PassWall2 是 OpenWrt 上一款功能强大的 LuCI 代理管理界面，提供高级代理、流量管理与访问控制能力。本仓库在官方版基础上**额外补充了 DNS 层广告过滤功能**，可在路由器层面网络级拦截广告与追踪器。

## 🛠️ 安装

### ⚠️ 安装前准备

在 [GitHub Releases](https://github.com/itoywh/openwrt-passwall2/releases/latest) 下载对应你路由器架构的包（本 fork 的发布位于 `itoywh/openwrt-passwall2`）。

根据你路由器的 OpenWrt 包管理器选择格式：

### OPKG 系统的 OpenWrt

1. 从 Releases 下载 IPK 包（如 `luci-app-passwall2_{VERSION}_all.ipk`），需要中文界面请同时下载 `luci-i18n-passwall2-zh-cn...`。
2. 上传到路由器并安装：
   ```bash
   opkg update
   opkg install luci-app-passwall2_*.ipk
   ```
   > 若因缺少依赖（如 `xray-core`）安装失败，需先把 PassWall 软件源加入 `/etc/opkg/customfeeds.conf`。

### APK 系统的 OpenWrt（如 ImmortalWrt 25.12+）

1. 下载 APK 包（如 `luci-app-passwall2_{VERSION}_all.apk`）。
2. 安装：
   ```bash
   apk add --allow-untrusted luci-app-passwall2_*.apk
   ```
   > ⚠️ `--allow-untrusted` 会跳过签名校验。

### 重启 LuCI
```bash
/etc/init.d/rpcd restart
```

## 📋 系统要求

- OpenWrt 21.02 及以上，LuCI 17.01 及以上
- 最低 256MB RAM，足够的存储空间（依所选协议而定）
- 核心依赖：`coreutils`、`curl`、`lua`、`luci-compat`、`geoview`、`v2ray-geoip`、`v2ray-geosite` 等（由包管理器自动解析）
- 可选协议包（按需要安装）：Xray、Sing-Box、Shadowsocks-Rust、ShadowsocksR、HAProxy

## 🚀 功能特性

### 多协议支持
- **Xray**（HTTP、Socks、Shadowsocks、VMess、VLESS、Trojan、Hysteria2、WireGuard）
- **Sing-Box**（HTTP、Socks、SSH、Shadowsocks、VMess、VLESS、Trojan、TUIC、Hysteria、Hysteria2、WireGuard、AnyTLS）
- **Shadowsocks-Rust**、**ShadowsocksR**、**HAProxy**

### 流量管理
- **负载均衡**：多节点流量分发
- **智能路由**：基于域名 / 地理位置的路由规则
- **DNS 控制**：高级 DNS 过滤、DoH/DoT 支持
- **透明代理**：全网透明代理

### 节点管理
- **订阅支持**：从订阅 URL 导入节点
- **节点测速**：内置延迟与连通性测试
- **故障转移**：自动切换到备用节点
- **二维码**：生成 / 扫描节点分享二维码

### 访问控制
- **按设备规则**：为每台设备单独配置
- **域名 / IP 过滤**：白名单 / 黑名单
- **定时规则**：按时间调度代理
- **DNS 广告过滤**：在 DNS 环节网络级拦截广告 / 追踪器（见下）

## 🛡️ 广告过滤功能

本仓库在官方版基础上补充的 **DNS 层广告过滤**，可在路由器上于 **DNS 解析阶段** 拦截广告与追踪器。保护覆盖 **全网所有设备**，且对 **国内外流量均生效**——它不与任何代理节点或协议绑定。

### 工作原理

1. **DNS 层拦截。** 当客户端查询广告 / 追踪器域名时，dnsmasq 在**任何路由或代理决策之前**直接返回 NULL 地址（`address=/domain/#`，A 记录解析为 `0.0.0.0`、AAAA 记录解析为 `::`）。域名因此无法解析，广告资源也就无法加载。由于拦截发生在 DNS 时刻，无论该流量之后走直连还是走代理节点，都能生效。
2. **全局规则源。** 规则源是一个单一的全局设置（存储在 `@global_rules[0].enable_adblock`，而非按节点），所选列表会被下载、规整并写入 `/usr/share/passwall2/adblock.conf`。
3. **注入 dnsmasq。** 服务启动时，规则文件会被复制进每个 dnsmasq 实例，作为其 `002-address.conf`（通过实例的 `conf-dir` 加载），从而使拦截规则对 PassWall2 处理的所有 DNS 查询立即生效。

> **为何更改 / 更新规则后需要重启：** sing-box / xray 仅在进程启动时读取规则文件，因此切换广告规则源或拉取更新后的规则会触发一次服务重启以重建 DNS 配置。（这与 `dae` 等工具不同——`dae` 只需 `reload` 即可。）

### 内置规则源

| 规则源 | 格式 | 地址 |
| --- | --- | --- |
| **NEO DEV HOST** | dnsmasq（`address=`） | `https://raw.githubusercontent.com/neodevpro/neodevhost/master/dnsmasq.conf` |
| **anti-AD** | dnsmasq（`address=`） | `https://anti-ad.net/anti-ad-for-dnsmasq.conf` |
| **AdGuard DNS Filter** | AdBlock 过滤格式 | `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt` |
| **自定义 URL** | 自动识别 | 粘贴任意其他规则源 URL（同时支持 AdGuardHome 与 dnsmasq 格式） |

格式自动识别：若至少一半行为 `address=` 条目，则按 dnsmasq 格式处理（原样保留，并为仅 IPv4 的规则补充 AAAA `::` 块）；否则按 AdBlock 过滤列表解析，转换为 `address=/domain/#` 规则。质量门控会拒绝少于 10 条规则或有效域名占比低于 50% 的来源，因此错误 / 损坏的来源会安全失败（fail safe）。

### 配置

- **开启：** `服务` → `PassWall2` → `基本设置` → **分流规则** 标签页 → **广告过滤** 下拉框。选择内置源、粘贴自有 URL，或选 **关闭** 以停用。
- **自动更新：** `服务` → `PassWall2` → **规则更新** 页面 → 勾选 **广告过滤规则**，然后设置更新计划（每天 / 每周 / 循环间隔）。更新复用与 geoip/geosite 相同的 cron / 循环调度引擎。

## ⚙️ 基本配置

1. 访问 LuCI：`服务` → `PassWall2`
2. 添加节点：`节点列表` → `添加节点`，选择协议并填写服务器信息
3. 配置基本设置：选择默认节点、配置 DNS、启用透明代理
4. 点击 `保存并应用`

## 🌐 语言支持

- 🇨🇳 中文（简体 / 繁体）
- 🇮🇷 波斯语（فارسی）

语言文件位于 `luci-app-passwall2/po/` 各子目录。

## 🔧 故障排查

**服务无法启动**：`logread | grep passwall2` 查看日志，检查节点配置与依赖包。

**DNS 问题**：在浏览器中关闭内置安全 DNS（Chrome：设置 → 隐私 → 安全 → 关闭"使用安全 DNS"）；重启后清除 DNS 缓存（`ipconfig /flushdns` 或切换飞行模式）。

**调试模式**：在 `其他设置` 中开启调试日志，主日志位于 `/tmp/log/passwall2.log`。

## 📄 许可证

本项目基于 GNU General Public License v3.0 许可——详见 [LICENSE](LICENSE) 文件。

> **注意**：本软件仅供合法用途。用户须自行遵守所在司法辖区的一切适用法律法规。

---

# 📗 English Version

PassWall2 is a powerful LuCI web interface application for OpenWrt that provides advanced proxy functionality. It's a comprehensive solution for network traffic management, proxy services, and access control on OpenWrt-based routers.

## 🛠️ Installation

### ⚠️ Pre-installation

```bash
# find it in releases,base of your router Arch
```
**Visit [GitHub Releases](https://github.com/itoywh/openwrt-passwall2/releases/latest) to download the correct package for your system.**

Choose the package format based on your **router's OpenWrt package manager**:

### For OpenWrt with OPKG 

1. **Download the IPK package** from the releases page  
   Look for `luci-app-passwall2_{VERSION}_all.ipk` in the Assets section.  
   > **Note:** If you need localization (Chinese/Persian), download the corresponding language package as well (e.g., `luci-i18n-passwall2-zh-cn...` or `...-fa...`).

2. **Upload to your router** (via SCP, LuCI upload, or wget):
   ```bash
   # Replace {VERSION} with the actual version (e.g., 26.2.5-1)
   wget https://github.com/itoywh/openwrt-passwall2/releases/download/{VERSION}/luci-app-passwall2_{VERSION}_all.ipk
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
   wget https://github.com/itoywh/openwrt-passwall2/releases/download/{VERSION}/luci-app-passwall2_{VERSION}_all.apk
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
