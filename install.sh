#!/bin/sh

PKG_DEPS="xray-core v2ray-geoip v2ray-geosite chinadns-ng tcping geoview"
KMODS="kmod-nft-socket kmod-nft-tproxy kmod-nft-nat"
API_SB="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
API_PW="https://api.github.com/repos/Openwrt-Passwall/openwrt-passwall2/releases/latest"
TMP_DIR="/tmp/passwall_install"

C_GREEN="\033[32;1m"
C_WARN="\033[33;1m"
C_ERR="\033[31;1m"
C_RESET="\033[0m"


msg() { printf "${C_GREEN}%s${C_RESET}\n" "$1"; }
warn() { printf "${C_WARN}%s${C_RESET}\n" "$1"; }
err() { printf "${C_ERR}%s${C_RESET}\n" "$1"; exit 1; }

is_installed() {
    opkg list-installed | grep -q "^$1 "
}

ask() {
    local prompt="$1"
    local def="$2"
    local suffix="[Y/n]"
    [ "$def" = "N" ] && suffix="[y/N]"

    printf "${C_GREEN}%s %s: ${C_RESET}" "$prompt" "$suffix"
    read -r ans
    [ -z "$ans" ] && ans="$def"
    case "$ans" in [yY]*) return 0 ;; *) return 1 ;; esac
}

get_json_val() {
    wget --no-check-certificate -qO- "$1" | grep -o "$2" | head -n 1
}

prepare_system() {
    msg "Checking system prerequisites..."

    # 1. Unzip Check
    if ! is_installed "unzip"; then
        msg "Installing unzip utility..."
        opkg install unzip || err "Failed to install unzip"
    fi

    # 2. DNSMasq Check: Replace basic dnsmasq with dnsmasq-full
    if ! is_installed "dnsmasq-full"; then
        if is_installed "dnsmasq"; then
            msg "Removing basic dnsmasq to replace with full version..."
            opkg remove dnsmasq
        fi
        msg "Installing dnsmasq-full..."
        opkg install dnsmasq-full || err "Failed to install dnsmasq-full"
    fi

    # 3. Kernel Modules Check
    for kmod in $KMODS; do
        if ! is_installed "$kmod"; then
            msg "Installing module: $kmod..."
            opkg install "$kmod" || warn "Failed to install $kmod (might be missing in repo)"
        fi
    done
}

install_dep_from_zip() {
    local pkg="$1"
    local zip="$2"

    if is_installed "$pkg"; then
        return
    fi

    if unzip -l "$zip" | grep -q "$pkg"; then
        unzip -jo "$zip" "*${pkg}*.ipk" -d "$TMP_DIR" >/dev/null 2>&1
        local ipk
        ipk=$(find "$TMP_DIR" -name "*${pkg}*.ipk" | head -n 1)
        
        if [ -n "$ipk" ]; then
            msg "Installing $pkg..."
            opkg install "$ipk" --force-overwrite
            rm -f "$ipk"
        else
            warn "Extracted $pkg but ipk file not found."
        fi
    else
        warn "Package $pkg not found in the downloaded archive."
    fi
}

install_singbox() {
    local arch="$1"
    if is_installed "sing-box"; then
        return
    fi

    msg "Fetching Sing-box URL..."
    local url
    url=$(get_json_val "$API_SB" "https://[^\"]*sing-box_[^\"]*_openwrt_${arch}\.ipk")
    [ -z "$url" ] && url=$(get_json_val "$API_SB" "https://[^\"]*sing-box_[^\"]*_${arch}\.ipk")

    if [ -n "$url" ]; then
        msg "Installing Sing-box from $url..."
        opkg install "$url" --force-overwrite
    else
        warn "Sing-box package not found for architecture: $arch"
    fi
}

main() {
    rm -rf "$TMP_DIR" && mkdir -p "$TMP_DIR"
    
    ask "Install sing-box?" "Y" && DO_SB=1
    ask "Install hysteria?" "N" && DO_HY=1

    msg "Updating package feeds..."
    opkg update
    prepare_system

    # Detect architecture
    local arch
    arch=$(opkg print-architecture | awk '$2!="all" {print $2}' | tail -n1)
    [ -z "$arch" ] && err "Failed to detect architecture."
    msg "Detected architecture: $arch"

    # Fetch Passwall release info
    msg "Fetching Passwall release info..."
    local json_pw
    json_pw=$(wget --no-check-certificate -qO- "$API_PW")
    
    local zip_url
    zip_url=$(echo "$json_pw" | grep -o "https://[^\"]*passwall_packages_ipk_${arch}\.zip" | head -n 1)
    [ -z "$zip_url" ] && zip_url=$(echo "$json_pw" | grep -o "https://[^\"]*passwall_packages_ipk_.*generic\.zip" | head -n 1)
    
    [ -z "$zip_url" ] && err "Dependencies ZIP URL not found in release data."
    
    # Download dependencies
    msg "Downloading dependencies archive..."
    wget --no-check-certificate -O "$TMP_DIR/deps.zip" "$zip_url" || err "Download failed."

    # Install dependencies
    for pkg in $PKG_DEPS; do
        install_dep_from_zip "$pkg" "$TMP_DIR/deps.zip"
    done

    if [ "$DO_HY" = "1" ]; then
        install_dep_from_zip "hysteria" "$TMP_DIR/deps.zip"
    fi

    if [ "$DO_SB" = "1" ]; then
        install_singbox "$arch"
    fi

    # Install LuCI
    local luci_url
    luci_url=$(echo "$json_pw" | grep -o "https://[^\"]*luci-app-passwall2[^\"]*_all\.ipk" | head -n 1)
    
    if [ -n "$luci_url" ]; then
        msg "Installing LuCI app Passwall2..."
        opkg install "$luci_url" --force-overwrite
    else
        err "LuCI package not found in release data."
    fi

    # Final cleanup
    rm -rf "$TMP_DIR"
    msg "Installation complete!"
}

main