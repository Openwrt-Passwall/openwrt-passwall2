#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for backend in nftables iptables; do
	file="$repo_root/luci-app-passwall2/root/usr/share/passwall2/$backend.sh"
	guards=$(grep -F '[ -z "$no_' "$file" | grep -F '_proxy" ] && [ -n "$redir_port" ] && {' | sed -n '1,2p' | sed 's/.*\$no_\([a-z]*\)_proxy.*/\1/')
	if [ "$guards" != "$(printf 'tcp\nudp')" ]; then
		echo "$backend: ACL UDP proxy rules must use no_udp_proxy" >&2
		exit 1
	fi
done

echo "ACL firewall rule tests passed"
