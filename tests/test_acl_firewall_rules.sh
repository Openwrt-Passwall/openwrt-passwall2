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

nftables_file="$repo_root/luci-app-passwall2/root/usr/share/passwall2/nftables.sh"
dns_insert_count=$(grep -F 'insert rule $NFTABLE_NAME PSW2_MANGLE' "$nftables_file" | grep -F 'dport 53 counter accept' | wc -l)
if [ "$dns_insert_count" -ne 4 ]; then
	echo "nftables: DNS exclusions must be inserted before transparent proxy rules" >&2
	exit 1
fi

iptables_file="$repo_root/luci-app-passwall2/root/usr/share/passwall2/iptables.sh"
dns_insert_count=$(grep -E '\$ipt_m -I PSW2|-I PSW2 -p' "$iptables_file" | grep -F -- '--dport 53 -j ACCEPT' | wc -l)
if [ "$dns_insert_count" -ne 4 ]; then
	echo "iptables: DNS exclusions must be inserted before transparent proxy rules" >&2
	exit 1
fi

echo "ACL firewall rule tests passed"
