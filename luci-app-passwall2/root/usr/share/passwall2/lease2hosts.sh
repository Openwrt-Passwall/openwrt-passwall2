#!/bin/sh

# DHCP leases and static hosts to hosts

. /lib/functions.sh
. /usr/share/passwall2/utils.sh
LOCK_FILE=${LOCK_PATH}/${CONFIG}_lease2hosts.lock
DNSMASQ_LEASE_FILE=$(uci -q get 'dhcp.@dnsmasq[0].leasefile')
DNSMASQ_LEASE_FILE=${DNSMASQ_LEASE_FILE:-/tmp/dhcp.leases}
ODHCPD_LEASE_FILE=$(uci -q get dhcp.odhcpd.leasefile)
ODHCPD_LEASE_FILE=${ODHCPD_LEASE_FILE:-/tmp/odhcpd.leases}
HOSTS_FILE="$TMP_PATH2/dhcp-hosts"
TMP_FILE="/tmp/dhcp-hosts.tmp"

exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

read_static_host() {
	local name ip
	config_get name "$1" name
	config_get ip "$1" ip
	[ -n "$name" ] && [ "$name" != "*" ] && [ -n "$ip" ] && [ "$ip" != "ignore" ] || return
	printf '%s %s\n' "$ip" "$name"
}

# Static DHCP configuration only needs to be read once at startup.
STATIC_HOSTS=$(
	config_load dhcp
	config_foreach read_static_host host
)

read_odhcpd_leases() {
	[ -f "$ODHCPD_LEASE_FILE" ] || return
	awk -v now="$(date +%s)" '
		function valid_name(name) {
			return name ~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/
		}
		# State records: # interface DUID IAID hostname expiry assigned length address/prefix ...
		$1 == "#" {
			if (NF < 9 || !valid_name($5) || ($6 != -1 && $6 <= now))
				next
			# Only host addresses, never delegated IPv6 prefixes.
			if (!(($4 == "ipv4" && $8 == 32) || ($4 != "ipv4" && $8 == 128)))
				next
			for (i = 9; i <= NF; i++) {
				split($i, addr, "/")
				print addr[1] " " $5
			}
			next
		}
		# Older odhcpd versions also include hosts-format lines, with optional aliases.
		NF >= 2 && $1 ~ /^[0-9a-fA-F:.]+$/ {
			for (i = 2; i <= NF && $i !~ /^#/; i++)
				if (valid_name($i))
					print $1 " " $i
		}
	' "$ODHCPD_LEASE_FILE"
}

reload_dnsmasq_pids() {
	local pidfile pid
	find $TMP_PATH/acl -type f -name '*_dnsmasq.pid' 2>/dev/null | while read pidfile; do
		if [ -s "$pidfile" ]; then
			read pid < "$pidfile"
			if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
				kill -HUP "$pid"
			fi
		fi
	done
}

while true; do

	{
		[ -n "$STATIC_HOSTS" ] && printf '%s\n' "$STATIC_HOSTS"
		if [ -f "$DNSMASQ_LEASE_FILE" ]; then
			awk 'NF >= 4 && $4 != "*" {print $3" "$4}' "$DNSMASQ_LEASE_FILE"
		fi
		read_odhcpd_leases
	} | sort -u > "$TMP_FILE"
	if [ -s "$TMP_FILE" ]; then
		if [ ! -f "$HOSTS_FILE" ] || ! cmp -s "$TMP_FILE" "$HOSTS_FILE"; then
			mv "$TMP_FILE" "$HOSTS_FILE"
			reload_dnsmasq_pids
		else
			rm -f "$TMP_FILE"
		fi
	else
		if [ -s "$HOSTS_FILE" ]; then
			: > "$HOSTS_FILE"
			reload_dnsmasq_pids
		fi
		rm -f "$TMP_FILE"
	fi

	sleep 60 9>&-

done 2>/dev/null
