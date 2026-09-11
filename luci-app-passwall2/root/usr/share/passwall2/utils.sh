#!/bin/sh
# Copyright (C) 2022-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization

CONFIG=passwall2
APP_PATH=/usr/share/${CONFIG}
TMP_PATH=/tmp/etc/${CONFIG}
TMP_PATH2=${TMP_PATH}_tmp
LOCK_PATH=/tmp/lock
LOG_FILE=/tmp/log/${CONFIG}.log
TMP_ACL_PATH=${TMP_PATH}/acl
TMP_BIN_PATH=${TMP_PATH}/bin
TMP_IFACE_PATH=${TMP_PATH}/iface
TMP_ROUTE_PATH=${TMP_PATH}/route
TMP_SCRIPT_FUNC_PATH=${TMP_PATH}/script_func
TMP_PROCESS_LIST_PATH=${TMP_PATH}/process_list

. /lib/functions/network.sh

config_get_type() {
	local ret=$(uci -q get "${CONFIG}.${1}" 2>/dev/null)
	echo "${ret:=$2}"
}

config_n_get() {
	local ret=$(uci -q get "${CONFIG}.${1}.${2}" 2>/dev/null)
	echo "${ret:=$3}"
}

config_t_get() {
	local index=${4:-0}
	local ret=$(uci -q get "${CONFIG}.@${1}[${index}].${2}" 2>/dev/null)
	echo "${ret:=${3}}"
}

eval_set_val() {
	for i in $@; do
		for j in $i; do
			eval $j
		done
	done
}

eval_unset_val() {
	for i in $@; do
		for j in $i; do
			eval unset $j
		done
	done
}

eval_cache_var() {
	[ -s "$TMP_PATH/var" ] && eval $(cat "$TMP_PATH/var")
}

get_cache_var() {
	local key="${1}"
	[ -n "${key}" ] && [ -s "$TMP_PATH/var" ] && {
		echo $(cat $TMP_PATH/var | grep "^${key}=" | awk -F '=' '{print $2}' | tail -n 1 | awk -F'"' '{print $2}')
	}
}

set_cache_var() {
	local key="${1}"
	shift 1
	local val="$@"
	[ -n "${key}" ] && [ -n "${val}" ] && {
		[ ! -d $TMP_PATH ] && mkdir -p $TMP_PATH
		sed -i "/${key}=/d" $TMP_PATH/var >/dev/null 2>&1
		echo "${key}=\"${val}\"" >> $TMP_PATH/var
		eval ${key}=\"${val}\"
	}
}

echolog() {
	echo -e "$*" >>$LOG_FILE
}

echolog_date() {
	local d="$(date "+%Y-%m-%d %H:%M:%S")"
	echolog "$d: $*"
}

i18n() {
	echo "$(lua ${APP_PATH}/i18n.lua "$@")"
}

log() {
	local num="$1"
	shift
	local content="$@"
	local indent=""
	if [ "$num" -ge 1 ]; then
		for i in $(seq 1 ${num}); do
			indent="${indent}  "
		done
		echolog_date "${indent}- ${content}"
	else
		echolog_date "${content}"
	fi
}

log_i18n() {
	local num="$1"
	shift
	log ${num} "$(i18n "$@")"
}

clean_log() {
	logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 1000 ] && {
		echo "" > $LOG_FILE
		log_i18n 0 "Log file is too long, clear it!"
	}
}

lua_api() {
	local func=${1}
	[ -z "${func}" ] && {
		echo ""
		return
	}
	echo $(lua -e "local api = require 'luci.passwall2.api' print(api.${func})")
}

check_host() {
	local f=${1}
	a=$(echo $f | grep "\/")
	[ -n "$a" ] && return 1
	# Determine if it contains Chinese characters.
	local tmp=$(echo -n $f | awk '{print gensub(/[!-~]/,"","g",$0)}')
	[ -n "$tmp" ] && return 1
	return 0
}

first_type() {
	[ "${1#/}" != "$1" ] && [ -x "$1" ] && echo "$1" && return
	for p in "/bin/$1" "/usr/bin/$1" "${TMP_BIN_PATH:-/tmp}/$1"; do
		[ -x "$p" ] && echo "$p" && return
	done
	command -v "$1" 2>/dev/null || command -v "$2" 2>/dev/null
}

get_enabled_anonymous_secs() {
	uci -q show "${CONFIG}" | grep "${1}\[.*\.enabled='1'" | cut -d '.' -sf2
}

get_geoip() {
	local geo_output_path="$TMP_PATH2/geo_output"
	mkdir -p ${geo_output_path}
	local geoip_code="$1"
	local geoip_type_flag=""
	local output_path="${geo_output_path}/geoip-${geoip_code}-$2"
	[ ! -s "${output_path}" ] && {
		local geoip_path="$(config_n_get @global_rules[0] v2ray_location_asset)"
		geoip_path="${geoip_path%*/}/geoip.dat"
		local bin="$(first_type $(config_n_get @global_app[0] geoview_file) geoview)"
		[ -n "$bin" ] && [ -s "$geoip_path" ] || { echo ""; return; }
		case "$2" in
			"ipv4") geoip_type_flag="-ipv6=false" ;;
			"ipv6") geoip_type_flag="-ipv4=false" ;;
		esac
		"$bin" -input "$geoip_path" -list "$geoip_code" $geoip_type_flag -lowmem=true -output ${output_path}
	}
	[ -s "${output_path}" ] && cat "${output_path}"
}

get_host_ip() {
	local host=$2
	local count=$3
	[ -z "$count" ] && count=3
	local isip=""
	local ip=""
	if [ "$1" == "ipv6" ]; then
		isip=$(echo $host | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		if [ -n "$isip" ]; then
			ip=$(echo "$host" | tr -d '[]')
		fi
	else
		isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
		[ -n "$isip" ] && ip=$isip
	fi
	[ -z "$isip" ] && {
		local t=4
		[ "$1" == "ipv6" ] && t=6
		local vpsrip=$(resolveip -$t -t $count $host | awk 'NR==1{print}')
		ip=$vpsrip
	}
	[ -n "$ip" ] && echo "$ip"
}

get_node_host_ip() {
	local ip
	local address=$(config_n_get $1 address)
	[ -n "$address" ] && {
		local use_ipv6=$(config_n_get $1 use_ipv6)
		local network_type="ipv4"
		[ "$use_ipv6" == "1" ] && network_type="ipv6"
		ip=$(get_host_ip $network_type $address)
	}
	echo $ip
}

get_ip_port_from() {
	local __host=${1}; shift 1
	local __ipv=${1}; shift 1
	local __portv=${1}; shift 1
	local __ucipriority=${1}; shift 1

	local val1 val2
	if [ -n "${__ucipriority}" ]; then
		val2=$(config_n_get ${__host} port $(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p'))
		val1=$(config_n_get ${__host} address "${__host%%${val2:+[:#]${val2}*}}")
	else
		val2=$(echo $__host | sed -n 's/^.*[:#]\([0-9]*\)$/\1/p')
		val1="${__host%%${val2:+[:#]${val2}*}}"
	fi
	eval "${__ipv}=\"$val1\"; ${__portv}=\"$val2\""
}

host_from_url(){
	local f=${1}

	## Remove protocol part of url  ##
	f="${f##http://}"
	f="${f##https://}"
	f="${f##ftp://}"
	f="${f##sftp://}"

	## Remove username and/or username:password part of URL  ##
	f="${f##*:*@}"
	f="${f##*@}"

	## Remove rest of urls ##
	f="${f%%/*}"
	echo "${f%%:*}"
}

hosts_foreach() {
	local __hosts
	eval "__hosts=\$${1}"; shift 1
	local __func=${1}; shift 1
	local __default_port=${1}; shift 1
	local __ret=1

	[ -z "${__hosts}" ] && return 0
	local __ip __port
	for __host in $(echo $__hosts | sed 's/[ ,]/\n/g'); do
		get_ip_port_from "$__host" "__ip" "__port"
		eval "$__func \"${__host}\" \"\${__ip}\" \"\${__port:-${__default_port}}\" \"$@\""
		__ret=$?
		[ ${__ret} -ge ${ERROR_NO_CATCH:-1} ] && return ${__ret}
	done
}

check_port_exists() {
	local port=$1
	local protocol=$2
	[ -n "$protocol" ] || protocol="tcp,udp"
	local result=
	if [ "$protocol" = "tcp" ]; then
		result=$(netstat -tln | grep -c ":$port ")
	elif [ "$protocol" = "udp" ]; then
		result=$(netstat -uln | grep -c ":$port ")
	elif [ "$protocol" = "tcp,udp" ]; then
		result=$(netstat -tuln | grep -c ":$port ")
	fi
	echo "${result}"
}

get_new_port() {
	local default_start_port=2001
	local min_port=1025
	local max_port=49151
	local port=$1 #Required parameter; please pass "auto" if you want it to be automatic.
	local last_get_new_port_auto
	if [ "$1" == "auto" ]; then
		last_get_new_port_auto=$(get_cache_var "last_get_new_port_auto")
		if [ -n "$last_get_new_port_auto" ]; then
			port=$last_get_new_port_auto
			port=$(expr $port + 1)
		else
			port=$default_start_port
		fi
	fi
	[ "$port" -lt $min_port -o "$port" -gt $max_port ] && port=$default_start_port
	local protocol=$(echo $2 | tr 'A-Z' 'a-z')
	local result=$(check_port_exists $port $protocol)
	[ -n "$(get_cache_var "get_port_${port}")" ] && {
		# exist, continue get.
		# Make the following result logic true.
		result=1
	}
	if [ "$result" != 0 ]; then
		local temp=
		if [ "$port" -lt $max_port ]; then
			# If the port is smaller than the maximum port, then increment by 1 and continue.
			temp=$(expr $port + 1)
		elif [ "$port" -gt $min_port ]; then
			# If the port is greater than the minimum port, then decrement by 1 and continue.
			temp=$(expr $port - 1)
		else
			# Otherwise, reassign the default starting port.
			temp=$default_start_port
		fi
		# Recursion, until it obtains an unused port.
		get_new_port $temp $protocol
	else
		# Set cache, mark this port as already obtained, so it should not be obtained again.
		set_cache_var "get_port_${port}" "1"
		[ "$1" == "auto" ] && set_cache_var "last_get_new_port_auto" "$port"
		echo $port
	fi
}

has_1_65535() {
	local val="$1"
	val=${val//:/-}
	case ",$val," in
		*,1-65535,*) return 0 ;;
		*) return 1 ;;
	esac
}

add_ip2route() {
	local ip=$(get_host_ip "ipv4" $1)
	[ -z "$ip" ] && {
		log 1 "$(i18n "Unable to resolve [%s], route table addition failed!" "${1}")"
		return 1
	}
	local remarks="${1}"
	[ "$remarks" != "$ip" ] && remarks="${1}(${ip})"

	local gateway device
	network_get_gateway gateway "$2"
	network_get_device device "$2"
	[ -z "${device}" ] && device=$(ubus call "network.interface.$2" status 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null)
	[ -z "${device}" ] && [ -d "/sys/class/net/$2" ] && device="$2"
	[ -z "${device}" ] && device="$2"

	if [ -n "${gateway}" ]; then
		route add -host ${ip} gw ${gateway} dev ${device} >/dev/null 2>&1
		echo "$ip" >> $TMP_ROUTE_PATH/${device}
		log 1 "$(i18n "[%s] was successfully added to the routing table of interface [%s]!" "${remarks}" "${device}")"
	else
		log 1 "$(i18n "Adding [%s] to the [%s] routing table failed! The reason is that the [%s] gateway cannot be found." "${remarks}" "${device}" "${device}")"
	fi
}

delete_ip2route() {
	[ -d "${TMP_ROUTE_PATH}" ] && {
		for interface in $(ls ${TMP_ROUTE_PATH}); do
			for ip in $(cat ${TMP_ROUTE_PATH}/${interface}); do
				route del -host ${ip} dev ${interface} >/dev/null 2>&1
			done
		done
	}
}

ln_run() {
	local queue_run=${1}
	local file_func=${2}
	local ln_name=${3}
	local output=${4}
	shift 4;

	if [  "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || log 1 "$(i18n "%s does not have execute permissions and cannot be started: %s %s" "$(readlink ${file_func})" "${file_func}" "$*")"
	fi
	#echo "${file_func} $*" >&2
	[ -n "${file_func}" ] || {
		log 1 "$(i18n "%s not found, unable to start..." "${ln_name}")"
		return 1
	}

	[ "${queue_run}" == "1" ] && {
		mkdir -p $TMP_PROCESS_LIST_PATH
		process_count=$(ls $TMP_PROCESS_LIST_PATH | grep -v "^_" | wc -l)
		process_count=$((process_count + 1))
		echo "${file_func:-log 1 "${ln_name}"} $@ >${output}" > $TMP_PROCESS_LIST_PATH/$process_count
		return
	}

	${file_func:-log 1 "${ln_name}"} "$@" >${output} 2>&1 &

	[ -n "$NO_REC_PROCESS" ] && return

	process_count=$(ls $TMP_SCRIPT_FUNC_PATH | grep -v "^_" | wc -l)
	process_count=$((process_count + 1))
	echo "${file_func:-log 1 "${ln_name}"} $@ >${output}" > $TMP_SCRIPT_FUNC_PATH/$process_count
}

run_process_queue() {
	[ -d ${TMP_PROCESS_LIST_PATH} ] && {
		mkdir -p ${TMP_SCRIPT_FUNC_PATH}
		for filename in $(ls ${TMP_PROCESS_LIST_PATH}); do
			cmd=$(cat ${TMP_PROCESS_LIST_PATH}/${filename})
			cmd_check=$(echo $cmd | awk -F '>' '{print $1}')
			icount=$(busybox pgrep -f "$(echo $cmd_check)" | wc -l)
			if [ $icount = 0 ]; then
				eval $(echo "nohup ${cmd} 2>&1 &") >/dev/null 2>&1 &
			fi
			mv -f ${TMP_PROCESS_LIST_PATH}/${filename} ${TMP_SCRIPT_FUNC_PATH}/queued_${filename}
		done
	}
	rm -rf ${TMP_PROCESS_LIST_PATH}
}

kill_all() {
	kill -9 $(pidof "$@") >/dev/null 2>&1
}

get_wan_ips() {
	local family="$1"
	local NET_ADDR
	local iface
	local INTERFACES=$(ubus call network.interface dump | jsonfilter -e \
			'@.interface[!(@.interface ~ /lan/) && !(@.l3_device ~ /\./) && @.route[0]].interface')
	for iface in $INTERFACES; do
		local addr
		if [ "$family" = "ip6" ]; then
			network_get_ipaddr6 addr "$iface"
			case "$addr" in
				""|fe80*) continue ;;
			esac
		else
			network_get_ipaddr addr "$iface"
			case "$addr" in
				""|"0.0.0.0") continue ;;
			esac
		fi
		case " $NET_ADDR " in
			*" $addr "*) ;;
			*) NET_ADDR="${NET_ADDR:+$NET_ADDR }$addr" ;;
		esac
	done
	echo "$NET_ADDR"
}

get_local_ips() {
	local family="$1"
	local ALL_IPS WAN_IPS ip NET_ADDR
	if [ "$family" = "ip6" ]; then
		ALL_IPS=$(ip -o -6 addr show scope global | awk '{print $4}' | cut -d/ -f1)
		WAN_IPS=$(get_wan_ips ip6)
	else
		ALL_IPS=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1)
		WAN_IPS=$(get_wan_ips ip4)
	fi
	# Supplementary loop (not included in scope global)
	[ "$family" = "ip6" ] && ALL_IPS="$ALL_IPS ::1"
	[ "$family" != "ip6" ] && ALL_IPS="$ALL_IPS 127.0.0.1"
	for ip in $ALL_IPS; do
		case "$ip" in
			""|0.0.0.0|::) continue ;;
		esac
		case " $WAN_IPS " in
			*" $ip "*) continue ;;
		esac
		case " $NET_ADDR " in
			*" $ip "*) ;;
			*) NET_ADDR="${NET_ADDR:+$NET_ADDR }$ip" ;;
		esac
	done
	for ip in $NET_ADDR; do
		echo "$ip"
	done
}
