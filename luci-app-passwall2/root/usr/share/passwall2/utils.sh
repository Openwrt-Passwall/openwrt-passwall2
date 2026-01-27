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

config_t_set() {
	local index=${4:-0}
	local ret=$(uci -q set "${CONFIG}.@${1}[${index}].${2}=${3}" 2>/dev/null)
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
			eval unset j
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
	local geoip_code="$1"
	local geoip_type_flag=""
	local geoip_path="$(config_t_get global_rules v2ray_location_asset)"
	geoip_path="${geoip_path%*/}/geoip.dat"
	[ -e "$geoip_path" ] || { echo ""; return; }
	case "$2" in
		"ipv4") geoip_type_flag="-ipv6=false" ;;
		"ipv6") geoip_type_flag="-ipv4=false" ;;
	esac
	if type geoview &> /dev/null; then
		geoview -input "$geoip_path" -list "$geoip_code" $geoip_type_flag -lowmem=true
	else
		echo ""
	fi
}

get_host_ip() {
	local host=$2
	local count=$3
	[ -z "$count" ] && count=3
	local isip=""
	local ip=$host
	if [ "$1" == "ipv6" ]; then
		isip=$(echo $host | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
		if [ -n "$isip" ]; then
			isip=$(echo $host | cut -d '[' -f2 | cut -d ']' -f1)
		else
			isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
		fi
	else
		isip=$(echo $host | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
	fi
	[ -z "$isip" ] && {
		local t=4
		[ "$1" == "ipv6" ] && t=6
		local vpsrip=$(resolveip -$t -t $count $host | awk 'NR==1{print}')
		ip=$vpsrip
	}
	echo $ip
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

get_first_dns() {
	local __hosts_val=${1}; shift 1
	__first() {
		[ -z "${2}" ] && return 0
		echo "${2}#${3}"
		return 1
	}
	eval "hosts_foreach \"${__hosts_val}\" __first \"$@\""
}

get_last_dns() {
	local __hosts_val=${1}; shift 1
	local __first __last
	__every() {
		[ -z "${2}" ] && return 0
		__last="${2}#${3}"
		__first=${__first:-${__last}}
	}
	eval "hosts_foreach \"${__hosts_val}\" __every \"$@\""
	[ "${__first}" ==  "${__last}" ] || echo "${__last}"
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
	local default_start_port=2000
	local min_port=1025
	local max_port=49151
	local port=$1
	[ "$port" == "auto" ] && port=$default_start_port
	[ "$port" -lt $min_port -o "$port" -gt $max_port ] && port=$default_start_port
	local protocol=$(echo $2 | tr 'A-Z' 'a-z')
	local result=$(check_port_exists $port $protocol)
	if [ "$result" != 0 ]; then
		local temp=
		if [ "$port" -lt $max_port ]; then
			temp=$(expr $port + 1)
		elif [ "$port" -gt $min_port ]; then
			temp=$(expr $port - 1)
		else
			temp=$default_start_port
		fi
		get_new_port $temp $protocol
	else
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

	. /lib/functions/network.sh
	local gateway device
	network_get_gateway gateway "$2"
	network_get_device device "$2"
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
	local file_func=${1}
	local ln_name=${2}
	local output=${3}

	shift 3;
	if [  "${file_func%%/*}" != "${file_func}" ]; then
		[ ! -L "${file_func}" ] && {
			ln -s "${file_func}" "${TMP_BIN_PATH}/${ln_name}" >/dev/null 2>&1
			file_func="${TMP_BIN_PATH}/${ln_name}"
		}
		[ -x "${file_func}" ] || log 1 "$(i18n "%s does not have execute permissions and cannot be started: %s %s" "$(readlink ${file_func})" "${file_func}" "$*")"
	fi
	#echo "${file_func} $*" >&2
	[ -n "${file_func}" ] || log 1 "$(i18n "%s not found, unable to start..." "${ln_name}")"
	${file_func:-log 1 "${ln_name}"} "$@" >${output} 2>&1 &

	local pid=${!}
	#sleep 1s
	#kill -0 ${pid} 2>/dev/null
	#local status_code=${?}
	process_count=$(ls $TMP_SCRIPT_FUNC_PATH | grep -v "^_" | wc -l)
	process_count=$((process_count + 1))
	echo "${file_func:-log 1 "${ln_name}"} $@ >${output}" > $TMP_SCRIPT_FUNC_PATH/$process_count
	#return ${status_code}
}

kill_all() {
	kill -9 $(pidof "$@") >/dev/null 2>&1
}
