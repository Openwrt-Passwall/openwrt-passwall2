#!/bin/sh
# Copyright (C) 2022-2025 xiaorouji
# Copyright (C) 2026 Openwrt-Passwall Organization

. /lib/functions.sh
. /lib/functions/service.sh
. /usr/share/libubox/jshn.sh

. /usr/share/passwall2/utils.sh
LUA_UTIL_PATH=/usr/lib/lua/luci/passwall2
UTIL_SINGBOX=$LUA_UTIL_PATH/util_sing-box.lua
UTIL_SS=$LUA_UTIL_PATH/util_shadowsocks.lua
UTIL_XRAY=$LUA_UTIL_PATH/util_xray.lua
SINGBOX_BIN=$(first_type $(config_n_get @global_app[0] sing_box_file) sing-box)
XRAY_BIN=$(first_type $(config_n_get @global_app[0] xray_file) xray)

check_run_environment() {
	local prefer_nft=$(config_n_get @global_forwarding[0] prefer_nft 1)
	local dnsmasq_info=$(dnsmasq -v 2>/dev/null)
	local dnsmasq_ver=$(echo "$dnsmasq_info" | sed -n '1s/.*version \([0-9.]*\).*/\1/p')
	# local dnsmasq_opts=$(echo "$dnsmasq_info" | grep -i "Compile time options")
	local dnsmasq_ipset=0; echo "$dnsmasq_info" | grep -qw "ipset" && dnsmasq_ipset=1
	local dnsmasq_nftset=0; echo "$dnsmasq_info" | grep -qw "nftset" && dnsmasq_nftset=1
	local has_ipt=0; { command -v iptables-legacy || command -v iptables; } >/dev/null && has_ipt=1
	local has_ipset=$(command -v ipset >/dev/null && echo 1 || echo 0)
	local has_fw4=$(command -v fw4 >/dev/null && echo 1 || echo 0)
	if [ "$prefer_nft" = "1" ]; then
		if [ "$dnsmasq_nftset" -eq 1 ] && [ "$has_fw4" -eq 1 ]; then
			USE_TABLES="nftables"
		elif [ "$has_ipset" -eq 1 ] && [ "$has_ipt" -eq 1 ] && [ "$dnsmasq_ipset" -eq 1 ]; then
			log_i18n 0 "Warning: The %s application environment is incomplete. Switch to %s. (%s)" "nftables (fw4)" "iptables" "has_fw4:$has_fw4/dnsmasq_nftset:$dnsmasq_nftset"
			USE_TABLES="iptables"
		fi
	else
		if [ "$has_ipset" -eq 1 ] && [ "$has_ipt" -eq 1 ] && [ "$dnsmasq_ipset" -eq 1 ]; then
			USE_TABLES="iptables"
		elif [ "$dnsmasq_nftset" -eq 1 ] && [ "$has_fw4" -eq 1 ]; then
			log_i18n 0 "Warning: The %s application environment is incomplete. Switch to %s. (%s)" "iptables (fw3)" "nftables" "has_ipt:$has_ipt/has_ipset:$has_ipset/dnsmasq_ipset:$dnsmasq_ipset"
			USE_TABLES="nftables"
		fi
	fi

	if [ -n "$USE_TABLES" ]; then
		local dep_list
		local file_path="/usr/lib/opkg/info"
		local file_ext=".control"
		[ -d "/lib/apk/packages" ] && { file_path="/lib/apk/packages"; file_ext=".list"; }

		if [ "$USE_TABLES" = "iptables" ]; then
			dep_list="iptables-mod-tproxy iptables-mod-socket iptables-mod-iprange iptables-mod-conntrack-extra kmod-ipt-nat"
		else
			dep_list="kmod-nft-socket kmod-nft-tproxy kmod-nft-nat"
			nftflag=1
			local v_num=$(echo "$dnsmasq_ver" | tr -cd '0-9')
			if [ "${v_num:-0}" -lt 290 ]; then
				log_i18n 0 "Note: Dnsmasq (%s) is below 2.90. Upgrading is recommended to improve stability." "${dnsmasq_ver}"
			fi
		fi
		local pkg
		for pkg in $dep_list; do
			if [ ! -s "${file_path}/${pkg}${file_ext}" ]; then
				log_i18n 0 "Warning: %s transparent proxy is missing basic dependency %s!" "${USE_TABLES}" "${pkg}"
			fi
		done
	else
		log 0 "$(i18n "Warning: Not compatible with any transparent proxy system environment.") (has_fw4:$has_fw4/has_ipt:$has_ipt/has_ipset:$has_ipset/dnsmasq_nftset:$dnsmasq_nftset/dnsmasq_ipset:$dnsmasq_ipset)"
	fi
}

run_xray() {
	local flag node redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_query_strategy remote_dns_protocol remote_dns_udp_server remote_dns_udp_port remote_dns_tcp_server remote_dns_tcp_port remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy dns_cache
	local loglevel log_file config_file
	eval_set_val $@
	node_protocol=$(config_n_get $node protocol)
	[ -n "$log_file" ] || local log_file="/dev/null"
	[ -z "$loglevel" ] && local loglevel=$(config_n_get @global[0] loglevel "warning")

	json_init
	json_add_string "loglevel" "${loglevel}"

	[ -n "$flag" ] && {
		busybox pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1{print $1}' | xargs kill -9 >/dev/null 2>&1
		json_add_string "flag" "${flag}"
	}
	[ -n "$socks_address" ] && [ -n "$socks_port" ] && {
		json_add_string "local_socks_address" "${socks_address}"
		json_add_string "local_socks_port" "${socks_port}"
		[ -n "$socks_username" ] && [ -n "$socks_password" ] && {
			json_add_string "local_socks_username" "${socks_username}"
			json_add_string "local_socks_password" "${socks_password}"
		}
	}
	[ -n "$http_address" ] && [ -n "$http_port" ] && {
		json_add_string "local_http_address" "${http_address}"
		json_add_string "local_http_port" "${http_port}"
		[ -n "$http_username" ] && [ -n "$http_password" ] && {
			json_add_string "local_http_username" "${http_username}"
			json_add_string "local_http_password" "${http_password}"
		}
	}
	local direct_dns_proto=${DIRECT_DNS_PROTO}
	local direct_dns_server=${DIRECT_DNS_SERVER}
	local direct_dns_port=${DIRECT_DNS_PORT}
	[ -n "$dns_listen_port" ] && {
		local dns_msg="DNS[${dns_listen_port}]:($(i18n "Direct DNS: %s" "${direct_dns_proto}://${direct_dns_server}:${direct_dns_port}")"
		json_add_string "dns_listen_port" "${dns_listen_port}"
		[ -n "$dns_cache" ] && json_add_string "dns_cache" "${dns_cache}"
		[ "${node_protocol}" = "_shunt" ] && local write_ipset_direct=$(config_n_get $node write_ipset_direct 0)
		[ "${write_ipset_direct}" = "1" ] && {
			direct_dnsmasq_listen_port=$(get_new_port auto)
			local direct_ipset_conf=${TMP_ACL_PATH}/dns_${flag}_direct.conf
			if [ "${nftflag}" = "1" ]; then
				local direct_nftset4="psw2_${node}_white"
				local direct_nftset6="psw2_${node}_white6"
				local direct_nftset="4#inet#passwall2#${direct_nftset4},6#inet#passwall2#${direct_nftset6}"
			else
				local direct_ipset4="psw2_${node}_white"
				local direct_ipset6="psw2_${node}_white6"
				local direct_ipset="${direct_ipset4},${direct_ipset6}"
			fi
			run_ipset_dns_server listen_port=${direct_dnsmasq_listen_port} proto=${direct_dns_proto} server_dns="${direct_dns_server}#${direct_dns_port}" ipset="${direct_ipset}" nftset="${direct_nftset}" config_file=${direct_ipset_conf}
			direct_dns_proto="udp"
			direct_dns_server="127.0.0.1"
			direct_dns_port=${direct_dnsmasq_listen_port}
			[ -n "${direct_ipset}" ] && {
				json_add_string "direct_ipset" "${direct_ipset}"
				set_cache_var "node_${node}_direct_ipset4" "${direct_ipset4}"
				set_cache_var "node_${node}_direct_ipset6" "${direct_ipset6}"
			}
			[ -n "${direct_nftset}" ] && {
				json_add_string "direct_nftset" "${direct_nftset}"
				set_cache_var "node_${node}_direct_nftset4" "${direct_nftset4}"
				set_cache_var "node_${node}_direct_nftset6" "${direct_nftset6}"
			}
		}
		case "$remote_dns_protocol" in
			udp)
				json_add_string "remote_dns_udp_server" "${remote_dns_udp_server}"
				json_add_string "remote_dns_udp_port" "${remote_dns_udp_port}"
				dns_msg="${dns_msg} $(i18n "Remote DNS: %s" "udp://${remote_dns_udp_server}:${remote_dns_udp_port}")"
			;;
			tcp)
				json_add_string "remote_dns_tcp_server" "${remote_dns_tcp_server}"
				json_add_string "remote_dns_tcp_port" "${remote_dns_tcp_port}"
				dns_msg="${dns_msg} $(i18n "Remote DNS: %s" "tcp://${remote_dns_tcp_server}:${remote_dns_tcp_port}")"
			;;
			doh)
				local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
				local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
				#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
				local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
				local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
				local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
				[ -z "${_doh_port}" ] && _doh_port=443
				local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
				[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
				json_add_string "remote_dns_doh_port" "${_doh_port}"
				json_add_string "remote_dns_doh_url" "${_doh_url}"
				json_add_string "remote_dns_doh_host" "${_doh_host}"
				[ -n "$_doh_bootstrap" ] && json_add_string "remote_dns_doh_ip" "${_doh_bootstrap}"
				dns_msg="${dns_msg} $(i18n "Remote DNS: %s" "${_doh_url}")"
			;;
		esac
		[ "$remote_fakedns" = "1" ] && {
			json_add_string "remote_dns_fake" "1"
			json_add_string "remote_dns_fake_strategy" "${remote_dns_query_strategy}"
			dns_msg="${dns_msg} + FakeDNS "
		}
		[ -n "$remote_dns_detour" ] && json_add_string "remote_dns_detour" "${remote_dns_detour}"
		[ -n "$remote_dns_query_strategy" ] && json_add_string "remote_dns_query_strategy" "${remote_dns_query_strategy}"
		[ -n "$remote_dns_client_ip" ] && json_add_string "remote_dns_client_ip" "${remote_dns_client_ip}"
		log_out="${dns_msg})"
	}
	json_add_string "direct_dns_${direct_dns_proto}_server" "${direct_dns_server}"
	json_add_string "direct_dns_${direct_dns_proto}_port" "${direct_dns_port}"
	json_add_string "direct_dns_query_strategy" "${direct_dns_query_strategy}"

	[ -n "${redir_port}" ] && {
		json_add_string "redir_port" "${redir_port}"
		set_cache_var "node_${node}_redir_port" "${redir_port}"
		json_add_string "tcp_proxy_way" "${TCP_PROXY_WAY}"
		[ -n "${log_out}" ] && log_out="Xray[${redir_port}] ${log_out}"
	}

	json_add_string "node" "${node}"

	local _json_arg="$(json_dump)"
	lua $UTIL_XRAY gen_config "${_json_arg}" > $config_file

	test_log_file=$log_file
	[ "$test_log_file" = "/dev/null" ] && test_log_file="${TMP_PATH}/test.log"

	$XRAY_BIN run -test -c "$config_file" > $test_log_file; local status=$?
	if [ "${status}" == 0 ]; then
		ln_run ${QUEUE_RUN} "$XRAY_BIN" xray $log_file run -c "$config_file"
		[ -n "${log_out}" ] && log 2 ${log_out}
		unset log_out
	else
		_error_log_file=$test_log_file
		return ${status}
	fi
}

run_singbox() {
	local flag node redir_port socks_address socks_port socks_username socks_password http_address http_port http_username http_password
	local dns_listen_port direct_dns_query_strategy remote_dns_protocol remote_dns_udp_server remote_dns_udp_port remote_dns_tcp_server remote_dns_tcp_port remote_dns_doh remote_dns_client_ip remote_dns_detour remote_fakedns remote_dns_query_strategy remote_rewrite_ttl dns_cache
	local loglevel log_file config_file
	eval_set_val $@
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	[ -z "$type" ] && return 1
	node_protocol=$(config_n_get $node protocol)
	[ -n "$log_file" ] || local log_file="/dev/null"
	[ -z "$loglevel" ] && local loglevel=$(config_n_get @global[0] loglevel "warn")
	local singbox_tag=$($SINGBOX_BIN version | grep 'Tags:' | awk '{print $2}')

	json_init
	json_add_string "tags" "${singbox_tag}"

	if [ "$log_file" = "/dev/null" ]; then
		json_add_string "log" "0"
	else
		json_add_string "log" "1"
		json_add_string "logfile" "${log_file}"
	fi
	json_add_string "loglevel" "${loglevel}"

	[ -n "$flag" ] && {
		busybox pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1{print $1}' | xargs kill -9 >/dev/null 2>&1
		json_add_string "flag" "${flag}"
	}
	[ -n "$socks_address" ] && [ -n "$socks_port" ] && {
		json_add_string "local_socks_address" "${socks_address}"
		json_add_string "local_socks_port" "${socks_port}"
		[ -n "$socks_username" ] && [ -n "$socks_password" ] && {
			json_add_string "local_socks_username" "${socks_username}"
			json_add_string "local_socks_password" "${socks_password}"
		}
	}
	[ -n "$http_address" ] && [ -n "$http_port" ] && {
		json_add_string "local_http_address" "${http_address}"
		json_add_string "local_http_port" "${http_port}"
		[ -n "$http_username" ] && [ -n "$http_password" ] && {
			json_add_string "local_http_username" "${http_username}"
			json_add_string "local_http_password" "${http_password}"
		}
	}
	local direct_dns_proto=${DIRECT_DNS_PROTO}
	local direct_dns_server=${DIRECT_DNS_SERVER}
	local direct_dns_port=${DIRECT_DNS_PORT}
	[ -n "$dns_listen_port" ] && {
		local dns_msg="DNS[${dns_listen_port}]:($(i18n "Direct DNS: %s" "${direct_dns_proto}://${direct_dns_server}:${direct_dns_port}")"
		json_add_string "dns_listen_port" "${dns_listen_port}"
		[ -n "$dns_cache" ] && json_add_string "dns_cache" "${dns_cache}"
		[ "${node_protocol}" = "_shunt" ] && local write_ipset_direct=$(config_n_get $node write_ipset_direct 0)
		[ "${write_ipset_direct}" = "1" ] && {
			direct_dnsmasq_listen_port=$(get_new_port auto)
			local direct_ipset_conf=${TMP_ACL_PATH}/dns_${flag}_direct.conf
			if [ "${nftflag}" = "1" ]; then
				local direct_nftset4="psw2_${node}_white"
				local direct_nftset6="psw2_${node}_white6"
				local direct_nftset="4#inet#passwall2#${direct_nftset4},6#inet#passwall2#${direct_nftset6}"
			else
				local direct_ipset4="psw2_${node}_white"
				local direct_ipset6="psw2_${node}_white6"
				local direct_ipset="${direct_ipset4},${direct_ipset6}"
			fi
			run_ipset_dns_server listen_port=${direct_dnsmasq_listen_port} proto=${direct_dns_proto} server_dns="${direct_dns_server}#${direct_dns_port}" ipset="${direct_ipset}" nftset="${direct_nftset}" config_file=${direct_ipset_conf}
			direct_dns_proto="udp"
			direct_dns_server="127.0.0.1"
			direct_dns_port=${direct_dnsmasq_listen_port}
			[ -n "${direct_ipset}" ] && {
				json_add_string "direct_ipset" "${direct_ipset}"
				set_cache_var "node_${node}_direct_ipset4" "${direct_ipset4}"
				set_cache_var "node_${node}_direct_ipset6" "${direct_ipset6}"
			}
			[ -n "${direct_nftset}" ] && {
				json_add_string "direct_nftset" "${direct_nftset}"
				set_cache_var "node_${node}_direct_nftset4" "${direct_nftset4}"
				set_cache_var "node_${node}_direct_nftset6" "${direct_nftset6}"
			}
		}

		case "$remote_dns_protocol" in
			udp|\
			quic)
				json_add_string "remote_dns_udp_server" "${remote_dns_udp_server}"
				json_add_string "remote_dns_udp_port" "${remote_dns_udp_port}"
				[ "$remote_dns_protocol" == "quic" ] && json_add_string "remote_dns_quic" "1"
				dns_msg="${dns_msg} $(i18n "Remote DNS: %s" "${remote_dns_protocol}://${remote_dns_udp_server}:${remote_dns_udp_port}")"
			;;
			tcp|\
			tls)
				json_add_string "remote_dns_tcp_server" "${remote_dns_tcp_server}"
				json_add_string "remote_dns_tcp_port" "${remote_dns_tcp_port}"
				[ "$remote_dns_protocol" == "tls" ] && json_add_string "remote_dns_tls" "1"
				dns_msg="${dns_msg} $(i18n "Remote DNS: %s" "${remote_dns_protocol}://${remote_dns_tcp_server}:${remote_dns_tcp_port}")"
			;;
			doh|\
			http3)
				local _doh_url=$(echo $remote_dns_doh | awk -F ',' '{print $1}')
				local _doh_host_port=$(lua_api "get_domain_from_url(\"${_doh_url}\")")
				#local _doh_host_port=$(echo $_doh_url | sed "s/https:\/\///g" | awk -F '/' '{print $1}')
				local _doh_host=$(echo $_doh_host_port | awk -F ':' '{print $1}')
				local is_ip=$(lua_api "is_ip(\"${_doh_host}\")")
				local _doh_port=$(echo $_doh_host_port | awk -F ':' '{print $2}')
				[ -z "${_doh_port}" ] && _doh_port=443
				local _doh_bootstrap=$(echo $remote_dns_doh | cut -d ',' -sf 2-)
				[ "${is_ip}" = "true" ] && _doh_bootstrap=${_doh_host}
				[ -n "$_doh_bootstrap" ] && json_add_string "remote_dns_doh_ip" "${_doh_bootstrap}"
				json_add_string "remote_dns_doh_port" "${_doh_port}"
				json_add_string "remote_dns_doh_url" "${_doh_url}"
				json_add_string "remote_dns_doh_host" "${_doh_host}"
				[ "$remote_dns_protocol" == "http3" ] && json_add_string "remote_dns_http3" "1"
				dns_msg="${dns_msg} $(i18n "Remote DNS: %s" "${_doh_url}")"
			;;
		esac
		[ "$remote_fakedns" = "1" ] && {
			json_add_string "remote_dns_fake" "1"
			dns_msg="${dns_msg} + FakeDNS "
		}

		[ -n "$remote_dns_detour" ] && json_add_string "remote_dns_detour" "${remote_dns_detour}"
		[ -n "$remote_dns_query_strategy" ] && json_add_string "remote_dns_query_strategy" "${remote_dns_query_strategy}"
		[ -n "$remote_dns_client_ip" ] && json_add_string "remote_dns_client_ip" "${remote_dns_client_ip}"
		[ -n "$remote_rewrite_ttl" ] && json_add_string "remote_rewrite_ttl" "${remote_rewrite_ttl}"
		log_out="${dns_msg})"
	}
	json_add_string "direct_dns_${direct_dns_proto}_server" "${direct_dns_server}"
	json_add_string "direct_dns_${direct_dns_proto}_port" "${direct_dns_port}"
	json_add_string "direct_dns_query_strategy" "${direct_dns_query_strategy}"

	[ -n "${redir_port}" ] && {
		json_add_string "redir_port" "${redir_port}"
		set_cache_var "node_${node}_redir_port" "${redir_port}"
		json_add_string "tcp_proxy_way" "${TCP_PROXY_WAY}"
		[ -n "${log_out}" ] && log_out="Sing-Box[${redir_port}] ${log_out}"
	}

	json_add_string "node" "${node}"

	local _json_arg="$(json_dump)"
	lua $UTIL_SINGBOX gen_config "${_json_arg}" > $config_file

	test_log_file=$log_file
	[ "$test_log_file" = "/dev/null" ] && test_log_file="${TMP_PATH}/test.log"

	$SINGBOX_BIN check -c "$config_file" > $test_log_file 2>&1; local status=$?
	if [ "${status}" == 0 ]; then
		ln_run ${QUEUE_RUN} "$SINGBOX_BIN" "sing-box" "${log_file}" run -c "$config_file"
		[ -n "${log_out}" ] && log 2 ${log_out}
		unset log_out
	else
		_error_log_file=$test_log_file
		return ${status}
	fi
}

run_socks() {
	local flag node bind socks_port config_file http_port http_config_file relay_port log_file no_run
	eval_set_val $@
	[ -n "$config_file" ] && [ -z "$(echo ${config_file} | grep $TMP_PATH)" ] && config_file=$TMP_PATH/$config_file
	[ -n "$http_port" ] || http_port=0
	[ -n "$http_config_file" ] && [ -z "$(echo ${http_config_file} | grep $TMP_PATH)" ] && http_config_file=$TMP_PATH/$http_config_file
	if [ -n "$log_file" ] && [ "$log_file" != "/dev/null" ] && [ -z "$(echo ${log_file} | grep $TMP_PATH)" ]; then
		log_file=$TMP_PATH/$log_file
	else
		log_file="/dev/null"
	fi
	local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
	local remarks=$(config_n_get $node remarks)
	local server_host=$(config_n_get $node address)
	local server_port=$(config_n_get $node port)
	[ -n "$relay_port" ] && {
		server_host="127.0.0.1"
		server_port=$relay_port
	}
	local error_msg tmp

	if [ -n "$server_host" ] && [ -n "$server_port" ]; then
		check_host $server_host
		[ $? != 0 ] && {
			log 1 "$(i18n "Socks node: [%s]%s is an invalid server address and cannot be started!" "${$remarks}" "${server_host}")"
			return 1
		}
		tmp="${server_host}:${server_port}"
	else
		error_msg="$(i18n "For some reason, the configuration for this Socks service has been lost, and its startup has been aborted!")"
	fi

	if [ "$type" == "sing-box" ] || [ "$type" == "xray" ]; then
		local protocol=$(config_n_get $node protocol)
		if [ "$protocol" == "_balancing" ] || [ "$protocol" == "_shunt" ] || [ "$protocol" == "_iface" ] || [ "$protocol" == "_urltest" ]; then
			unset error_msg
		fi
	fi

	if [ -n "${error_msg}" ] && ([ -n "$(config_n_get $node hysteria_hop)" ] || [ -n "$(config_n_get $node hysteria2_hop)" ] || [ "$(config_n_get $node hysteria2_realms)" = "1" ]); then
		unset error_msg
	fi

	[ -n "${error_msg}" ] && {
		[ "$bind" != "127.0.0.1" ] && log 1 "$(i18n "Socks node: [%s]%s, start failed %s:%s %s" "${remarks}" "${tmp}" "${bind}" "${socks_port}" "${error_msg}")"
		return 1
	}
	[ "$bind" != "127.0.0.1" ] && log 1 "$(i18n "Socks node: [%s]%s, starting %s:%s" "${remarks}" "${tmp}" "${bind}" "${socks_port}")"

	json_init
	json_add_string "node" "${node}"
	json_add_string "server_host" "${server_host}"
	json_add_string "server_port" "${server_port}"
	case "$type" in
	sing-box)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file%%.*}+http${config_file#${config_file%%.*}}"
			json_add_string "local_http_address" "${bind}"
			json_add_string "local_http_port" "${http_port}"
		}
		[ -z "$relay_port" ] && {
			json_add_null "server_host"
			json_add_null "server_port"
		}
		[ "${log_file}" != "/dev/null" ] && {
			local loglevel=$(config_n_get @global[0] loglevel "warn")
			json_add_string "log" "1"
			json_add_string "loglevel" "${loglevel}"
			json_add_string "logfile" "${log_file}"
		}
		[ -n "$no_run" ] && json_add_string "no_run" "1"
		json_add_string "flag" "${flag}"
		json_add_string "local_socks_address" "${bind}"
		json_add_string "local_socks_port" "${socks_port}"
		json_add_string "direct_dns_${DIRECT_DNS_PROTO}_server" "${DIRECT_DNS_SERVER}"
		json_add_string "direct_dns_${DIRECT_DNS_PROTO}_port" "${DIRECT_DNS_PORT}"
		json_add_string "direct_dns_query_strategy" "${DIRECT_DNS_QUERY_STRATEGY}"
		local _json_arg="$(json_dump)"
		lua $UTIL_SINGBOX gen_config "${_json_arg}" > $config_file
		[ -z "$no_run" ] && ln_run ${QUEUE_RUN} "$SINGBOX_BIN" "sing-box" /dev/null run -c "$config_file"
	;;
	xray)
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file%%.*}+http${config_file#${config_file%%.*}}"
			json_add_string "local_http_address" "${bind}"
			json_add_string "local_http_port" "${http_port}"
		}
		[ -z "$relay_port" ] && {
			json_add_null "server_host"
			json_add_null "server_port"
		}
		[ "${log_file}" != "/dev/null" ] && {
			local loglevel=$(config_n_get @global[0] loglevel "warn")
			json_add_string "log" "1"
			json_add_string "loglevel" "${loglevel}"
		}
		[ -n "$no_run" ] && json_add_string "no_run" "1"
		json_add_string "flag" "${flag}"
		json_add_string "local_socks_address" "${bind}"
		json_add_string "local_socks_port" "${socks_port}"
		json_add_string "direct_dns_${DIRECT_DNS_PROTO}_server" "${DIRECT_DNS_SERVER}"
		json_add_string "direct_dns_${DIRECT_DNS_PROTO}_port" "${DIRECT_DNS_PORT}"
		json_add_string "direct_dns_query_strategy" "${DIRECT_DNS_QUERY_STRATEGY}"
		local _json_arg="$(json_dump)"
		lua $UTIL_XRAY gen_config "${_json_arg}" > $config_file
		[ -z "$no_run" ] && ln_run ${QUEUE_RUN} "$XRAY_BIN" "xray" $log_file run -c "$config_file"
	;;
	ssr)
		json_add_string "local_addr" "${bind}"
		json_add_string "local_port" "${socks_port}"
		local _json_arg="$(json_dump)"
		lua $UTIL_SS gen_config "${_json_arg}" > $config_file
		[ -z "$no_run" ] && ln_run ${QUEUE_RUN} "$(first_type ssr-local)" "ssr-local" $log_file -c "$config_file" -v -u
	;;
	ss-rust)
		json_add_string "local_socks_address" "${bind}"
		json_add_string "local_socks_port" "${socks_port}"
		[ "$http_port" != "0" ] && {
			http_flag=1
			config_file="${config_file%%.*}+http${config_file#${config_file%%.*}}"
			json_add_string "local_http_address" "${bind}"
			json_add_string "local_http_port" "${http_port}"
		}
		[ -z "$no_run" ] && {
			local plugin_sh="${config_file%.json}_plugin.sh"
			json_add_string "plugin_sh" "${plugin_sh}"
		}
		local _json_arg="$(json_dump)"
		lua $UTIL_SS gen_config "${_json_arg}" > $config_file
		[ -z "$no_run" ] && ln_run ${QUEUE_RUN} "$(first_type sslocal)" "sslocal" $log_file -c "$config_file" -v
	;;
	esac

	# http to socks
	[ -z "$http_flag" ] && [ "$http_port" != "0" ] && [ -n "$http_config_file" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && [ "$type" != "socks" ] && {
		json_init
		json_add_string "local_http_port" "${http_port}"
		json_add_string "server_proto" "socks"
		json_add_string "server_address" "127.0.0.1"
		json_add_string "server_port" "${socks_port}"
		json_add_string "server_username" "${_username}"
		json_add_string "server_password" "${_password}"
		local _json_arg="$(json_dump)"
		if [ -n "${SINGBOX_BIN}" ]; then
			type="sing-box"
			local bin="${SINGBOX_BIN}"
			local util="${UTIL_SINGBOX}"
		elif [ -n "${XRAY_BIN}" ]; then
			type="xray"
			local bin="${XRAY_BIN}"
			local util="${UTIL_XRAY}"
		fi
		[ -n "${bin}" ] && [ -n "${util}" ] && {
			lua ${util} gen_proto_config "${_json_arg}" > ${http_config_file}
			[ -z "$no_run" ] && ln_run ${QUEUE_RUN} "${bin}" ${type} /dev/null run -c ${http_config_file}
		}
		unset bin util
	}
	unset http_flag

	[ -z "$no_run" ] && [ "${server_host}" != "127.0.0.1" ] && [ "$type" != "sing-box" ] && [ "$type" != "xray" ] && echo "${node}" >> $TMP_PATH/direct_node_list
}

socks_node_switch() {
	local flag new_node
	eval_set_val $@
	[ -n "$flag" ] && [ -n "$new_node" ] && {
		local suffix pf filename
		# Kill the SS plugin process
		for suffix in "" "+http"; do
			pf="$TMP_PATH/${flag}${suffix}_plugin.pid"
			[ -s "$pf" ] && kill -9 "$(head -n1 "$pf")" >/dev/null 2>&1
		done

		busybox pgrep -af "$TMP_BIN_PATH" | awk -v P1="${flag}" 'BEGIN{IGNORECASE=1}$0~P1 && !/acl\/|acl_/{print $1}' | xargs kill -9 >/dev/null 2>&1
		for suffix in "" "+http" "_http"; do
			rm -rf "$TMP_PATH/${flag}${suffix}"*
		done

		for filename in $(ls ${TMP_SCRIPT_FUNC_PATH}); do
			cmd=$(cat ${TMP_SCRIPT_FUNC_PATH}/${filename})
			[ -n "$(echo $cmd | grep "${flag}")" ] && rm -f ${TMP_SCRIPT_FUNC_PATH}/${filename}
		done
		local bind_local=$(config_n_get $flag bind_local 0)
		local bind="0.0.0.0"
		[ "$bind_local" = "1" ] && bind="127.0.0.1"
		local port=$(config_n_get $flag port)
		local config_file="${flag}.json"
		local log_file="${flag}.log"
		local log=$(config_n_get $flag log 1)
		[ "$log" == "0" ] && log_file=""
		local http_port=$(config_n_get $flag http_port 0)
		local http_config_file="${flag}_http.json"
		LOG_FILE="/dev/null"
		run_socks flag=$flag node=$new_node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file
		set_cache_var "${flag}" "$new_node"
		local USE_TABLES=$(get_cache_var "USE_TABLES")
		[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh filter_direct_node_list
	}
}

start_socks() {
	[ "$SOCKS_ENABLED" = "1" ] && {
		local ids=$(uci show $CONFIG | grep "=socks" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
		[ -n "$ids" ] && {
			log_i18n 0 "Analyzing the node configuration of the Socks service..."
			for id in $ids; do
				local enabled=$(config_n_get $id enabled 0)
				[ "$enabled" == "0" ] && continue
				local node=$(config_n_get $id node)
				[ -z "$node" ] && continue
				local bind_local=$(config_n_get $id bind_local 0)
				local bind="0.0.0.0"
				[ "$bind_local" = "1" ] && bind="127.0.0.1"
				local port=$(config_n_get $id port)
				local config_file="${id}.json"
				local log_file="${id}.log"
				local log=$(config_n_get $id log 1)
				[ "$log" == "0" ] && log_file=""
				local http_port=$(config_n_get $id http_port 0)
				local http_config_file="${id}_http.json"
				run_socks flag=$id node=$node bind=$bind socks_port=$port config_file=$config_file http_port=$http_port http_config_file=$http_config_file log_file=$log_file
				set_cache_var "${id}" "$node"

				# Auto switch logic
				local enable_autoswitch=$(config_n_get $id enable_autoswitch 0)
				[ "$enable_autoswitch" = "1" ] && { $APP_PATH/socks_auto_switch.sh ${id} > /dev/null 2>&1 & }
			done
		}
	}
}

clean_crontab() {
	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && return
	touch /etc/crontabs/root
	#sed -i "/${CONFIG}/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "/etc/init.d/${CONFIG}" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/rule_update.lua log" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1
	sed -i "/$(echo "lua ${APP_PATH}/subscribe.lua start" | sed 's#\/#\\\/#g')/d" /etc/crontabs/root >/dev/null 2>&1

	busybox pgrep -af "${CONFIG}/" | awk '/tasks\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
	rm -rf /tmp/lock/${CONFIG}_tasks.lock
}

start_crontab() {
	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		start_daemon=$(config_n_get @global_delay[0] start_daemon 0)
		[ "$start_daemon" = "1" ] && { $APP_PATH/monitor.sh > /dev/null 2>&1 & }
	fi

	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && {
		rm -rf "/tmp/lock/${CONFIG}_cron.lock"
		log_i18n 0 "The task is currently running automatically as a scheduled task; no reconfiguration of the scheduled task is required."
		return
	}

	clean_crontab

	[ "$ENABLED" != 1 ] && {
		/etc/init.d/cron restart
		return
	}

	stop_week_mode=$(config_n_get @global_delay[0] stop_week_mode)
	stop_time_mode=$(config_n_get @global_delay[0] stop_time_mode)
	if [ -n "$stop_week_mode" ]; then
		stop_time_hh=$(echo $stop_time_mode | awk -F ':' '{print $1}')
		stop_time_mm=$(echo $stop_time_mode | awk -F ':' '{print $2}')
		local t="$stop_time_mm $stop_time_hh * * $stop_week_mode"
		[ "$stop_week_mode" = "7" ] && t="$stop_time_mm $stop_time_hh * * *"
		echo "$t /etc/init.d/$CONFIG stop > /dev/null 2>&1 &" >>/etc/crontabs/root
		log_i18n 0 "Scheduled tasks: Auto stop service."
	fi

	start_week_mode=$(config_n_get @global_delay[0] start_week_mode)
	start_time_mode=$(config_n_get @global_delay[0] start_time_mode)
	if [ -n "$start_week_mode" ]; then
		start_time_hh=$(echo $start_time_mode | awk -F ':' '{print $1}')
		start_time_mm=$(echo $start_time_mode | awk -F ':' '{print $2}')
		local t="$start_time_mm $start_time_hh * * $start_week_mode"
		[ "$start_week_mode" = "7" ] && t="$start_time_mm $start_time_hh * * *"
		echo "$t /etc/init.d/$CONFIG start > /dev/null 2>&1 &" >>/etc/crontabs/root
		log_i18n 0 "Scheduled tasks: Auto start service."
	fi

	restart_week_mode=$(config_n_get @global_delay[0] restart_week_mode)
	restart_time_mode=$(config_n_get @global_delay[0] restart_time_mode)
	if [ -n "$restart_week_mode" ]; then
		restart_time_hh=$(echo $restart_time_mode | awk -F ':' '{print $1}')
		restart_time_mm=$(echo $restart_time_mode | awk -F ':' '{print $2}')
		local t="$restart_time_mm $restart_time_hh * * $restart_week_mode"
		[ "$restart_week_mode" = "7" ] && t="$restart_time_mm $restart_time_hh * * *"
		if [ "$restart_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t /etc/init.d/$CONFIG restart > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		log_i18n 0 "Scheduled tasks: Auto restart service."
	fi

	rules_update_week_mode=$(config_n_get @global_rules[0] update_week_mode)
	rules_update_time_mode=$(config_n_get @global_rules[0] update_time_mode)
	if [ -n "$rules_update_week_mode" ]; then
		rules_update_time_hh=$(echo $rules_update_time_mode | awk -F ':' '{print $1}')
		rules_update_time_mm=$(echo $rules_update_time_mode | awk -F ':' '{print $2}')
		local t="$rules_update_time_mm $rules_update_time_hh * * $rules_update_week_mode"
		[ "$rules_update_week_mode" = "7" ] && t="$rules_update_time_mm $rules_update_time_hh * * *"
		if [ "$rules_update_week_mode" = "8" ]; then
			update_loop=1
		else
			echo "$t lua $APP_PATH/rule_update.lua log all cron > /dev/null 2>&1 &" >>/etc/crontabs/root
		fi
		log_i18n 0 "Scheduled tasks: Auto update rules."
	fi

	TMP_SUB_PATH=$TMP_PATH/sub_crontabs
	mkdir -p $TMP_SUB_PATH
	for item in $(uci show ${CONFIG} | grep "=subscribe_list" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
		sub_update_week_mode=$(config_n_get $item update_week_mode)
		if [ -n "$sub_update_week_mode" ]; then
			remark=$(config_n_get $item remark)
			sub_update_time_mode=$(config_n_get $item update_time_mode)
			echo "$item" >> $TMP_SUB_PATH/${sub_update_week_mode}_${sub_update_time_mode}
			log_i18n 0 "Scheduled tasks: Auto update [%s] subscription." "${remark}"
		fi
	done

	[ -d "${TMP_SUB_PATH}" ] && {
		for name in $(ls ${TMP_SUB_PATH}); do
			cfgids=$(echo -n $(cat ${TMP_SUB_PATH}/${name}) | sed 's# #,#g')
			sub_update_week_mode=$(echo $name | awk -F '_' '{print $1}')
			sub_update_time_mode=$(echo $name | awk -F '_' '{print $2}')
			sub_update_time_hh=$(echo $sub_update_time_mode | awk -F ':' '{print $1}')
			sub_update_time_mm=$(echo $sub_update_time_mode | awk -F ':' '{print $2}')
			local t="$sub_update_time_mm $sub_update_time_hh * * $sub_update_week_mode"
			[ "$sub_update_week_mode" = "7" ] && t="$sub_update_time_mm $sub_update_time_hh * * *"
			if [ "$sub_update_week_mode" = "8" ]; then
				update_loop=1
			else
				echo "$t lua $APP_PATH/subscribe.lua start $cfgids cron > /dev/null 2>&1 &" >>/etc/crontabs/root
			fi
		done
		rm -rf $TMP_SUB_PATH
	}

	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		[ "$update_loop" = "1" ] && {
			$APP_PATH/tasks.sh > /dev/null 2>&1 &
			log_i18n 0 "Auto updates: Starts a cyclical update process."
		}
	else
		log_i18n 0 "Running in no proxy mode, it only allows scheduled tasks for starting and stopping services."
	fi

	/etc/init.d/cron restart
}

stop_crontab() {
	[ -f "/tmp/lock/${CONFIG}_cron.lock" ] && return
	clean_crontab
	/etc/init.d/cron restart
	#log_i18n 0 "Clear scheduled commands."
}

start_haproxy() {
	[ "$(config_n_get @global_haproxy[0] balancing_enable 0)" != "1" ] && return
	haproxy_path=$TMP_PATH/haproxy
	haproxy_conf="config.cfg"
	lua $APP_PATH/haproxy.lua -path ${haproxy_path} -conf ${haproxy_conf}
	ln_run 0 "$(first_type haproxy)" haproxy "/dev/null" -f "${haproxy_path}/${haproxy_conf}"
}

detect_adblock() {
	# Adblock is a global setting, it is not tied to any node.
	# Echo 1 only when a rule source is selected and the rule file is present.
	local __url
	__url=$(uci -q get "passwall2.@global_rules[0].enable_adblock")
	case "${__url}" in
		""|0|1)
			# Disabled: drop any stale rule file so dnsmasq can never load it again.
			rm -f "/usr/share/passwall2/adblock.conf"
			echo "0"
			;;
		*)
			[ -f "/usr/share/passwall2/adblock.conf" ] && echo "1" || echo "0"
			;;
	esac
}

run_copy_dnsmasq() {
	local flag listen_port local_dns tun_dns default_dns
	eval_set_val $@
	local dnsmasq_conf="${TMP_ACL_PATH}/${flag}_dnsmasq.conf"
	local dnsmasq_conf_path="${TMP_ACL_PATH}/${flag}_dnsmasq.d"
	local dnsmasq_pid="${TMP_ACL_PATH}/${flag}_dnsmasq.pid"
	mkdir -p $dnsmasq_conf_path

	json_init
	json_add_string "LISTEN_PORT" "${listen_port}"
	json_add_string "DNSMASQ_CONF" "${dnsmasq_conf}"
	lua $APP_PATH/helper_dnsmasq.lua copy_instance "$(json_dump)"

	json_init
	json_add_string "FLAG" "${flag}"
	json_add_string "TMP_DNSMASQ_PATH" "${dnsmasq_conf_path}"
	json_add_string "DNSMASQ_CONF_FILE" "${dnsmasq_conf}"
	json_add_string "DEFAULT_DNS" "${default_dns}"
	json_add_string "LOCAL_DNS" "${local_dns}"
	json_add_string "TUN_DNS" "${tun_dns}"
	json_add_string "NFTFLAG" "${nftflag:-0}"
	json_add_string "NO_LOGIC_LOG" "${NO_LOGIC_LOG:-0}"
	json_add_string "ADBLOCK" "$(detect_adblock)"
	lua $APP_PATH/helper_dnsmasq.lua add_rule "$(json_dump)"

	ln_run 0 "$(first_type dnsmasq)" "dnsmasq_${flag}" "/dev/null" -C ${dnsmasq_conf} -x ${dnsmasq_pid}
	set_cache_var "ACL_${flag}_dns_port" "${listen_port}"
}

run_ipset_dns_server() {
	if [ -n "$(first_type chinadns-ng)" ]; then
		run_ipset_chinadns_ng $@
	else
		run_ipset_dnsmasq $@
	fi
}

run_ipset_chinadns_ng() {
	local listen_port proto server_dns ipset nftset config_file
	eval_set_val $@
	[ ! -s "$TMP_ACL_PATH/vpslist" ] && {
		node_servers=$(uci show "${CONFIG}" | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2)
		hosts_foreach "node_servers" host_from_url | grep '[a-zA-Z]$' | sort -u | grep -v "engage.cloudflareclient.com" > $TMP_ACL_PATH/vpslist
	}
	
	[ -n "${ipset}" ] && {
		set_names=$ipset
		vps_set_names="psw2_vps,psw2_vps6"
	}
	[ -n "${nftset}" ] && {
		set_names=$(echo ${nftset} | awk -F, '{printf "%s,%s", substr($1,3), substr($2,3)}' | sed 's/#/@/g')
		vps_set_names="inet@passwall2@psw2_vps,inet@passwall2@psw2_vps6"
	}
	cat <<-EOF > $config_file
		bind-addr 127.0.0.1
		bind-port ${listen_port}
		china-dns ${proto}://${server_dns}
		trust-dns ${proto}://${server_dns}
		filter-qtype 65
		add-tagchn-ip ${set_names}
		default-tag chn
		group vpslist
		group-dnl $TMP_ACL_PATH/vpslist
		group-upstream ${proto}://${server_dns}
		group-ipset ${vps_set_names}
	EOF
	ln_run 0 "$(first_type chinadns-ng)" "chinadns-ng" "/dev/null" -C $config_file -v
}

run_ipset_dnsmasq() {
	local listen_port server_dns ipset nftset cache_size dns_forward_max config_file
	eval_set_val $@
	cat <<-EOF > $config_file
		port=${listen_port}
		no-poll
		no-resolv
		strict-order
		cache-size=${cache_size:-0}
		dns-forward-max=${dns_forward_max:-1000}
	EOF
	for i in $(echo ${server_dns} | sed "s#,# #g"); do
		echo "server=${i}" >> $config_file
	done
	[ -n "${ipset}" ] && echo "ipset=${ipset}" >> $config_file
	[ -n "${nftset}" ] && echo "nftset=${nftset}" >> $config_file
	ln_run 0 "$(first_type dnsmasq)" "dnsmasq" "/dev/null" -C $config_file
}

acl_node() {
	[ ! -f ${TMP_ACL_PATH}/acl_node_default ] && ENABLED_DEFAULT_ACL=0
	local acl_node_num=$(jsonfilter -s "${acl_json}" -e '$.node_order[*]' | wc -l)
	[ "${acl_node_num}" == 0 ] && {
		ENABLED_DEFAULT_ACL=0
		ENABLED_ACLS=0
		return
	}
	[ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect)" == "1" ] && {
		uci -q set ${CONFIG}.@global[0].dnsmasq_dns_redirect='1'
		uci -q commit ${CONFIG}
		uci -q set dhcp.@dnsmasq[0].dns_redirect='0'
		uci -q commit dhcp

		json_init
		json_add_string "LOG" "0"
		lua $APP_PATH/helper_dnsmasq.lua restart "$(json_dump)"
	}
	local run_func
	[ -n "${XRAY_BIN}" ] && run_func="run_xray"
	[ -n "${SINGBOX_BIN}" ] && run_func="run_singbox"
	for nid in $(jsonfilter -s "${acl_json}" -e '$.node_order[*]'); do
		[ ! -f ${TMP_ACL_PATH}/acl_node_${nid} ] && continue
		local _var=$(cat ${TMP_ACL_PATH}/acl_node_${nid} 2>/dev/null)
		eval local ${_var}
		local type=$(echo $(config_n_get $node type) | tr 'A-Z' 'a-z')
		[ -n "${type}" ] || continue
		if [ "${type}" = "xray" ] && [ -n "${XRAY_BIN}" ]; then
			run_func="run_xray"
		elif [ "${type}" = "sing-box" ] && [ -n "${SINGBOX_BIN}" ]; then
			run_func="run_singbox"
		fi
		${run_func} ${_var}
		local status=$?
		if [ "$status" != 0 ]; then
			log_i18n 2 "[%s] process %s error, skip this transparent proxy!" "${node}" "${config_file}"
			cat ${_error_log_file} >> ${LOG_FILE}
			unset _error_log_file
			continue
		fi
		local run_new_dnsmasq=1
		local DNSMASQ_TUN_DNS="127.0.0.1#${dns_listen_port}"
		local DNSMASQ_DEFAULT_DNS="${AUTO_DNS}"
		local DNSMASQ_LOCAL_DNS="${LOCAL_DNS:-${AUTO_DNS}}"
		[ -n "${DIRECT_DNS_DNSMASQ_SERVER}" ] && DNSMASQ_LOCAL_DNS="${DIRECT_DNS_DNSMASQ_SERVER}"
		if [ "${flag}" = "default" ]; then
			set_cache_var "GLOBAL_SOCKS_server" "127.0.0.1:$socks_port"
			set_cache_var "ACL_GLOBAL_node" "$node"
			run_new_dnsmasq=$(config_n_get @global[0] dns_redirect 1)
			if [ "${run_new_dnsmasq}" != "1" ]; then
				#Rewrite the default DNS service configuration
				#Modify the default dnsmasq service
				lua $APP_PATH/helper_dnsmasq.lua stretch
				json_init
				json_add_string "FLAG" "default"
				json_add_string "TMP_DNSMASQ_PATH" "${GLOBAL_DNSMASQ_CONF_PATH}"
				json_add_string "DNSMASQ_CONF_FILE" "${GLOBAL_DNSMASQ_CONF}"
				json_add_string "DEFAULT_DNS" "${DNSMASQ_DEFAULT_DNS}"
				json_add_string "LOCAL_DNS" "${DNSMASQ_LOCAL_DNS}"
				json_add_string "TUN_DNS" "${DNSMASQ_TUN_DNS}"
				json_add_string "NFTFLAG" "${nftflag:-0}"
				json_add_string "NO_LOGIC_LOG" "${NO_LOGIC_LOG:-0}"
				json_add_string "ADBLOCK" "$(detect_adblock)"
				lua $APP_PATH/helper_dnsmasq.lua add_rule "$(json_dump)"
				uci -q add_list dhcp.@dnsmasq[0].addnmount=${GLOBAL_DNSMASQ_CONF_PATH}
				uci -q commit dhcp

				lua $APP_PATH/helper_dnsmasq.lua logic_restart
			fi
		fi
		[ "${run_new_dnsmasq}" == "1" ] && {
			#Run a copy dnsmasq instance, DNS hijack for that need proxy devices.
			dnsmasq_port=$(get_new_port auto)
			run_copy_dnsmasq flag="${flag}" listen_port=${dnsmasq_port} local_dns="${DNSMASQ_LOCAL_DNS}" tun_dns="${DNSMASQ_TUN_DNS}" default_dns="${DNSMASQ_DEFAULT_DNS}"
			#dhcp.leases to hosts
			$APP_PATH/lease2hosts.sh > /dev/null 2>&1 &
			log 2 "Dnsmasq[${dnsmasq_port}]:(127.0.0.1:${dns_listen_port})"
		}
		rm -f ${TMP_ACL_PATH}/acl_node_${nid}
	done
}

start() {
	busybox pgrep -f ${TMP_PATH}/bin > /dev/null 2>&1 && {
		logger -t PW2-RESTART "Upgrade or overload residue is detected, and the subprocess is being called to perform complete cleaning..."
		(stop)
		sleep 2
	}
	mkdir -p /tmp/etc /tmp/log $TMP_PATH $TMP_BIN_PATH $TMP_SCRIPT_FUNC_PATH $TMP_ROUTE_PATH $TMP_ACL_PATH $TMP_PATH2
	get_config
	export V2RAY_LOCATION_ASSET=$(config_n_get @global_rules[0] v2ray_location_asset "/usr/share/v2ray/")
	export XRAY_LOCATION_ASSET=$V2RAY_LOCATION_ASSET
	export ENABLE_DEPRECATED_GEOSITE=true
	export ENABLE_DEPRECATED_GEOIP=true
	export SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN=1
	ulimit -n 65535
	start_haproxy
	start_socks
	nftflag=0
	USE_TABLES=""
	check_run_environment
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh start
	set_cache_var "USE_TABLES" "$USE_TABLES"
	if [ "$ENABLED_DEFAULT_ACL" == 1 ] || [ "$ENABLED_ACLS" == 1 ]; then
		bridge_nf_ipt=$(sysctl -e -n net.bridge.bridge-nf-call-iptables)
		set_cache_var "bak_bridge_nf_ipt" "$bridge_nf_ipt"
		sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
		[ "$PROXY_IPV6" == "1" ] && {
			bridge_nf_ip6t=$(sysctl -e -n net.bridge.bridge-nf-call-ip6tables)
			set_cache_var "bak_bridge_nf_ip6t" "$bridge_nf_ip6t"
			sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null 2>&1
		}
	fi
	run_process_queue
	start_crontab
	log_i18n 0 "Running complete!"
	echolog "\n"

	[ "$ENABLED" = 1 ] && [ "$1" = "boot" ] && {
		local cfgids item
		for item in $(uci show ${CONFIG} | grep "=subscribe_list" | cut -d '.' -sf 2 | cut -d '=' -sf 1); do
			if [ "$(config_n_get "$item" boot_update 0)" = "1" ]; then
				cfgids="${cfgids:+$cfgids,}$item"
			fi
		done
		[ -n "$cfgids" ] && {
			sleep 5
			lua $APP_PATH/subscribe.lua start $cfgids cron > /dev/null 2>&1 &
		}
	}
}

stop() {
	clean_log
	eval_cache_var
	[ -n "$USE_TABLES" ] && source $APP_PATH/${USE_TABLES}.sh stop
	delete_ip2route
	# Kill the SS plugin process
	# kill_all xray-plugin v2ray-plugin obfs-local shadow-tls
	local pid_file pid
	find "$TMP_PATH" -type f -name '*_plugin.pid' 2>/dev/null | while read -r pid_file; do
		read -r pid < "$pid_file"
		if [ -n "$pid" ]; then
			kill -9 "$pid" >/dev/null 2>&1
		fi
	done
	busybox pgrep -af "${CONFIG}/monitor\.sh" | xargs -r kill -9 >/dev/null 2>&1
	busybox pgrep -f "sleep.*(6s|9s|58s)" | xargs -r kill -9 >/dev/null 2>&1
	busybox pgrep -af "${CONFIG}/" | awk '! /app\.sh|subscribe\.lua|rule_update\.lua|tasks\.sh|server_app\.lua|ujail/{print $1}' | xargs -r kill -9 >/dev/null 2>&1
	unset V2RAY_LOCATION_ASSET
	unset XRAY_LOCATION_ASSET
	unset SS_SYSTEM_DNS_RESOLVER_FORCE_BUILTIN
	stop_crontab
	rm -rf $GLOBAL_DNSMASQ_CONF
	rm -rf $GLOBAL_DNSMASQ_CONF_PATH
	[ "1" = "1" ] && {
		#restore logic
		bak_dnsmasq_dns_redirect=$(config_n_get @global[0] dnsmasq_dns_redirect)
		[ -n "${bak_dnsmasq_dns_redirect}" ] && {
			uci -q set dhcp.@dnsmasq[0].dns_redirect="${bak_dnsmasq_dns_redirect}"
			uci -q commit dhcp
			uci -q delete ${CONFIG}.@global[0].dnsmasq_dns_redirect
			uci -q commit ${CONFIG}
		}
		if [ -z "${ACL_default_dns_port}" ] || [ -n "${bak_dnsmasq_dns_redirect}" ]; then
			uci -q del_list dhcp.@dnsmasq[0].addnmount="${GLOBAL_DNSMASQ_CONF_PATH}"
			uci -q commit dhcp

			json_init
			json_add_string "LOG" "0"
			lua $APP_PATH/helper_dnsmasq.lua restart "$(json_dump)"
		fi
		[ -n "${bak_bridge_nf_ipt}" ] && sysctl -w net.bridge.bridge-nf-call-iptables=${bak_bridge_nf_ipt} >/dev/null 2>&1
		[ -n "${bak_bridge_nf_ip6t}" ] && sysctl -w net.bridge.bridge-nf-call-ip6tables=${bak_bridge_nf_ip6t} >/dev/null 2>&1
	}
	rm -rf $TMP_PATH
	rm -rf /tmp/lock/${CONFIG}_socks_auto_switch*
	rm -rf /tmp/lock/${CONFIG}_lease2hosts*
	log_i18n 0 "Clearing and closing related programs and cache complete."
	exit 0
}

get_direct_dns() {
	RESOLVFILE=/tmp/resolv.conf.d/resolv.conf.auto
	[ -f "${RESOLVFILE}" ] && [ -s "${RESOLVFILE}" ] || RESOLVFILE=/tmp/resolv.conf.auto

	ISP_DNS=$(cat $RESOLVFILE 2>/dev/null | grep -E -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -v -E '^(0\.0\.0\.0|127\.0\.0\.1)$' | awk '!seen[$0]++')
	ISP_DNS6=$(cat $RESOLVFILE 2>/dev/null | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | awk -F % '{print $1}' | awk -F " " '{print $2}' | grep -v -Fx ::1 | grep -v -Fx :: | awk '!seen[$0]++')

	DNSMASQ_UPSTREAM_DNS=$(uci show dhcp.@dnsmasq[0] | grep "\.server=" | awk -F '=' '{print $2}' | sed "s/'//g" | tr ' ' '\n' | grep -v "\/" | awk '{if($1 ~ /#/) {sub(/#/, "#", $1); print $1} else {print $1"#53"}}' | head -2 | sed ':label;N;s/\n/,/;b label')
	DEFAULT_DNS="${DNSMASQ_UPSTREAM_DNS}"
	[ -z "${DEFAULT_DNS}" ] && DEFAULT_DNS=$(echo -n $ISP_DNS | tr ' ' '\n' | head -2 | tr '\n' ',' | sed 's/,$//')
	AUTO_DNS=${DEFAULT_DNS:-119.29.29.29}
	RETURN_DNS=${AUTO_DNS}

	local AUTO_DNS_1=$(echo ${AUTO_DNS} | awk -F ',' '{print $1}')
	local AUTO_DNS_2=$(echo ${AUTO_DNS} | awk -F ',' '{print $2}')

	DIRECT_DNS_PROTO="udp"
	DIRECT_DNS_SERVER=$(echo ${AUTO_DNS_1} | awk -F '#' '{print $1}')
	DIRECT_DNS_PORT=$(echo ${AUTO_DNS_1} | awk -F '#' '{print $2}')
	DIRECT_DNS_PORT=${DIRECT_DNS_PORT:-53}

	local direct_dns_protocol=$(config_n_get @global[0] direct_dns_protocol)
	if [ "${direct_dns_protocol}" = "tcp" ] || [ "${direct_dns_protocol}" = "udp" ]; then
		local DIRECT_DNS=$(config_n_get @global[0] direct_dns)
		local result=$(lua_api "parseDNS(\"${DIRECT_DNS}\")")
		[ "${result}" != "nil" ] && {
			DIRECT_DNS_PROTO="${direct_dns_protocol}"
			DIRECT_DNS_SERVER=$(echo ${result} | awk '{print $1}')
			DIRECT_DNS_PORT=$(echo ${result} | awk '{print $2}')
			[ "${DIRECT_DNS_PROTO}" = "udp" ] && DIRECT_DNS_DNSMASQ_SERVER="${DIRECT_DNS_SERVER}#${DIRECT_DNS_PORT}"
			RETURN_DNS="${RETURN_DNS},${DIRECT_DNS_SERVER}#${DIRECT_DNS_PORT}#${DIRECT_DNS_PROTO}"
		}
	fi
}

get_config() {
	ENABLED_DEFAULT_ACL=0
	ENABLED=$(config_n_get @global[0] enabled 0)
	NODE=$(config_n_get @global[0] node)
	[ "$ENABLED" == 1 ] && [ -n "$NODE" ] && [ "$(config_get_type $NODE)" == "nodes" ] && ENABLED_DEFAULT_ACL=1
	ENABLED_ACLS=$(config_n_get @global[0] acl_enable 0)
	SOCKS_ENABLED=$(config_n_get @global[0] socks_enabled 0)
	TCP_PROXY_WAY=$(config_n_get @global_forwarding[0] tcp_proxy_way redirect)
	PROXY_IPV6=$(config_n_get @global_forwarding[0] ipv6_tproxy 0)
	DIRECT_DNS_QUERY_STRATEGY=$(config_n_get @global[0] direct_dns_query_strategy UseIP)

	get_direct_dns

	DEFAULT_DNSMASQ_CONF_DIR=/tmp/dnsmasq.d
	DNSMASQ_CONF_DIR=${DEFAULT_DNSMASQ_CONF_DIR}
	DEFAULT_DNSMASQ_CFGID="$(uci -q show "dhcp.@dnsmasq[0]" | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')"
	if [ -f "/tmp/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID" ]; then
		DNSMASQ_CONF_DIR="$(awk -F '=' '/^conf-dir=/ {print $2}' "/tmp/etc/dnsmasq.conf.$DEFAULT_DNSMASQ_CFGID")"
		if [ -n "$DNSMASQ_CONF_DIR" ]; then
			DNSMASQ_CONF_DIR=${DNSMASQ_CONF_DIR%*/}
		else
			DNSMASQ_CONF_DIR=${DEFAULT_DNSMASQ_CONF_DIR}
		fi
	fi
	set_cache_var GLOBAL_DNSMASQ_CONF ${DNSMASQ_CONF_DIR}/dnsmasq-${CONFIG}.conf
	set_cache_var GLOBAL_DNSMASQ_CONF_PATH ${TMP_ACL_PATH}/default_dnsmasq.d

	QUEUE_RUN=1
}

arg1=$1
shift
case $arg1 in
run_socks)
	get_direct_dns
	QUEUE_RUN=0
	run_socks $@
	;;
socks_node_switch)
	get_direct_dns
	QUEUE_RUN=0
	socks_node_switch $@
	;;
start)
	start $@
	;;
stop)
	stop
	;;
esac
