#!/bin/sh

DIR="$(cd "$(dirname "$0")" && pwd)"
MY_PATH=$DIR/iptables.sh
UTILS_PATH=$DIR/utils.sh
IPSET_LOCAL="psw2_local"
IPSET_DIRECT="psw2_direct"
IPSET_VPS="psw2_vps"
IPSET_WAN="psw2_wan"

IPSET_LOCAL6="psw2_local6"
IPSET_DIRECT6="psw2_direct6"
IPSET_VPS6="psw2_vps6"
IPSET_WAN6="psw2_wan6"

FWMARK="0x50535732"

ipt=$(command -v iptables-legacy || command -v iptables)
ip6t=$(command -v ip6tables-legacy || command -v ip6tables)

ipt_n="$ipt -t nat -w"
ipt_m="$ipt -t mangle -w"
ip6t_n="$ip6t -t nat -w"
ip6t_m="$ip6t -t mangle -w"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_nat')" ] && ip6t_n="eval #$ip6t_n"
[ -z "$ip6t" -o -z "$(lsmod | grep 'ip6table_mangle')" ] && ip6t_m="eval #$ip6t_m"
FWI=$(uci -q get firewall.passwall2.path 2>/dev/null)
FAKE_IP="198.18.0.0/16"
FAKE_IP_6="fc00::/18"

factor() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		echo ""
	elif [ "$1" == "1:65535" ]; then
		echo ""
	else
		echo "$2 $1"
	fi
}

dst() {
	echo "-m set $2 --match-set $1 dst"
}

comment() {
	local name=$(echo $1 | sed 's/ /_/g')
	echo "-m comment --comment "${name}""
}

# Resolves invalid IP addresses for ports exceeding 15; it supports single ports and port ranges.
add_port_rules() {
	local ipt_cmd="$1"
	local port_list="$2"
	local target="$3"
	echo "$port_list" | grep -vq '[0-9]' && return
	port_list=$(echo "$port_list" | tr -d ' ' | sed 's/-/:/g' | tr ',' '\n' | awk '!a[$0]++' | grep -v '^$')
	[ -z "$port_list" ] && return
	if echo "$port_list" | grep -q '^1:65535$'; then
		eval "$ipt_cmd $target"
		return
	fi
	local multiport_ports=""
	local range_ports=""
	local count=0
	local port
	for port in $port_list; do
		if echo "$port" | grep -q ':'; then
			range_ports="$range_ports $port"
		else
			multiport_ports="$multiport_ports,$port"
			count=$((count + 1))
			if [ "$count" -eq 15 ]; then
				eval "$ipt_cmd -m multiport --dport ${multiport_ports#,} $target"
				multiport_ports=""
				count=0
			fi
		fi
	done
	if [ -n "$multiport_ports" ]; then
		eval "$ipt_cmd -m multiport --dport ${multiport_ports#,} $target"
	fi
	for port in $range_ports; do
		eval "$ipt_cmd --dport $port $target"
	done
}

destroy_ipset() {
	for i in "$@"; do
		ipset -q -F $i
		ipset -q -X $i
	done
}

insert_rule_before() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | head -n 1 | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -z "${_index}" ]; then
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

insert_rule_after() {
	[ $# -ge 3 ] || {
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local keyword="${1}"; shift
	local rule="${1}"; shift
	local default_index="${1}"; shift
	default_index=${default_index:-0}
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$keyword" | awk 'END {print}' | awk '{print $1}')
	if [ -z "${_index}" ] && [ "${default_index}" = "0" ]; then
		$ipt_tmp -A $chain $rule
	else
		if [ -n "${_index}" ]; then
			_index=$((_index + 1))
		else
			_index=${default_index}
		fi
		$ipt_tmp -I $chain $_index $rule
	fi
}

RULE_LAST_INDEX() {
	[ $# -ge 3 ] || {
		log_i18n 1 "Incorrect index listing method (%s), execution terminated!" "iptables"
		return 1
	}
	local ipt_tmp="${1}"; shift
	local chain="${1}"; shift
	local list="${1}"; shift
	local default="${1:-0}"; shift
	local _index=$($ipt_tmp -n -L $chain --line-numbers 2>/dev/null | grep "$list" | head -n 1 | awk '{print $1}')
	echo "${_index:-${default}}"
}

REDIRECT() {
	local s="-j REDIRECT"
	[ -n "$1" ] && {
		local s="$s --to-ports $1"
		[ "$2" == "TPROXY" ] && {
			local mark="-m mark --mark ${FWMARK}"
			s="${mark} -j TPROXY --on-port $1"
		}
	}
	echo $s
}

get_redirect_ipt() {
	echo "$(REDIRECT $2 $3)"
}

get_redirect_ip6t() {
	echo "$(REDIRECT $2 $3)"
}

gen_shunt_list() {
	local node=${1}
	local shunt_list4_var_name=${2}
	local shunt_list6_var_name=${3}
	[ -z "$node" ] && continue
	unset ${shunt_list4_var_name}
	unset ${shunt_list6_var_name}
	local _SHUNT_LIST4 _SHUNT_LIST6
	local USE_SHUNT_NODE=0
	NODE_PROTOCOL=$(config_n_get $node protocol)
	[ "$NODE_PROTOCOL" = "_shunt" ] && USE_SHUNT_NODE=1
	[ "$USE_SHUNT_NODE" = "1" ] && {
		local enable_geoview_ip=$(config_n_get $node enable_geoview_ip 0)
		[ -z "$(first_type geoview)" ] && enable_geoview_ip=0
		local preloading=0
		preloading=$enable_geoview_ip
		[ "${preloading}" = "1" ] && {
			local default_node=$(config_n_get ${node} default_node _direct)
			local default_outbound="redirect"
			[ "$default_node" = "_direct" ] && default_outbound="direct"
			local shunt_ids=$(uci show $CONFIG | grep "=shunt_rules" | awk -F '.' '{print $2}' | awk -F '=' '{print $1}')
			local shunt_group=$(config_n_get $node shunt_group)
			for shunt_id in $shunt_ids; do
				[ "${shunt_group}" != "$(config_n_get ${shunt_id} group)" ] && continue
				local shunt_node=$(config_n_get ${node} "${shunt_id}")
				[ -n "$shunt_node" ] && {
					local ipset_v4="psw2_${node}_${shunt_id}"
					local ipset_v6="psw2_${node}_${shunt_id}6"
					ipset -! create $ipset_v4 nethash maxelem 1048576
					ipset -! create $ipset_v6 nethash family inet6 maxelem 1048576
					local outbound="redirect"
					[ "$shunt_node" = "_direct" ] && outbound="direct"
					[ "$shunt_node" = "_default" ] && outbound="${default_outbound}"
					_SHUNT_LIST4="${_SHUNT_LIST4} ${ipset_v4}:${outbound}"
					_SHUNT_LIST6="${_SHUNT_LIST6} ${ipset_v6}:${outbound}"

					config_n_get $shunt_id ip_list | sed 's/#.*//' | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $ipset_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
					config_n_get $shunt_id ip_list | sed 's/#.*//' | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $ipset_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
					[ "${enable_geoview_ip}" = "1" ] && {
						local _geoip_code=$(config_n_get $shunt_id ip_list | tr -s "\r\n" "\n" | sed -e "/^$/d" | grep -E "^geoip:" | grep -v "^geoip:private" | sed -E 's/^geoip:(.*)/\1/' | sed ':a;N;$!ba;s/\n/,/g')
						[ -n "$_geoip_code" ] && {
							get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $ipset_v4 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
							get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $ipset_v6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
							#log 3 "$(i18n "parse the traffic splitting rules[%s]-[geoip:%s] add to %s to complete." "${shunt_id}" "${_geoip_code}" "IPSET[${ipset_v4},${ipset_v6}]")"
						}
					}
				}
			done
		}
		local direct_ipset4=$(get_cache_var "node_${node}_direct_ipset4")
		[ -n "${direct_ipset4}" ] && {
			ipset -! create ${direct_ipset4} iphash maxelem 1048576 timeout 259200
			_SHUNT_LIST4="${_SHUNT_LIST4} ${direct_ipset4}:direct"
		}
		local direct_ipset6=$(get_cache_var "node_${node}_direct_ipset6")
		[ -n "${direct_ipset6}" ] && {
			ipset -! create ${direct_ipset6} iphash family inet6 maxelem 1048576 timeout 259200
			_SHUNT_LIST6="${_SHUNT_LIST6} ${direct_ipset6}:direct"
		}
	}
	[ -n "${_SHUNT_LIST4}" ] && eval ${shunt_list4_var_name}=\"${_SHUNT_LIST4}\"
	[ -n "${_SHUNT_LIST6}" ] && eval ${shunt_list6_var_name}=\"${_SHUNT_LIST6}\"
	set_cache_var "${node}_gen_shunt_list" "1"
}

add_shunt_t_rule() {
	local shunt_args=${1}
	local t_args=${2}
	local t_jump_args=${3}
	local t_ports_args=${4}
	[ -n "${shunt_args}" ] && {
		for j in ${shunt_args}; do
			local _set_name=$(echo ${j} | awk -F ':' '{print $1}')
			local _outbound=$(echo ${j} | awk -F ':' '{print $2}')
			[ -n "${_set_name}" ] && [ -n "${_outbound}" ] && {
				local _t_arg="${t_jump_args}"
				[ "${_outbound}" = "direct" ] && _t_arg="-j RETURN"
				if [ -z "${t_ports_args}" ] || [ "${t_ports_args}" == "1:65535" ]; then
					${t_args} $(dst ${_set_name}) ${_t_arg}
				else
					add_port_rules "${t_args} $(dst ${_set_name})" "${t_ports_args}" "${_t_arg}"
				fi
			}
		done
	}
}

load_acl() {
	log_i18n 1 "Access Control:"
	acl_json=$(lua $APP_PATH/app_acl.lua)
	acl_node
	for sid in $(jsonfilter -s "${acl_json}" -e '$.acl[*].flag'); do
		eval local $(cat "${TMP_ACL_PATH}/${sid}/var")

		[ -z "$(get_cache_var "${node}_gen_shunt_list")" ] && [ -n "${node}" ] && gen_shunt_list "${node}" shunt_list4 shunt_list6
		[ -n "${use}" ] && local dns_redirect_port=$(get_cache_var "ACL_${use}_dns_port")

		local ipt_tmp=$ipt_n
		[ -n "${is_tproxy}" ] && ipt_tmp=$ipt_m

		[ "${client_proxy}" = "1" ] && {
			msg1="$(i18n "[%s]," "${remarks}")"
			for i in $(cat ${TMP_ACL_PATH}/${sid}/source_list); do
				local _ipt_source _ipv4
				local msg
				if [ -n "${interface}" ]; then
					local gateway device
					network_get_gateway gateway "${interface}"
					network_get_device device "${interface}"
					# network_get_device returns empty for non-UP interfaces (e.g. auto='0').
					# Try ubus directly, then check if the name is a kernel device.
					[ -z "${device}" ] && device=$(ubus call "network.interface.${interface}" status 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null)
					[ -z "${device}" ] && [ -d "/sys/class/net/${interface}" ] && device="${interface}"
					[ -z "${device}" ] && device="${interface}"
					_ipt_source="-i ${device} "
					msg=$(i18n "Source iface [%s]," "${device}")
				else
					msg=$(i18n "Source iface [%s]," $(i18n "All"))
				fi
				if [ -n "$(echo ${i} | grep '^iprange:')" ]; then
					_iprange=$(echo ${i} | sed 's#iprange:##g')
					_ipt_source=$(factor ${_iprange} "${_ipt_source}-m iprange --src-range")
					msg="${msg}$(i18n "IP range [%s]," "${_iprange}")"
					_ipv4="1"
					unset _iprange
				elif [ -n "$(echo ${i} | grep '^ipset:')" ]; then
					_ipset=$(echo ${i} | sed 's#ipset:##g')
					msg="${msg}IPset$(i18n "[%s]," "${_ipset}")"
					ipset -q list ${_ipset} >/dev/null
					if [ $? -eq 0 ]; then
						_ipt_source="${_ipt_source}-m set --match-set ${_ipset} src"
						unset _ipset
					else
						log 2 "$(i18n "[%s]," "${remarks}")${msg}$(i18n "Does not exist, ignore.")"
						unset _ipset
						continue
					fi
				elif [ -n "$(echo ${i} | grep '^ip:')" ]; then
					_ip=$(echo ${i} | sed 's#ip:##g')
					_ipt_source=$(factor ${_ip} "${_ipt_source}-s")
					msg="${msg}IP$(i18n "[%s]," "${_ip}")"
					_ipv4="1"
					unset _ip
				elif [ -n "$(echo ${i} | grep '^mac:')" ]; then
					_mac=$(echo ${i} | sed 's#mac:##g')
					_ipt_source=$(factor ${_mac} "${_ipt_source}-m mac --mac-source")
					msg="${msg}MAC$(i18n "[%s]," "${_mac}")"
					unset _mac
				elif [ -n "$(echo ${i} | grep '^any')" ]; then
					msg="${msg}$(i18n "All device,")"
				else
					continue
				fi

				msg="${msg1}${msg}"

				[ -n "$tcp_no_redir_ports" ] && {
					if ! has_1_65535 "$tcp_no_redir_ports"; then
						[ "$_ipv4" != "1" ] && add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp" $tcp_no_redir_ports "-j RETURN" 2>/dev/null
						add_port_rules "$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp" $tcp_no_redir_ports "-j RETURN"
						log 2 "${msg}$(i18n "not proxy %s port [%s]" "TCP" "${tcp_no_redir_ports}")"
					else
						# It will return when it ends, so no extra rules are needed.
						no_tcp_proxy="1"
						log 2 "${msg}$(i18n "not proxy all %s" "TCP")"
					fi
				}
				
				[ -n "$udp_no_redir_ports" ] && {
					if ! has_1_65535 "$udp_no_redir_ports"; then
						[ "$_ipv4" != "1" ] && add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp" $udp_no_redir_ports "-j RETURN" 2>/dev/null
						add_port_rules "$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp" $udp_no_redir_ports "-j RETURN"
						log 2 "${msg}$(i18n "not proxy %s port [%s]" "UDP" "${udp_no_redir_ports}")"
					else
						# It will return when it ends, so no extra rules are needed.
						no_udp_proxy="1"
						log 2 "${msg}$(i18n "not proxy all %s" "UDP")"
					fi
				}
				
				if ([ -z "$no_tcp_proxy" ] || [ -z "$no_udp_proxy" ]) && [ -n "$dns_redirect_port" ]; then
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					log 2 "${msg}$(i18n "DNS will redirected to the dedicated DNS server [%s]." "${dns_redirect_port}")"
				else
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p udp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
					$ipt_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN
					$ip6t_n -A PSW2_DNS $(comment "$remarks") -p tcp ${_ipt_source} --dport 53 -j RETURN 2>/dev/null
				fi

				[ -z "$no_tcp_proxy" ] && [ -n "$redir_port" ] && {
					msg2="${msg}$(i18n "Use the %s node [%s]" "TCP" "${node_remarks}")"
					if [ -n "${is_tproxy}" ]; then
						msg2="${msg2}(TPROXY:${redir_port})"
						ipt_j="-j PSW2_RULE"
					else
						msg2="${msg2}(REDIRECT:${redir_port})"
						ipt_j="$(REDIRECT $redir_port)"
					fi

					[ "$accept_icmp" = "1" ] && {
						$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} -d $FAKE_IP $(REDIRECT)
						add_shunt_t_rule "${shunt_list4}" "$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source}" "$(REDIRECT)"
						$ipt_n -A PSW2 $(comment "$remarks") -p icmp ${_ipt_source} $(REDIRECT)
					}
					
					[ "$accept_icmpv6" = "1" ] && [ "$PROXY_IPV6" == "1" ] && {
						$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} -d $FAKE_IP_6 $(REDIRECT) 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source}" "$(REDIRECT)" 2>/dev/null
						$ip6t_n -A PSW2 $(comment "$remarks") -p ipv6-icmp ${_ipt_source} $(REDIRECT) 2>/dev/null
					}

					$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP ${ipt_j}
					add_shunt_t_rule "${shunt_list4}" "$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" "${ipt_j}" $tcp_redir_ports
					add_port_rules "$ipt_tmp -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "${ipt_j}"
					[ -n "${is_tproxy}" ] && $ipt_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY)

					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} -d $FAKE_IP_6 -j PSW2_RULE 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" "${ipt_j}" $tcp_redir_ports 2>/dev/null
						add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source}" $tcp_redir_ports "-j PSW2_RULE" 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p tcp ${_ipt_source} $(REDIRECT $redir_port TPROXY) 2>/dev/null
					}
					log 2 "${msg2}"
				}
				$ipt_tmp -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN
				[ "$_ipv4" != "1" ] && $ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p tcp -j RETURN 2>/dev/null

				[ -z "$no_udp_proxy" ] && [ -n "$redir_port" ] && {
					msg2="${msg}$(i18n "Use the %s node [%s]" "UDP" "${node_remarks}")(TPROXY:${redir_port})"

					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP -j PSW2_RULE
					add_shunt_t_rule "${shunt_list4}" "$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" "-j PSW2_RULE" $udp_redir_ports
					add_port_rules "$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "-j PSW2_RULE"
					$ipt_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $redir_port TPROXY)

					[ "$PROXY_IPV6" == "1" ] && [ "$_ipv4" != "1" ] && {
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} -d $FAKE_IP_6 -j PSW2_RULE 2>/dev/null
						add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" "-j PSW2_RULE" $udp_redir_ports 2>/dev/null
						add_port_rules "$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source}" $udp_redir_ports "-j PSW2_RULE" 2>/dev/null
						$ip6t_m -A PSW2 $(comment "$remarks") -p udp ${_ipt_source} $(REDIRECT $redir_port TPROXY) 2>/dev/null
					}
					log 2 "${msg2}"
				}
				$ipt_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN
				[ "$_ipv4" != "1" ] && $ip6t_m -A PSW2 $(comment "$remarks") ${_ipt_source} -p udp -j RETURN 2>/dev/null
				unset ipt_j _ipt_source msg msg2 _ipv4 no_tcp_proxy no_udp_proxy
			done
			unset msg1
		}
		[ "${local_proxy}" = "1" ] && {
			msg="$(i18n "[Local],")"
			[ -n "$tcp_no_redir_ports" ] && {
				add_port_rules "$ipt_tmp -A PSW2_OUTPUT -p tcp" $tcp_no_redir_ports "-j RETURN"
				add_port_rules "$ip6t_m -A PSW2_OUTPUT -p tcp" $tcp_no_redir_ports "-j RETURN"
				if ! has_1_65535 "$tcp_no_redir_ports"; then
					log 2 "${msg}$(i18n "not proxy %s port [%s]" "TCP" "${tcp_no_redir_ports}")"
				else
					no_tcp_local_proxy="1"
					log 2 "${msg}$(i18n "not proxy all %s" "TCP")"
				fi
			}
			[ -n "$udp_no_redir_ports" ] && {
				add_port_rules "$ipt_m -A PSW2_OUTPUT -p udp" $udp_no_redir_ports "-j RETURN"
				add_port_rules "$ip6t_m -A PSW2_OUTPUT -p udp" $udp_no_redir_ports "-j RETURN"
				if ! has_1_65535 "$udp_no_redir_ports"; then
					log 2 "${msg}$(i18n "not proxy %s port [%s]" "UDP" "${udp_no_redir_ports}")"
				else
					no_udp_local_proxy="1"
					log 2 "${msg}$(i18n "not proxy all %s" "UDP")"
				fi
			}
			
			if [ -n "$node" ] && ([ -z "$no_tcp_local_proxy" ] || [ -z "$no_udp_local_proxy" ]); then
				[ -n "$dns_redirect_port" ] && {
					$ipt_n -A OUTPUT $(comment "PSW2_DNS") -p udp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A OUTPUT $(comment "PSW2_DNS") -p udp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					$ipt_n -A OUTPUT $(comment "PSW2_DNS") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port
					$ip6t_n -A OUTPUT $(comment "PSW2_DNS") -p tcp -o lo --dport 53 -j REDIRECT --to-ports $dns_redirect_port 2>/dev/null
					log 2 "${msg}$(i18n "DNS will redirected to the dedicated DNS server [%s]." "${dns_redirect_port}")"
				}
			fi

			local comment_l="$(i18n "Local")"

			# Loading local router proxy TCP
			if [ -n "$node" ] && [ -z "$no_tcp_local_proxy" ]; then
				[ "$accept_icmp" = "1" ] && {
					$ipt_n -A OUTPUT $(dst $IPSET_DIRECT !) -p icmp -j PSW2_OUTPUT
					$ipt_n -A PSW2_OUTPUT -p icmp -d $FAKE_IP $(REDIRECT)
					add_shunt_t_rule "${shunt_list4}" "$ipt_n -A PSW2_OUTPUT -p icmp" "$(REDIRECT)"
					$ipt_n -A PSW2_OUTPUT -p icmp $(REDIRECT)
				}

				[ "$accept_icmpv6" = "1" ] && {
					$ip6t_n -A OUTPUT $(dst $IPSET_DIRECT6 !) -p ipv6-icmp -j PSW2_OUTPUT
					$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp -d $FAKE_IP_6 $(REDIRECT)
					add_shunt_t_rule "${shunt_list6}" "$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp" "$(REDIRECT)"
					$ip6t_n -A PSW2_OUTPUT -p ipv6-icmp $(REDIRECT)
				}

				msg2="${msg}$(i18n "Use the %s node [%s]" "TCP" "${node_remarks}")"
				if [ -n "${is_tproxy}" ]; then
					msg2="${msg2}(TPROXY:${redir_port})"
					ipt_j="-j PSW2_RULE"
				else
					msg2="${msg2}(REDIRECT:${redir_port})"
					ipt_j="$(REDIRECT $redir_port)"
				fi

				$ipt_tmp -A PSW2_OUTPUT -p tcp -d $FAKE_IP ${ipt_j}
				add_shunt_t_rule "${shunt_list4}" "$ipt_tmp -A PSW2_OUTPUT -p tcp" "${ipt_j}" $tcp_redir_ports
				add_port_rules "$ipt_tmp -A PSW2_OUTPUT -p tcp" $tcp_redir_ports "${ipt_j}"
				[ -z "${is_tproxy}" ] && $ipt_n -A OUTPUT $(dst $IPSET_DIRECT !) -p tcp -j PSW2_OUTPUT
				[ -n "${is_tproxy}" ] && {
					$ipt_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo $(REDIRECT $redir_port TPROXY)
					$ipt_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo -j RETURN
					insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT !) -p tcp -j PSW2_OUTPUT"
				}

				[ "$PROXY_IPV6" == "1" ] && {
					$ip6t_m -A PSW2_OUTPUT -p tcp -d $FAKE_IP_6 -j PSW2_RULE
					add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2_OUTPUT -p tcp" "-j PSW2_RULE" $tcp_redir_ports
					add_port_rules "$ip6t_m -A PSW2_OUTPUT -p tcp" $tcp_redir_ports "-j PSW2_RULE"
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo $(REDIRECT $redir_port TPROXY)
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p tcp -i lo -j RETURN
					insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT6 !) -p tcp -j PSW2_OUTPUT"
				}

				[ -d "${TMP_IFACE_PATH}" ] && {
					for iface in $(ls ${TMP_IFACE_PATH}); do
						$ipt_n -A PSW2_OUTPUT -o $iface -p tcp -j RETURN
						$ipt_m -A PSW2_OUTPUT -o $iface -p tcp -j RETURN
					done
				}
				log 2 "${msg2}"
			fi

			# Loading local router proxy UDP
			if [ -n "$node" ] && [ -z "$no_udp_local_proxy" ]; then
				msg2="${msg}$(i18n "Use the %s node [%s]" "UDP" "${node_remarks}")(TPROXY:${redir_port})"
				$ipt_m -A PSW2_OUTPUT -p udp -d $FAKE_IP -j PSW2_RULE
				add_shunt_t_rule "${shunt_list4}" "$ipt_m -A PSW2_OUTPUT -p udp" "-j PSW2_RULE" $udp_redir_ports
				add_port_rules "$ipt_m -A PSW2_OUTPUT -p udp" $udp_redir_ports "-j PSW2_RULE"
				$ipt_m -A PSW2 $(comment "${comment_l}") -p udp -i lo $(REDIRECT $redir_port TPROXY)
				$ipt_m -A PSW2 $(comment "${comment_l}") -p udp -i lo -j RETURN
				insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT !) -p udp -j PSW2_OUTPUT"

				[ "$PROXY_IPV6" == "1" ] && {
					$ip6t_m -A PSW2_OUTPUT -p udp -d $FAKE_IP_6 -j PSW2_RULE
					add_shunt_t_rule "${shunt_list6}" "$ip6t_m -A PSW2_OUTPUT -p udp" "-j PSW2_RULE" $udp_redir_ports
					add_port_rules "$ip6t_m -A PSW2_OUTPUT -p udp" $udp_redir_ports "-j PSW2_RULE"
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p udp -i lo $(REDIRECT $redir_port TPROXY)
					$ip6t_m -A PSW2 $(comment "${comment_l}") -p udp -i lo -j RETURN
					insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) $(dst $IPSET_DIRECT6 !) -p udp -j PSW2_OUTPUT"
				}

				[ -d "${TMP_IFACE_PATH}" ] && {
					for iface in $(ls ${TMP_IFACE_PATH}); do
						$ipt_n -A PSW2_OUTPUT -o $iface -p udp -j RETURN
						$ipt_m -A PSW2_OUTPUT -o $iface -p udp -j RETURN
					done
				}

				log 2 "${msg2}"
			fi

			$ipt_m -I OUTPUT $(comment "mangle-OUTPUT-PSW2") -o lo -j RETURN
			insert_rule_before "$ipt_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -m mark --mark ${FWMARK} -j RETURN"
			
			$ip6t_m -I OUTPUT $(comment "mangle-OUTPUT-PSW2") -o lo -j RETURN
			insert_rule_before "$ip6t_m" "OUTPUT" "mwan3" "$(comment mangle-OUTPUT-PSW2) -m mark --mark ${FWMARK} -j RETURN"

			$ipt_m -I PSW2 -p tcp --dport 53 -j ACCEPT
			$ipt_m -I PSW2 -p udp --dport 53 -j ACCEPT
			$ip6t_m -I PSW2 -p tcp --dport 53 -j ACCEPT
			$ip6t_m -I PSW2 -p udp --dport 53 -j ACCEPT

			unset msg msg2 comment_l
		}
		unset dns_redirect_port ipt_tmp
		unset $(cat "${TMP_ACL_PATH}/${sid}/var" | awk -F '=' '{print $1}' | tr "\n" " ")
	done
}

filter_haproxy() {
	[ "$(config_n_get @global_haproxy[0] balancing_enable 0)" != "1" ] && return
	for item in $(uci show $CONFIG | grep ".lbss=" | cut -d "'" -f 2); do
		local ip=$(get_host_ip ipv4 $(echo $item | awk -F ":" '{print $1}') 1)
		[ -n "$ip" ] && ipset -q add $IPSET_VPS $ip
	done
	log_i18n 1 "Add node to the load balancer is directly connected to %s[%s]." "ipset" "${IPSET_VPS}"
}

filter_vpsip() {
	local ipv4_addrs=$(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | grep -v "^127\.0\.0\.1$")
	[ -n "$ipv4_addrs" ] && {
		echo "$ipv4_addrs" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPS &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
		log 1 "$(i18n "Add all %s nodes to %s[%s] direct connection complete." "IPv4" "ipset" "${IPSET_VPS}")"
	}
	local ipv6_addrs=$(uci show $CONFIG | grep -E "(.address=|.download_address=)" | cut -d "'" -f 2 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}")
	[ -n "$ipv6_addrs" ] && {
		echo "$ipv6_addrs" | sed -e "/^$/d" | sed -e "s/^/add $IPSET_VPS6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
		log 1 "$(i18n "Add all %s nodes to %s[%s] direct connection complete." "IPv6" "ipset" "${IPSET_VPS6}")"
	}
}

filter_server_port() {
	local address=${1}
	local port=${2}
	local stream=${3}
	stream=$(echo ${3} | tr 'A-Z' 'a-z')
	local _is_tproxy ipt_tmp
	ipt_tmp=$ipt_n
	_is_tproxy=${is_tproxy}
	[ "$stream" == "udp" ] && _is_tproxy="TPROXY"
	[ -n "${_is_tproxy}" ] && ipt_tmp=$ipt_m

	for _ipt in 4 6; do
		[ "$_ipt" == "4" ] && _ipt=$ipt_tmp
		[ "$_ipt" == "6" ] && _ipt=$ip6t_m
		$_ipt -n -L PSW2_OUTPUT | grep -q "${address}:${port}"
		if [ $? -ne 0 ]; then
			$_ipt -I PSW2_OUTPUT $(comment "${address}:${port}") -p $stream -d $address --dport $port -j RETURN 2>/dev/null
		fi
	done
}

filter_node() {
	local node=${1}
	local stream=${2}
	if [ -n "$node" ]; then
		local address=$(config_n_get $node address)
		local port=$(config_n_get $node port)
		[ -z "$address" ] && [ -z "$port" ] && {
			return 1
		}
		filter_server_port $address $port $stream
		filter_server_port $address $port $stream
	fi
}

filter_direct_node_list() {
	[ ! -s "$TMP_PATH/direct_node_list" ] && return
	for _node_id in $(cat $TMP_PATH/direct_node_list | awk '!seen[$0]++'); do
		filter_node "$_node_id" TCP
		filter_node "$_node_id" UDP
		unset _node_id
	done
}

update_wan_sets() {
	[ -z "$(command -v get_wan_ips)" ] && . "$UTILS_PATH"

	local WAN_IP=$(get_wan_ips ip4)
	[ -n "$WAN_IP" ] && {
		ipset -F "$IPSET_WAN"
		for wan_ip in $WAN_IP; do
			ipset -! add "$IPSET_WAN" "$wan_ip"
		done
	}

	local WAN6_IP=$(get_wan_ips ip6)
	[ -n "$WAN6_IP" ] && {
		ipset -F "$IPSET_WAN6"
		for wan6_ip in $WAN6_IP; do
			ipset -! add "$IPSET_WAN6" "$wan6_ip"
		done
	}
}

add_firewall_rule() {
	log_i18n 0 "Starting to load %s firewall rules..." "iptables"
	
	ipset -! create $IPSET_LOCAL nethash maxelem 1048576
	ipset -! create $IPSET_DIRECT nethash maxelem 1048576
	ipset -! create $IPSET_VPS iphash maxelem 1048576
	ipset -! create $IPSET_WAN nethash maxelem 1048576
	
	ipset -! create $IPSET_LOCAL6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_DIRECT6 nethash family inet6 maxelem 1048576
	ipset -! create $IPSET_VPS6 iphash family inet6 maxelem 1048576
	ipset -! create $IPSET_WAN6 nethash family inet6 maxelem 1048576

	get_local_ips ip4 | sed "s/^/add $IPSET_LOCAL /" | ipset -! -R
	get_local_ips ip6 | sed "s/^/add $IPSET_LOCAL6 /" | ipset -! -R

	for ip in $(cat /usr/share/passwall2/direct_ip | tr -s "\r\n" "\n" | grep -v "^#" | sed -e "/^$/d"); do
		if [[ "$ip" == *::* ]]; then
			ipset -! add $IPSET_DIRECT6 $ip
		elif [[ "$ip" == "geoip:"* ]]; then
			local _geoip_code=$(echo $ip | awk -F ':' '{print $2}')
			get_geoip $_geoip_code ipv4 | grep -E "(\.((2(5[0-5]|[0-4][0-9]))|[0-1]?[0-9]{1,2})){3}" | sed -e "s/^/add $IPSET_DIRECT &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
			get_geoip $_geoip_code ipv6 | grep -E "([A-Fa-f0-9]{1,4}::?){1,7}[A-Fa-f0-9]{1,4}" | sed -e "s/^/add $IPSET_DIRECT6 &/g" | awk '{print $0} END{print "COMMIT"}' | ipset -! -R
		else
			ipset -! add $IPSET_DIRECT $ip
		fi
	done

	# Ignore special IP ranges
	local lan_ifname lan_ip
	lan_ifname=$(uci -q -p /tmp/state get network.lan.ifname)
	[ -n "$lan_ifname" ] && {
		lan_ip=$(ip address show $lan_ifname | grep -w "inet" | awk '{print $2}')
		lan_ip6=$(ip address show $lan_ifname | grep -w "inet6" | awk '{print $2}')
		#log_i18n 1 "local network segments (%s) direct connection: %s" "IPv4" "${lan_ip}"
		#log_i18n 1 "local network segments (%s) direct connection: %s" "IPv6" "${lan_ip6}"

		[ -n "$lan_ip" ] && ipset -! -R <<-EOF
			$(echo $lan_ip | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_DIRECT /")
		EOF

		[ -n "$lan_ip6" ] && ipset -! -R <<-EOF
			$(echo $lan_ip6 | sed -e "s/ /\n/g" | sed -e "s/^/add $IPSET_DIRECT6 /")
		EOF
	}

	update_wan_sets

	[ -n "$ISP_DNS" ] && {
		for ispip in $ISP_DNS; do
			ipset -! add $IPSET_DIRECT $ispip
			log_i18n 1 "$(i18n "Add ISP %s DNS to the whitelist: %s" "IPv4" "${ispip}")"
		done
	}

	[ -n "$ISP_DNS6" ] && {
		for ispip6 in $ISP_DNS6; do
			ipset -! add $IPSET_DIRECT6 $ispip6
			log_i18n 1 "$(i18n "Add ISP %s DNS to the whitelist: %s" "IPv6" "${ispip6}")"
		done
	}

	# Filter all node IPs
	filter_vpsip > /dev/null 2>&1 &
	filter_haproxy > /dev/null 2>&1 &

	accept_icmp=$(config_n_get @global_forwarding[0] accept_icmp 0)
	accept_icmpv6=$(config_n_get @global_forwarding[0] accept_icmpv6 0)

	if [ "${TCP_PROXY_WAY}" = "redirect" ]; then
		unset is_tproxy
	elif [ "${TCP_PROXY_WAY}" = "tproxy" ]; then
		is_tproxy="TPROXY"
	fi

	if [ -z "${is_tproxy}" ] || [ "$accept_icmp" = "1" ]; then
		IPT_N=1
	fi

	if [ -z "${is_tproxy}" ] || [ "$accept_icmpv6" = "1" ]; then
		IP6T_N=1
	fi

	$ipt_n -N PSW2
	$ipt_n -A PSW2 $(dst $IPSET_VPS) -j RETURN
	$ipt_n -A PSW2 $(comment "WAN_IP_RETURN") $(dst $IPSET_WAN) -j RETURN
	
	[ "$accept_icmp" = "1" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p icmp -j PSW2"
	[ -z "${is_tproxy}" ] && insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p tcp -j PSW2"

	$ipt_n -N PSW2_OUTPUT
	$ipt_n -A PSW2_OUTPUT $(dst $IPSET_VPS) -j RETURN
	$ipt_n -A PSW2_OUTPUT -m mark --mark 255 -j RETURN

	$ipt_n -N PSW2_DNS
	if [ $(config_n_get @global[0] dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ipt_n -I PREROUTING -m set --match-set $IPSET_DIRECT src $(dst $IPSET_LOCAL) -j PSW2_DNS
	else
		$ipt_n -I PREROUTING -m set --match-set $IPSET_DIRECT src -j PSW2_DNS
	fi

	$ipt_m -N PSW2_RULE
	$ipt_m -A PSW2_RULE -j CONNMARK --restore-mark
	$ipt_m -A PSW2_RULE -m mark --mark ${FWMARK} -j RETURN
	$ipt_m -A PSW2_RULE -p tcp -m tcp --syn -j MARK --set-xmark ${FWMARK}
	$ipt_m -A PSW2_RULE -p udp -m conntrack --ctstate NEW,RELATED -j MARK --set-xmark ${FWMARK}
	$ipt_m -A PSW2_RULE -j CONNMARK --save-mark

	$ipt_m -N PSW2
	# Socket Only TCP, UDP Invalid.
	$ipt_m -A PSW2 -p tcp -m socket -j MARK --set-mark ${FWMARK}
	$ipt_m -A PSW2 -p tcp -m socket -j ACCEPT
	$ipt_m -A PSW2 $(dst $IPSET_VPS) -j RETURN
	$ipt_m -A PSW2 $(comment "WAN_IP_RETURN") $(dst $IPSET_WAN) -j RETURN
	$ipt_m -A PSW2 -m conntrack --ctdir REPLY -j RETURN

	insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT !) -j PSW2"

	$ipt_m -N PSW2_OUTPUT
	$ipt_m -A PSW2_OUTPUT $(dst $IPSET_VPS) -j RETURN
	$ipt_m -A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN
	$ipt_m -A PSW2_OUTPUT -m mark --mark 255 -j RETURN

	ip rule add fwmark ${FWMARK} table 999 priority 999
	ip route add local 0.0.0.0/0 dev lo table 999

	[ "$accept_icmpv6" = "1" ] && {
		$ip6t_n -N PSW2
		$ip6t_n -A PSW2 $(dst $IPSET_VPS6) -j RETURN
		$ip6t_n -A PREROUTING $(dst $IPSET_DIRECT6 !) -p ipv6-icmp -j PSW2

		$ip6t_n -N PSW2_OUTPUT
		$ip6t_n -A PSW2_OUTPUT $(dst $IPSET_VPS6) -j RETURN
		$ip6t_n -A PSW2_OUTPUT -m mark --mark 255 -j RETURN
	}
	
	$ip6t_n -N PSW2_DNS
	if [ $(config_n_get @global[0] dns_redirect "1") = "0" ]; then
		#Only hijack when dest address is local IP
		$ip6t_n -I PREROUTING -m set --match-set $IPSET_DIRECT6 src $(dst $IPSET_LOCAL6) -j PSW2_DNS
	else
		$ip6t_n -I PREROUTING -m set --match-set $IPSET_DIRECT6 src -j PSW2_DNS
	fi

	$ip6t_m -N PSW2_RULE
	$ip6t_m -A PSW2_RULE -j CONNMARK --restore-mark
	$ip6t_m -A PSW2_RULE -m mark --mark ${FWMARK} -j RETURN
	$ip6t_m -A PSW2_RULE -p tcp -m tcp --syn -j MARK --set-xmark ${FWMARK}
	$ip6t_m -A PSW2_RULE -p udp -m conntrack --ctstate NEW,RELATED -j MARK --set-xmark ${FWMARK}
	$ip6t_m -A PSW2_RULE -j CONNMARK --save-mark

	$ip6t_m -N PSW2
	# Socket Only TCP, UDP Invalid.
	$ip6t_m -A PSW2 -p tcp -m socket -j MARK --set-mark ${FWMARK}
	$ip6t_m -A PSW2 -p tcp -m socket -j ACCEPT
	$ip6t_m -A PSW2 $(dst $IPSET_VPS6) -j RETURN
	$ip6t_m -A PSW2 $(comment "WAN6_IP_RETURN") $(dst $IPSET_WAN6) -j RETURN
	$ip6t_m -A PSW2 -m conntrack --ctdir REPLY -j RETURN

	insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT6 !) -j PSW2"

	$ip6t_m -N PSW2_OUTPUT
	$ip6t_m -A PSW2_OUTPUT -m mark --mark 255 -j RETURN
	$ip6t_m -A PSW2_OUTPUT $(dst $IPSET_VPS6) -j RETURN
	$ip6t_m -A PSW2_OUTPUT -m conntrack --ctdir REPLY -j RETURN

	[ -n "$AUTO_DNS" ] && {
		for auto_dns in $(echo $AUTO_DNS | tr ',' ' '); do
			local dns_address=$(echo $auto_dns | awk -F '#' '{print $1}')
			local dns_port=$(echo $auto_dns | awk -F '#' '{print $2}')
			if [[ "$dns_address" == *::* ]]; then
				$ip6t_m -I PSW2_OUTPUT -p udp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				log_i18n 1 "$(i18n "Add direct DNS to %s: %s" "ip6tables" "[${dns_address}]:${dns_port:-53}")"
			else
				$ipt_m -I PSW2_OUTPUT -p udp -d ${dns_address} --dport ${dns_port:-53} -j RETURN
				log_i18n 1 "$(i18n "Add direct DNS to %s: %s" "iptables" "${dns_address}:${dns_port:-53}")"
			fi
		done
	}

	ip -6 rule add fwmark ${FWMARK} table 999 priority 999
	ip -6 route add local ::/0 dev lo table 999

	load_acl

	filter_direct_node_list > /dev/null 2>&1 &

	[ -z "${IPT_N}" ] && {
		for chain in "PSW2" "PSW2_OUTPUT"; do
			$ipt_n -F $chain 2>/dev/null
			$ipt_n -X $chain 2>/dev/null
		done
	}
	[ -z "${IP6T_N}" ] && {
		for chain in "PSW2" "PSW2_OUTPUT"; do
			$ip6t_n -F $chain 2>/dev/null
			$ip6t_n -X $chain 2>/dev/null
		done
	}

	log_i18n 0 "%s firewall rules load complete!" "iptables"
}

del_firewall_rule() {
	for ipt in "$ipt_n" "$ipt_m" "$ip6t_n" "$ip6t_m"; do
		for chain in "PREROUTING" "OUTPUT"; do
			for i in $(seq 1 $($ipt -nL $chain | grep -c PSW2)); do
				local index=$($ipt --line-number -nL $chain | grep PSW2 | head -1 | awk '{print $1}')
				$ipt -D $chain $index 2>/dev/null
			done
		done
		for chain in "PSW2" "PSW2_OUTPUT" "PSW2_DNS" "PSW2_RULE"; do
			$ipt -F $chain 2>/dev/null
			$ipt -X $chain 2>/dev/null
		done
	done

	ip rule del fwmark ${FWMARK} 2>/dev/null
	ip route del local 0.0.0.0/0 dev lo table 999 2>/dev/null

	ip -6 rule del fwmark ${FWMARK} 2>/dev/null
	ip -6 route del local ::/0 dev lo table 999 2>/dev/null

	log_i18n 0 "Delete %s rules is complete." "iptables"
}

flush_ipset() {
	log_i18n 0 "Clear %s." "IPSet"
	for _name in $(ipset list | grep "Name: " | grep "psw2_" | awk '{print $2}'); do
		destroy_ipset ${_name}
	done
}

flush_include() {
	echo '#!/bin/sh' >$FWI
}

gen_include() {
	flush_include
	extract_rules() {
		local _ipt="${ipt}"
		[ "$1" == "6" ] && _ipt="${ip6t}"
		[ -z "${_ipt}" ] && return

		echo "*$2"
		${_ipt}-save -t $2 | grep "PSW2" | grep -v "\-j PSW2$" | sed -e "s/^-A \(OUTPUT\|PREROUTING\)/-I \1 1/"
		echo 'COMMIT'
	}
	local __ipt=""
	[ -n "${ipt}" ] && {
		__ipt=$(cat <<- EOF
			${MY_PATH} update_wan_sets
			$ipt-save -c | grep -v "PSW2" | $ipt-restore -c
			$ipt-restore -n <<-EOT
			$(extract_rules 4 nat)
			$(extract_rules 4 mangle)
			EOT

			[ "$accept_icmp" = "1" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p icmp -j PSW2")
			[ -z "${is_tproxy}" ] && \$(${MY_PATH} insert_rule_after "$ipt_n" "PREROUTING" "prerouting_rule" "$(dst $IPSET_DIRECT !) -p tcp -j PSW2")

			\$(${MY_PATH} insert_rule_before "$ipt_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT !) -j PSW2")
		EOF
		)
	}
	local __ip6t=""
	[ -n "${ip6t}" ] && {
		__ip6t=$(cat <<- EOF
			${MY_PATH} update_wan_sets
			$ip6t-save -c | grep -v "PSW2" | $ip6t-restore -c
			$ip6t-restore -n <<-EOT
			$(extract_rules 6 nat)
			$(extract_rules 6 mangle)
			EOT

			[ "$accept_icmpv6" = "1" ] && $ip6t_n -A PREROUTING $(dst $IPSET_DIRECT6 !) -p ipv6-icmp -j PSW2

			\$(${MY_PATH} insert_rule_before "$ip6t_m" "PREROUTING" "mwan3" "$(dst $IPSET_DIRECT6 !) -j PSW2")
		EOF
		)
	}
	cat <<-EOF >> $FWI
		${__ipt}

		${__ip6t}
		
		return 0
	EOF
	return 0
}

get_ipt_bin() {
	echo $ipt
}

get_ip6t_bin() {
	echo $ip6t
}

start() {
	[ "$ENABLED_DEFAULT_ACL" == 0 -a "$ENABLED_ACLS" == 0 ] && return
	add_firewall_rule
	gen_include
}

stop() {
	[ -z "$(command -v log_i18n)" ] && . "$UTILS_PATH"
	del_firewall_rule
	[ $(config_n_get @global[0] flush_set "0") = "1" ] && {
		uci -q delete ${CONFIG}.@global[0].flush_set
		uci -q commit ${CONFIG}
		flush_ipset
		rm -rf $TMP_PATH2/singbox*
		rm -rf $TMP_PATH2/geo_output
	}
	flush_include
}

arg1=$1
shift
case $arg1 in
RULE_LAST_INDEX)
	RULE_LAST_INDEX "$@"
	;;
insert_rule_before)
	insert_rule_before "$@"
	;;
insert_rule_after)
	insert_rule_after "$@"
	;;
get_ipt_bin)
	get_ipt_bin
	;;
get_ip6t_bin)
	get_ip6t_bin
	;;
filter_direct_node_list)
	filter_direct_node_list
	;;
update_wan_sets)
	update_wan_sets "$@"
	;;
stop)
	stop
	;;
start)
	start
	;;
*) ;;
esac
