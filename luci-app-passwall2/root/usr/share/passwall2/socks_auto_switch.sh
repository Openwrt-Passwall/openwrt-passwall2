#!/bin/sh

. /usr/share/passwall2/utils.sh
APP_FILE=${APP_PATH}/app.sh

flag=0

check_process() {
	while busybox pgrep -af "${CONFIG}/" | grep -E 'app\.sh.*(start|stop)|nftables\.sh|iptables\.sh|subscribe\.lua' >/dev/null; do
		sleep 6s
	done
}

test_url() {
	local url=$1
	local try=1
	[ -n "$2" ] && try=$2
	local timeout=2
	[ -n "$3" ] && timeout=$3
	local extra_params=$4
	if /usr/bin/curl --help all | grep -q "\-\-retry-all-errors"; then
		extra_params="--retry-all-errors ${extra_params}"
	fi
	local status=$(/usr/bin/curl -I -o /dev/null -skL ${extra_params} --connect-timeout ${timeout} --retry ${try} -w %{http_code} "$url")
	case "$status" in
		204)
			status=200
		;;
	esac
	echo $status
}

test_proxy() {
	local result=0
	local status=$(test_url "${probe_url}" ${retry_num} ${connect_timeout} "-x socks5h://127.0.0.1:${socks_port}")
	if [ "$status" = "200" ]; then
		result=0
	else
		local status2=$(test_url "https://www.baidu.com" ${retry_num} ${connect_timeout})
		if [ "$status2" = "200" ]; then
			result=1
		else
			result=2
			ping -c 3 -W 1 119.29.29.29 > /dev/null 2>&1
			[ $? -eq 0 ] && {
				result=1
			}
		fi
	fi
	echo $result
}

test_node() {
	local node_id=$1
	local _type=$(echo $(config_n_get ${node_id} type) | tr 'A-Z' 'a-z')
	[ -n "${_type}" ] && {
		check_process
		local _tmp_port=$(get_new_port 48800 tcp,udp)
		NO_REC_PROCESS=1 $APP_FILE run_socks flag="test_node_${node_id}" node=${node_id} bind=127.0.0.1 socks_port=${_tmp_port} config_file=test_node_${node_id}.json
		sleep 2s
		local curlx="socks5h://127.0.0.1:${_tmp_port}"
		local _proxy_status=$(test_url "${probe_url}" ${retry_num} ${connect_timeout} "-x $curlx")
		# Kill the SS plugin process
		local pid_file="/tmp/etc/${CONFIG}/test_node_${node_id}_plugin.pid"
		[ -s "$pid_file" ] && kill -9 "$(head -n 1 "$pid_file")" >/dev/null 2>&1
		busybox pgrep -af "test_node_${node_id}" | awk '! /socks_auto_switch\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf /tmp/etc/${CONFIG}/test_node_${node_id}*.*
		if [ "${_proxy_status}" -eq 200 ]; then
			return 0
		fi
	}
	return 1
}

test_auto_switch() {
	flag=$((flag + 1))
	local b_nodes=$1
	local now_node=$2
	[ -z "$now_node" ] && {
		if [ -n "$(get_cache_var "socks_${id}")" ]; then
			now_node=$(get_cache_var "socks_${id}")
		else
			#log_i18n 0 "Socks switch detection: Unknown error."
			return 1
		fi
	}
	
	[ $flag -le 1 ] && {
		main_node=$now_node
	}

	local status=$(test_proxy)
	if [ "$status" = "2" ]; then
		log_i18n 0 "Socks switch detection: Unable to connect to the network. Please check if the network is working properly!"
		return 2
	fi

	# Check if the main node is usable
	if [ "$restore_switch" = "1" ] && [ -n "$main_node" ] && [ "$now_node" != "$main_node" ]; then
		test_node ${main_node}
		[ $? -eq 0 ] && {
			check_process
			# The main node is working properly; switch to the main node.
			log_i18n 0 "Socks switch detection: Primary node 【%s: [%s]】 is normal. Switch to the primary node!" "${id}" "$(config_n_get $main_node type)" "$(config_n_get $main_node remarks)"
			$APP_FILE socks_node_switch flag=${id} new_node=${main_node}
			[ $? -eq 0 ] && {
				log_i18n 0 "Socks switch detection: %s node switch complete!" "${id}"
			}
			return 0
		}
	fi

	if [ "$status" = "0" ]; then
		#log_i18n 0 "Socks switch detection: %s 【%s:[%s]】 normal." "${id}" "$(config_n_get $now_node type)" "$(config_n_get $now_node remarks)"
		return 0
	elif [ "$status" = "1" ]; then
		local new_node msg
		if [ "$backup_node_num" -gt 1 ]; then
			# When there are multiple backup nodes
			local first_node found node
			for node in $b_nodes; do
				[ -z "$first_node" ] && first_node="$node"       # Record the first node.
				[ "$found" = "1" ] && { new_node="$node"; break; } # Find the current node and then retrieve the next one.
				[ "$node" = "$now_node" ] && found=1             # Mark the current node found.
			done
			# If the current node is not found, or if the current node is the last node, then take the first node.
			[ -z "$new_node" ] && new_node="$first_node"
			local msg2="$(i18n "next backup node")"
			[ "$now_node" = "$main_node" ] && msg2="$(i18n "backup node")"
			msg="$(i18n "switch to %s test detect!" "${msg2}")"
		else
			# When there is only one backup node, poll with the primary node.
			new_node=$([ "$now_node" = "$main_node" ] && echo "$b_nodes" || echo "$main_node")
			local msg2="$(i18n "main node")"
			[ "$now_node" = "$main_node" ] && msg2="$(i18n "backup node")"
			msg="$(i18n "switch to %s test detect!" "${msg2}")"
		fi
		log_i18n 0 "Socks switch detection: %s 【%s:[%s]】 abnormal, %s" "${id}" "$(config_n_get $now_node type)" "$(config_n_get $now_node remarks)" "${msg}"
		test_node ${new_node}
		if [ $? -eq 0 ]; then
#			[ "$restore_switch" = "0" ] && {
#				uci set $CONFIG.${id}.node=$new_node
#				[ -z "$(echo $b_nodes | grep $main_node)" ] && uci add_list $CONFIG.${id}.autoswitch_backup_node=$main_node
#				uci commit $CONFIG
#			}
			check_process
			log_i18n 0 "Socks switch detection: %s 【%s:[%s]】 normal, switch to this node!" "${id}" "$(config_n_get $new_node type)" "$(config_n_get $new_node remarks)"
			$APP_FILE socks_node_switch flag=${id} new_node=${new_node}
			[ $? -eq 0 ] && {
				log_i18n 0 "Socks switch detection: %s node switch complete!" "${id}"
			}
			return 0
		else
			test_auto_switch "${b_nodes}" ${new_node}
		fi
	fi
}

start() {
	id=$1
	LOCK_FILE=${LOCK_PATH}/${CONFIG}_socks_auto_switch_${id}.lock
	main_node=$(config_n_get $id node)
	socks_port=$(config_n_get $id port 0)
	delay=$(config_n_get $id autoswitch_testing_time 30)
	connect_timeout=$(config_n_get $id autoswitch_connect_timeout 3)
	retry_num=$(config_n_get $id autoswitch_retry_num 1)
	restore_switch=$(config_n_get $id autoswitch_restore_switch 0)
	probe_url=$(config_n_get $id autoswitch_probe_url "https://www.google.com/generate_204")
	backup_node=$(lua_api "get_socks_backup_nodes(\"${id}\")")
	if [ -n "$backup_node" ]; then
		backup_node_num=$(printf "%s\n" "$backup_node" | wc -w)
		if [ "$backup_node_num" -eq 1 ]; then
			[ "$main_node" = "$backup_node" ] && return
		fi
	else
		return
	fi
	while [ -n "$backup_node" ]; do
		[ -f "$LOCK_FILE" ] && {
			sleep 6s
			continue
		}
		check_process
		touch $LOCK_FILE
		test_auto_switch "$backup_node"
		rm -f $LOCK_FILE
		sleep ${delay}
	done
}

start $@
