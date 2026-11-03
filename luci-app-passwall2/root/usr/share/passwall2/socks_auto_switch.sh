#!/bin/sh

. /usr/share/passwall2/utils.sh
APP_FILE=${APP_PATH}/app.sh

check_process() {
	while busybox pgrep -af "${CONFIG}/" | grep -E 'app\.sh.*(start|stop)|nftables\.sh|iptables\.sh|subscribe\.lua' >/dev/null; do
		sleep 6s 8>&- 9>&-
	done
}

test_url() {
	local url="$1"
	local try="${2:-1}"
	local timeout="${3:-2}"
	local extra_params="$4"
	local repeat="$5"

	if [ -z "$curl_retry_all_errors" ]; then
		if /usr/bin/curl --help all | grep -q "\-\-retry-all-errors"; then
			curl_retry_all_errors=1
		fi
	fi
	[ "$curl_retry_all_errors" = "1" ] && extra_params="--retry-all-errors ${extra_params}"

	local max_time=$((timeout + 3))
	local retry_max_time=$((max_time * (try + 1) + try))
	curl_test() {
		/usr/bin/curl -skIL -o /dev/null ${extra_params} --max-time ${max_time} --connect-timeout ${timeout} --retry ${try} --retry-delay 1 --retry-max-time ${retry_max_time} -w "%{http_code}" "$url" 8>&- 9>&-
	}

	local status
	status=$(curl_test) || status=000
	[ "$status" = "204" ] && status=200
	if [ "$status" = "200" ] && [ "$repeat" = "1" ]; then
		sleep 3s 8>&- 9>&-
		status=$(curl_test) || status=000
		[ "$status" = "204" ] && status=200
	fi
	printf '%s' "$status"
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
			ping -c 3 -W 1 223.5.5.5 > /dev/null 2>&1 8>&- 9>&-
			[ $? -eq 0 ] && {
				result=1
			}
		fi
	fi
	echo $result
}

test_node() {
	local node_id=$1
	local test_flag="test_node_${id}_${node_id}"
	local _type _tmp_port curlx _proxy_status pid_file
	(
		exec 9>&-
		exec 8>"${LOCK_PATH}/${CONFIG}_socks_auto_switch_test.lock"
		flock -x 8 || exit 1
		_type=$(echo $(config_n_get ${node_id} type) | tr 'A-Z' 'a-z')
		[ -n "${_type}" ] && {
			check_process
			_tmp_port=$(get_new_port 48800 tcp,udp) || exit 1
			NO_REC_PROCESS=1 "$APP_FILE" run_socks flag="$test_flag" node="$node_id" bind=127.0.0.1 socks_port="$_tmp_port" config_file="${test_flag}.json" 8>&- 9>&-
			sleep 2s 8>&- 9>&-
			curlx="socks5h://127.0.0.1:${_tmp_port}"
			_proxy_status=$(test_url "${probe_url}" ${retry_num} ${connect_timeout} "-x $curlx" 1)
			# Kill the SS plugin process.
			pid_file="${TMP_PATH}/${test_flag}_plugin.pid"
			[ -s "$pid_file" ] && kill -9 "$(head -n 1 "$pid_file")" >/dev/null 2>&1
			busybox pgrep -af "${TMP_PATH}/${test_flag}[._]" | awk '! /socks_auto_switch\.sh/{print $1}' | xargs -r kill -9 >/dev/null 2>&1
			rm -f "$TMP_PATH/${test_flag}"*.*
			if [ "${_proxy_status}" -eq 200 ]; then
				exit 0
			fi
		}
		exit 1
	)
}

try_switch_backup() {
	local b_nodes="$1"
	local now_node="$2"
	local total tried
	local new_node msg
	local first_node found node

	# Only one backup node, alternate with the primary node.
	if [ "$backup_node_num" -eq 1 ]; then
		b_nodes="$b_nodes $main_node"
	fi

	total=$(printf "%s\n" "$b_nodes" | wc -w)
	tried=0

	while [ "$tried" -lt "$total" ]; do
		new_node=""
		first_node=""
		found=""
		for node in $b_nodes; do
			[ -z "$first_node" ] && first_node="$node"         # Record first node.
			[ "$found" = "1" ] && { new_node="$node"; break; } # Find the current node and then get the next one.
			[ "$node" = "$now_node" ] && found=1               # flag the found current node.
		done
		# If the current node is not found, or if it is the last node, select the first node.
		[ -z "$new_node" ] && new_node="$first_node"

		local node_role node_type node_remarks
		if [ "$new_node" = "$main_node" ]; then
			node_role="$(i18n "main node")"
		else
			node_role="$(i18n "next backup node")"
		fi
		node_type=$(config_n_get $new_node type)
		node_remarks=$(config_n_get $new_node remarks)
		log_i18n 0 "Socks switch detection: Port [%s] try %s [%s:%s]." "${socks_port}" "${node_role}" "${node_type}" "${node_remarks}"

		if test_node ${new_node}; then
			check_process
			log_i18n 0 "Socks switch detection: Port [%s] [%s:[%s]] normal, switch to this node!" "${socks_port}" "${node_type}" "${node_remarks}"
			if NO_REC_PROCESS=1 "$APP_FILE" socks_node_switch flag="$id" new_node="$new_node" 9>&-; then
				log_i18n 0 "Socks switch detection: Port [%s] node switch complete!" "${socks_port}"
				return 0
			fi
			log_i18n 0 "Socks switch detection: Port [%s] node switch failed, continue trying other nodes!" "${socks_port}"
		else
			log_i18n 0 "Socks switch detection: Port [%s] [%s:[%s]] abnormal." "${socks_port}" "${node_type}" "${node_remarks}"
		fi
		now_node="$new_node"
		tried=$((tried + 1))
	done

	log_i18n 0 "Socks switch detection: Port [%s] all nodes are unavailable or switching failed!" "${socks_port}"
	return 1
}

test_auto_switch() {
	local b_nodes=$1
	local now_node=$2
	[ -z "$now_node" ] && {
		if [ -n "$(get_cache_var "${id}")" ]; then
			now_node=$(get_cache_var "${id}")
		else
			#log_i18n 0 "Socks switch detection: Port [%s] Unknown error." "${socks_port}"
			return 1
		fi
	}

	local status=$(test_proxy 9>&-)
	if [ "$status" = "2" ]; then
		log_i18n 0 "Socks switch detection: Port [%s] Unable to connect to the network. Please check if the network is working properly!" "${socks_port}"
		return 2
	fi

	# Check if the main node is usable
	if [ "$restore_switch" = "1" ] && [ -n "$main_node" ] && [ "$now_node" != "$main_node" ]; then
		test_node ${main_node}
		[ $? -eq 0 ] && {
			check_process
			log_i18n 0 "Socks switch detection: Port [%s] Primary node [%s: [%s]] is normal. Switch to the primary node!" "${socks_port}" "$(config_n_get $main_node type)" "$(config_n_get $main_node remarks)"
			if NO_REC_PROCESS=1 "$APP_FILE" socks_node_switch flag="$id" new_node="$main_node" 9>&-; then
				log_i18n 0 "Socks switch detection: Port [%s] node switch complete!" "${socks_port}"
				return 0
			fi
			log_i18n 0 "Socks switch detection: Port [%s] failed to restore the primary node!" "${socks_port}"
			status=1
		}
	fi

	[ "$status" = "0" ] && {
		#log_i18n 0 "Socks switch detection: Port [%s] [%s:[%s]] normal." "${socks_port}" "$(config_n_get $now_node type)" "$(config_n_get $now_node remarks)"
		return 0
	}

	log_i18n 0 "Socks switch detection: Port [%s] [%s:[%s]] abnormal." "${socks_port}" "$(config_n_get $now_node type)" "$(config_n_get $now_node remarks)"
	try_switch_backup "$b_nodes" "$now_node"
	return $?
}

start() {
	id=$1
	LOCK_FILE=${LOCK_PATH}/${CONFIG}_socks_auto_switch_${id}.lock
	exec 9>"$LOCK_FILE"
	flock -n 9 || return 0
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
		log_i18n 0 "Socks switch detection: Port [%s] Number of backup nodes: %s" "${socks_port}" "${backup_node_num}"
		if [ "$backup_node_num" -eq 1 ]; then
			[ "$main_node" = "$backup_node" ] && return
		elif [ "$backup_node_num" -gt 1 ]; then
			[ "$restore_switch" != "1" ] && {
				case " $backup_node " in
					*" $main_node "*) ;;
					*) backup_node="${backup_node} ${main_node}" ;;
				esac
			}
		fi
	else
		log_i18n 0 "Socks switch detection: Port [%s] Number of backup nodes: %s" "${socks_port}" "0"
		return
	fi
	while [ -n "$backup_node" ]; do
		check_process
		test_auto_switch "$backup_node"
		sleep ${delay} 9>&-
	done
}

start $@
