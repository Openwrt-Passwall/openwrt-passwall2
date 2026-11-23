#!/bin/sh

. /usr/share/passwall2/utils.sh

test_url() {
	local url=$1
	local try=1
	[ -n "$2" ] && try=$2
	local timeout=2
	[ -n "$3" ] && timeout=$3
	local extra_params=$4
	curl --help all | grep "\-\-retry-all-errors" > /dev/null
	[ $? == 0 ] && extra_params="--retry-all-errors ${extra_params}"
	status=$(/usr/bin/curl -I -o /dev/null -skL $extra_params --connect-timeout ${timeout} --retry ${try} -w %{http_code} "$url")
	case "$status" in
		204|\
		200)
			status=200
		;;
	esac
	echo $status
}

test_proxy() {
	result=0
	status=$(test_url "https://www.google.com/generate_204" ${retry_num} ${connect_timeout})
	if [ "$status" = "200" ]; then
		result=0
	else
		status2=$(test_url "https://www.baidu.com" ${retry_num} ${connect_timeout})
		if [ "$status2" = "200" ]; then
			result=1
		else
			result=2
			ping -c 3 -W 1 223.5.5.5 > /dev/null 2>&1
			[ $? -eq 0 ] && {
				result=1
			}
		fi
	fi
	echo $result
}

url_test_node() (
	local result=0
	local node_id=$1
	local test_flag="url_test_${node_id}_$$"
	local _tmp_port
	local _type=$(echo $(config_n_get ${node_id} type) | tr 'A-Z' 'a-z')
	[ -n "${_type}" ] && {
		# Serialize port selection and startup with other temporary node tests.
		exec 8>"${LOCK_PATH}/${CONFIG}_socks_auto_switch_test.lock"
		flock -x 8 || { echo 0; return 1; }
		_tmp_port=$(get_new_port 48900 tcp,udp) || { echo 0; return 1; }
		NO_REC_PROCESS=1 /usr/share/${CONFIG}/app.sh run_socks flag="$test_flag" node="$node_id" bind=127.0.0.1 socks_port="$_tmp_port" config_file="${test_flag}.json" 8>&-
		local curlx="socks5h://127.0.0.1:${_tmp_port}"
		sleep 2s 8>&-
		# Once listening, the socket itself prevents the next test from reusing the port.
		# Keep the lock through cleanup if startup is still pending or has failed.
		if [ "$(check_port_exists "$_tmp_port" tcp)" -gt 0 ]; then
			flock -u 8
			exec 8>&-
		fi
		local probeUrl=$(config_n_get @global_other[0] url_test_url https://www.google.com/generate_204)
		# Warm up the proxy connection to reduce cold-start effects on latency tests.
		curl --connect-timeout 3 --max-time 5 -o /dev/null -I -sk -A 'Mozilla/5.0' -x "$curlx" "$probeUrl" >/dev/null 2>&1
		result=$(curl --connect-timeout 3 --max-time 5 -o /dev/null -I -skL -A 'Mozilla/5.0' -w "%{http_code}:%{time_pretransfer}" -x ${curlx} "${probeUrl}")
		# End the SS plugin process
		local pid_file="${TMP_PATH}/${test_flag}_plugin.pid"
		[ -s "$pid_file" ] && kill -9 "$(head -n 1 "$pid_file")" >/dev/null 2>&1
		busybox pgrep -af "${TMP_PATH}/${test_flag}[._]" | awk '! /test\.sh/{print $1}' | xargs -r kill -9 >/dev/null 2>&1
		rm -f "$TMP_PATH/${test_flag}"*.*
	}
	echo $result
)

arg1=$1
shift
case $arg1 in
test_url)
	test_url $@
	;;
url_test_node)
	url_test_node $@
	;;
esac
