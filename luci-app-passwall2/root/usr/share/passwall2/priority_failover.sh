#!/bin/sh

. /usr/share/libubox/jshn.sh
. /usr/share/passwall2/utils.sh

CONFIG_FILE="$1"
[ -s "$CONFIG_FILE" ] || exit 1

RUNTIME_NAME="$(basename "$CONFIG_FILE" .json)"
STATE_FILE="${CONFIG_FILE%.json}.state"
READY_FILE="${CONFIG_FILE%.json}.ready"
XRAY_BIN="$(first_type "$(config_t_get global_app xray_file)" xray)"
[ -x "$XRAY_BIN" ] || exit 1

normalize_failure_threshold() {
	case "$1" in
		2|3|4|5) printf '%s\n' "$1" ;;
		*) printf '%s\n' 2 ;;
	esac
}

sanitize_probe_url() {
	printf '%s' "$1" |
		tr '\r\n\t' '___' |
		awk '
			function first_delimiter(value, question, fragment) {
				question = index(value, "?")
				fragment = index(value, "#")
				if (!question) return fragment
				if (!fragment || question < fragment) return question
				return fragment
			}
			function last_at(value, found, offset) {
				offset = 0
				while ((found = index(substr(value, offset + 1), "@")) > 0) offset += found
				return offset
			}
			{
				url = $0
				gsub(/[[:space:]]/, "_", url)
				prefix = ""
				rest = url
				if (match(rest, /^[[:alpha:]][[:alnum:]+.-]*:\/\//)) {
					prefix = substr(rest, 1, RLENGTH)
					rest = substr(rest, RLENGTH + 1)
				} else if (substr(rest, 1, 2) == "//") {
					prefix = "//"
					rest = substr(rest, 3)
				}
				slash = index(rest, "/")
				if (slash) {
					authority = substr(rest, 1, slash - 1)
					suffix = substr(rest, slash)
				} else {
					authority = rest
					suffix = ""
				}
				at = last_at(authority)
				delimiter = first_delimiter(authority)
				if (at && delimiter && delimiter < at) {
					print prefix "[redacted]"
					next
				}
				if (at) authority = substr(authority, at + 1)
				sanitized = prefix authority suffix
				delimiter = first_delimiter(sanitized)
				if (delimiter) sanitized = substr(sanitized, 1, delimiter - 1)
				print sanitized
			}'
}

monotonic_seconds() {
	local uptime_seconds ignored
	read -r uptime_seconds ignored < /proc/uptime || return 1
	uptime_seconds=${uptime_seconds%%.*}
	case "$uptime_seconds" in
		''|*[!0-9]*) return 1 ;;
	esac
	printf '%s\n' "$uptime_seconds"
}

elapsed_seconds() {
	if [ "$1" -ge "$2" ]; then
		printf '%s\n' "$(( $1 - $2 ))"
	else
		printf '%s\n' 0
	fi
}

load_config() {
	json_cleanup
	json_load "$(cat "$CONFIG_FILE")" || return 1
	json_get_var FAILOVER_ID id
	json_get_var XRAY_CONFIG_FILE xray_config_file
	json_get_var API_PORT api_port
	json_get_var PROBE_PORT probe_port
	json_get_var MAIN_BALANCER main_balancer
	json_get_var PROBE_BALANCER probe_balancer
	json_get_var PRIMARY_ID primary_id
	json_get_var PRIMARY_TAG primary_tag
	json_get_var DIRECT_FALLBACK direct_fallback
	json_get_var RESTORE_PRIMARY restore_primary
	json_get_var CHECK_INTERVAL check_interval
	json_get_var CONNECT_TIMEOUT connect_timeout
	json_get_var FAILURE_THRESHOLD failure_threshold
	json_get_var MINIMUM_FAILURE_DURATION minimum_failure_duration
	json_get_var RECOVERY_INTERVAL recovery_interval
	json_get_var RECOVERY_SUCCESSES recovery_successes
	json_get_var MINIMUM_DWELL minimum_dwell
	json_get_var PRIMARY_URL primary_url
	json_get_var SECONDARY_URL secondary_url

	CHECK_INTERVAL=${CHECK_INTERVAL:-20}
	CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-3}
	FAILURE_THRESHOLD="$(normalize_failure_threshold "${FAILURE_THRESHOLD:-2}")"
	MINIMUM_FAILURE_DURATION=${MINIMUM_FAILURE_DURATION:-10}
	RECOVERY_INTERVAL=${RECOVERY_INTERVAL:-300}
	RECOVERY_SUCCESSES=${RECOVERY_SUCCESSES:-2}
	MINIMUM_DWELL=${MINIMUM_DWELL:-600}
	PRIMARY_URL=${PRIMARY_URL:-https://www.gstatic.com/generate_204}
	SECONDARY_URL=${SECONDARY_URL:-https://cp.cloudflare.com/generate_204}
}

log_event() {
	logger -t passwall2-failover "[$FAILOVER_ID] $*"
}

override_balancer() {
	local balancer="$1"
	local outbound="$2"
	"$XRAY_BIN" api bo --server="127.0.0.1:${API_PORT}" -b "$balancer" "$outbound" >/dev/null 2>&1
}

get_core_pid() {
	[ -n "$XRAY_CONFIG_FILE" ] || return 1
	busybox pgrep -af 'run -c' 2>/dev/null | awk -v config="$XRAY_CONFIG_FILE" \
		'index($0, "run -c " config) { print $1; exit }'
}

write_state() {
	local reason="$1"
	STATE_REASON="$reason"
	printf '{"id":"%s","state":"%s","current_id":"%s","current_tag":"%s","reason":"%s","switched_at":%s,"switched_monotonic":%s,"failure_count":%s,"first_failure_at":%s,"last_failed_id":"%s","last_failure_count":%s,"last_failure_started_at":%s}\n' \
		"$FAILOVER_ID" "$STATE" "$CURRENT_ID" "$CURRENT_TAG" "$reason" "$SWITCHED_AT" \
		"${SWITCHED_MONOTONIC:-0}" "${ACTIVE_FAILURES:-0}" "${FIRST_FAILURE_AT:-0}" \
		"${LAST_FAILED_ID:-}" "${LAST_FAILURE_COUNT:-0}" "${LAST_FAILURE_STARTED_AT:-0}" > "$STATE_FILE"
}

set_main() {
	local node_id="$1"
	local node_tag="$2"
	local state="$3"
	local reason="$4"
	local previous_id="$CURRENT_ID"
	local previous_failures="${ACTIVE_FAILURES:-0}"
	local failure_started="${FIRST_FAILURE_AT:-0}"
	local switched_monotonic
	switched_monotonic="$(monotonic_seconds)" || return 1
	override_balancer "$MAIN_BALANCER" "$node_tag" || return 1
	if [ "$previous_failures" -gt 0 ]; then
		LAST_FAILED_ID="$previous_id"
		LAST_FAILURE_COUNT="$previous_failures"
		LAST_FAILURE_STARTED_AT="$failure_started"
	fi
	CURRENT_ID="$node_id"
	CURRENT_TAG="$node_tag"
	STATE="$state"
	SWITCHED_AT="$(date +%s)"
	SWITCHED_MONOTONIC="$switched_monotonic"
	ACTIVE_FAILURES=0
	FIRST_FAILURE_AT=0
	FIRST_FAILURE_MONOTONIC=0
	RECOVERY_COUNT=0
	write_state "$reason"
	log_event "state=$STATE node=$CURRENT_ID previous_node=$previous_id reason=$reason failure_count=$previous_failures first_failure_at=$failure_started"
}

probe_url() {
	local node_id="$1"
	local url="$2"
	local result curl_exit code remainder time_connect time_appconnect time_total sanitized_url
	result="$(/usr/bin/curl -o /dev/null -sS -L \
		--connect-timeout "$CONNECT_TIMEOUT" \
		--max-time "$((CONNECT_TIMEOUT + 3))" \
		--proxy "socks5h://127.0.0.1:${PROBE_PORT}" \
		-w '%{http_code}|%{time_connect}|%{time_appconnect}|%{time_total}' "$url" 2>/dev/null)"
	curl_exit=$?
	code=${result%%|*}
	remainder=${result#*|}
	time_connect=${remainder%%|*}
	remainder=${remainder#*|}
	time_appconnect=${remainder%%|*}
	time_total=${remainder#*|}
	case "$code" in
		2??) return 0 ;;
		*)
			sanitized_url="$(sanitize_probe_url "$url")"
			log_event "reason=probe-endpoint-failed node=$node_id url=$sanitized_url curl_exit=$curl_exit http_code=${code:-000} time_connect=${time_connect:-0} time_appconnect=${time_appconnect:-0} time_total=${time_total:-0}"
			return 1
			;;
	esac
}

probe_tag() {
	local node_id="$1"
	local node_tag="$2"
	if ! override_balancer "$PROBE_BALANCER" "$node_tag"; then
		log_event "reason=node-failed node=$node_id phase=probe-balancer-override"
		return 1
	fi
	probe_url "$node_id" "$PRIMARY_URL" && return 0
	probe_url "$node_id" "$SECONDARY_URL"
}

route_carrier_down() {
	local device="$1"
	local carrier
	[ -r "/sys/class/net/${device}/carrier" ] || return 1
	carrier="$(cat "/sys/class/net/${device}/carrier" 2>/dev/null)"
	[ "$carrier" = "0" ]
}

gateway_ping() {
	local family="$1"
	local device="$2"
	local gateway="$3"
	if [ "$family" = "6" ]; then
		ping -6 -I "$device" -c 1 -W 1 "$gateway" >/dev/null 2>&1
	else
		ping -4 -I "$device" -c 1 -W 1 "$gateway" >/dev/null 2>&1
	fi
}

wan_candidate_available() {
	local family="$1"
	local device="$2"
	local gateway="$3"
	WAN_FAMILY="$family"
	WAN_DEVICE="$device"
	WAN_GATEWAY="$gateway"
	route_carrier_down "$device" && return 1
	if [ -n "$gateway" ] && ! gateway_ping "$family" "$device" "$gateway"; then
		WAN_DETAIL="gateway-ping-unanswered"
	else
		WAN_DETAIL="available"
	fi
	return 0
}

wan_available() {
	local routes entry family route device gateway token route_has_nexthop
	local route_count=0
	local device_count=0
	WAN_DEVICE=""
	WAN_GATEWAY=""
	WAN_FAMILY=""
	WAN_DETAIL=""
	routes="$({
		ip -4 route show default 2>/dev/null | sed 's/^/4|/'
		ip -6 route show default 2>/dev/null | sed 's/^/6|/'
	})"

	while IFS= read -r entry; do
		[ -n "$entry" ] || continue
		family=${entry%%|*}
		route=${entry#*|}
		route_count=$((route_count + 1))
		device=""
		gateway=""
		route_has_nexthop=0
		set -- $route
		while [ "$#" -gt 0 ]; do
			token="$1"
			shift
			case "$token" in
				nexthop)
					if [ "$route_has_nexthop" -eq 1 ] && [ -n "$device" ]; then
						device_count=$((device_count + 1))
						wan_candidate_available "$family" "$device" "$gateway" && return 0
					fi
					route_has_nexthop=1
					device=""
					gateway=""
					;;
				dev)
					[ "$#" -gt 0 ] || break
					device="$1"
					shift
					;;
				via)
					[ "$#" -gt 0 ] || break
					gateway="$1"
					shift
					case "$gateway" in
						inet|inet6)
							[ "$#" -gt 0 ] || { gateway=""; break; }
							gateway="$1"
							shift
							;;
					esac
					;;
			esac
		done
		[ -n "$device" ] || continue
		device_count=$((device_count + 1))
		wan_candidate_available "$family" "$device" "$gateway" && return 0
	done <<-EOF
	$routes
	EOF

	if [ "$route_count" -eq 0 ]; then
		WAN_DETAIL="no-default-route"
	elif [ "$device_count" -eq 0 ]; then
		WAN_DETAIL="no-default-device"
	else
		WAN_DETAIL="carrier-down"
	fi
	return 1
}

candidate_tag() {
	local wanted_id="$1"
	local keys key node_id node_tag
	json_select candidates || return 1
	json_get_keys keys
	for key in $keys; do
		json_select "$key"
		json_get_var node_id id
		json_get_var node_tag tag
		json_select ..
		if [ "$node_id" = "$wanted_id" ]; then
			json_select ..
			printf '%s' "$node_tag"
			return 0
		fi
	done
	json_select ..
	return 1
}

find_healthy_candidate() {
	local skip_id="$1"
	local keys key node_id node_tag
	json_select candidates || return 1
	json_get_keys keys
	for key in $keys; do
		json_select "$key"
		json_get_var node_id id
		json_get_var node_tag tag
		json_select ..
		[ "$node_id" = "$skip_id" ] && continue
		if probe_tag "$node_id" "$node_tag"; then
			json_select ..
			printf '%s|%s' "$node_id" "$node_tag"
			return 0
		fi
	done
	json_select ..
	return 1
}

backoff_seconds() {
	case "$1" in
		0) echo 15 ;;
		1) echo 30 ;;
		2) echo 60 ;;
		3) echo 120 ;;
		*) echo 300 ;;
	esac
}

restore_previous_state() {
	[ -s "$STATE_FILE" ] || return 1
	local saved_id saved_tag saved_state saved_switched saved_switched_monotonic
	local saved_last_failed_id saved_last_failure_count saved_last_failure_started_at
	local now_monotonic candidate
	saved_id="$(jsonfilter -i "$STATE_FILE" -e '@.current_id' 2>/dev/null)"
	saved_tag="$(jsonfilter -i "$STATE_FILE" -e '@.current_tag' 2>/dev/null)"
	saved_state="$(jsonfilter -i "$STATE_FILE" -e '@.state' 2>/dev/null)"
	saved_switched="$(jsonfilter -i "$STATE_FILE" -e '@.switched_at' 2>/dev/null)"
	saved_switched_monotonic="$(jsonfilter -i "$STATE_FILE" -e '@.switched_monotonic' 2>/dev/null)"
	saved_last_failed_id="$(jsonfilter -i "$STATE_FILE" -e '@.last_failed_id' 2>/dev/null || true)"
	saved_last_failure_count="$(jsonfilter -i "$STATE_FILE" -e '@.last_failure_count' 2>/dev/null || true)"
	saved_last_failure_started_at="$(jsonfilter -i "$STATE_FILE" -e '@.last_failure_started_at' 2>/dev/null || true)"
	now_monotonic="$(monotonic_seconds)" || return 1
	case "$saved_switched_monotonic" in
		''|*[!0-9]*) saved_switched_monotonic="$now_monotonic" ;;
	esac
	case "$saved_last_failure_count" in
		''|*[!0-9]*) saved_last_failure_count=0 ;;
	esac
	case "$saved_last_failure_started_at" in
		''|*[!0-9]*) saved_last_failure_started_at=0 ;;
	esac
	[ "$saved_switched_monotonic" -le "$now_monotonic" ] || saved_switched_monotonic="$now_monotonic"
	case "$saved_id" in
		direct) [ "$DIRECT_FALLBACK" = "1" ] || return 1 ;;
		blackhole) [ "$DIRECT_FALLBACK" != "1" ] || return 1 ;;
		*)
			candidate="$(candidate_tag "$saved_id")" || return 1
			[ "$candidate" = "$saved_tag" ] || return 1
		;;
	esac
	override_balancer "$MAIN_BALANCER" "$saved_tag" || return 1
	CURRENT_ID="$saved_id"
	CURRENT_TAG="$saved_tag"
	STATE=${saved_state:-backup}
	SWITCHED_AT=${saved_switched:-$(date +%s)}
	SWITCHED_MONOTONIC="$saved_switched_monotonic"
	LAST_FAILED_ID="$saved_last_failed_id"
	LAST_FAILURE_COUNT="$saved_last_failure_count"
	LAST_FAILURE_STARTED_AT="$saved_last_failure_started_at"
	return 0
}

load_config || exit 1
[ -n "$XRAY_CONFIG_FILE" ] || exit 1

CURRENT_ID="$PRIMARY_ID"
CURRENT_TAG="$PRIMARY_TAG"
STATE="primary"
SWITCHED_AT="$(date +%s)"
SWITCHED_MONOTONIC="$(monotonic_seconds)" || exit 1
ACTIVE_FAILURES=0
FIRST_FAILURE_AT=0
FIRST_FAILURE_MONOTONIC=0
LAST_FAILED_ID=""
LAST_FAILURE_COUNT=0
LAST_FAILURE_STARTED_AT=0
RECOVERY_COUNT=0
LAST_RECOVERY_CHECK_MONOTONIC=0
BACKOFF_INDEX=0
STATE_REASON=""

api_ready=0
attempt=0
while [ "$attempt" -lt 10 ]; do
	if override_balancer "$PROBE_BALANCER" "$PRIMARY_TAG"; then
		api_ready=1
		break
	fi
	attempt=$((attempt + 1))
	sleep 1
done
[ "$api_ready" = "1" ] || exit 1

if ! restore_previous_state; then
	set_main "$PRIMARY_ID" "$PRIMARY_TAG" "primary" "startup" || exit 1
else
	write_state "supervisor-restart"
	log_event "state=$STATE node=$CURRENT_ID reason=supervisor-restart"
fi
CORE_PID="$(get_core_pid)"
[ -n "$CORE_PID" ] || exit 1
touch "$READY_FILE"

trap 'rm -f "$READY_FILE"; exit 0' INT TERM EXIT

while true; do
	current_core_pid="$(get_core_pid)"
	if [ -z "$current_core_pid" ]; then
		sleep 2
		continue
	fi
	if [ "$current_core_pid" != "$CORE_PID" ]; then
		if ! override_balancer "$MAIN_BALANCER" "$CURRENT_TAG"; then
			sleep 2
			continue
		fi
		CORE_PID="$current_core_pid"
		ACTIVE_FAILURES=0
		FIRST_FAILURE_AT=0
		FIRST_FAILURE_MONOTONIC=0
		RECOVERY_COUNT=0
		write_state "xray-recovered"
		log_event "state=$STATE node=$CURRENT_ID reason=xray-recovered"
	fi

	if [ "$STATE" = "all-down" ] || [ "$STATE" = "direct-fallback" ]; then
		candidate="$(find_healthy_candidate "")"
		if [ -n "$candidate" ]; then
			node_id=${candidate%%|*}
			node_tag=${candidate#*|}
			if [ "$node_id" = "$PRIMARY_ID" ]; then
				set_main "$node_id" "$node_tag" "primary" "node-recovered"
			else
				set_main "$node_id" "$node_tag" "backup" "node-recovered"
			fi
			BACKOFF_INDEX=0
			continue
		fi
		if wan_available; then
			if [ "$STATE_REASON" != "probe-endpoint-failed" ]; then
				write_state "probe-endpoint-failed"
				log_event "state=$STATE node=$CURRENT_ID reason=probe-endpoint-failed detail=all-candidates-failed wan_detail=$WAN_DETAIL family=${WAN_FAMILY:-unknown} device=${WAN_DEVICE:-unknown} gateway=${WAN_GATEWAY:-none}"
			fi
		else
			if [ "$STATE_REASON" != "wan-down" ]; then
				write_state "wan-down"
				log_event "state=$STATE node=$CURRENT_ID reason=wan-down detail=$WAN_DETAIL family=${WAN_FAMILY:-unknown} device=${WAN_DEVICE:-unknown} gateway=${WAN_GATEWAY:-none}"
			fi
		fi
		delay="$(backoff_seconds "$BACKOFF_INDEX")"
		[ "$BACKOFF_INDEX" -lt 4 ] && BACKOFF_INDEX=$((BACKOFF_INDEX + 1))
		sleep "$delay"
		continue
	fi

	if probe_tag "$CURRENT_ID" "$CURRENT_TAG"; then
		ACTIVE_FAILURES=0
		FIRST_FAILURE_AT=0
		FIRST_FAILURE_MONOTONIC=0
		if [ "$STATE_REASON" = "wan-down" ]; then
			write_state "wan-recovered"
			log_event "state=$STATE node=$CURRENT_ID reason=wan-recovered"
		fi
		if [ "$STATE" = "backup" ] && [ "$RESTORE_PRIMARY" != "0" ]; then
			now_monotonic="$(monotonic_seconds)" || { sleep "$CHECK_INTERVAL"; continue; }
			dwell_elapsed="$(elapsed_seconds "$now_monotonic" "$SWITCHED_MONOTONIC")"
			recovery_elapsed="$(elapsed_seconds "$now_monotonic" "$LAST_RECOVERY_CHECK_MONOTONIC")"
			if [ "$dwell_elapsed" -ge "$MINIMUM_DWELL" ] && [ "$recovery_elapsed" -ge "$RECOVERY_INTERVAL" ]; then
				LAST_RECOVERY_CHECK_MONOTONIC="$now_monotonic"
				if probe_tag "$PRIMARY_ID" "$PRIMARY_TAG"; then
					RECOVERY_COUNT=$((RECOVERY_COUNT + 1))
					if [ "$RECOVERY_COUNT" -ge "$RECOVERY_SUCCESSES" ]; then
						set_main "$PRIMARY_ID" "$PRIMARY_TAG" "primary" "primary-stable"
					fi
				else
					RECOVERY_COUNT=0
				fi
			fi
		fi
		sleep "$CHECK_INTERVAL"
		continue
	fi

	now_monotonic="$(monotonic_seconds)" || { sleep 2; continue; }
	if [ "$ACTIVE_FAILURES" -eq 0 ]; then
		FIRST_FAILURE_AT="$(date +%s)"
		FIRST_FAILURE_MONOTONIC="$now_monotonic"
	fi
	ACTIVE_FAILURES=$((ACTIVE_FAILURES + 1))
	if [ "$ACTIVE_FAILURES" -lt "$FAILURE_THRESHOLD" ]; then
		delay=2
		elapsed="$(elapsed_seconds "$now_monotonic" "$FIRST_FAILURE_MONOTONIC")"
		remaining=$((MINIMUM_FAILURE_DURATION - elapsed))
		[ "$remaining" -gt "$delay" ] && delay="$remaining"
		sleep "$delay"
		continue
	fi
	elapsed="$(elapsed_seconds "$now_monotonic" "$FIRST_FAILURE_MONOTONIC")"
	if [ "$elapsed" -lt "$MINIMUM_FAILURE_DURATION" ]; then
		sleep "$((MINIMUM_FAILURE_DURATION - elapsed))"
		continue
	fi

	candidate="$(find_healthy_candidate "$CURRENT_ID")"
	if [ -n "$candidate" ]; then
		node_id=${candidate%%|*}
		node_tag=${candidate#*|}
		if [ "$node_id" = "$PRIMARY_ID" ]; then
			set_main "$node_id" "$node_tag" "primary" "node-failed"
		else
			set_main "$node_id" "$node_tag" "backup" "node-failed"
		fi
		continue
	fi

	if ! wan_available; then
		if [ "$STATE_REASON" != "wan-down" ]; then
			write_state "wan-down"
			log_event "state=$STATE node=$CURRENT_ID reason=wan-down detail=$WAN_DETAIL family=${WAN_FAMILY:-unknown} device=${WAN_DEVICE:-unknown} gateway=${WAN_GATEWAY:-none}"
		fi
		sleep "$CHECK_INTERVAL"
		continue
	fi
	log_event "state=$STATE node=$CURRENT_ID reason=probe-endpoint-failed detail=all-candidates-failed wan_detail=$WAN_DETAIL family=${WAN_FAMILY:-unknown} device=${WAN_DEVICE:-unknown} gateway=${WAN_GATEWAY:-none}"

	if [ "$DIRECT_FALLBACK" = "1" ]; then
		set_main "direct" "direct" "direct-fallback" "probe-endpoint-failed"
	else
		set_main "blackhole" "blackhole" "all-down" "probe-endpoint-failed"
	fi
	BACKOFF_INDEX=0
done
