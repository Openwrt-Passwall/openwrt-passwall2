local m, s = ...

if not api.finded_com("xray") then
	return
end

local jsonc = api.jsonc

type_name = "Xray"

-- [[ Xray ]]

s.fields["type"]:value(type_name, "Xray")
if not s.fields["type"].default then
	s.fields["type"].default = type_name
end

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "xray_"

local function _n(name)
	return option_prefix .. name
end

local formvalue_proto = luci.http.formvalue(formvalue_key .. _n("protocol"))

if formvalue_proto then s.val["protocol"] = formvalue_proto end

local arg_select_proto = luci.http.formvalue("select_proto") or ""

local ss_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = { "auto", "aes-128-gcm", "chacha20-poly1305" }

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"
}

local xray_version = api.get_app_version("xray")

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("vmess", translate("Vmess"))
o:value("vless", translate("VLESS"))
o:value("http", translate("HTTP"))
o:value("socks", translate("Socks"))
o:value("shadowsocks", translate("Shadowsocks"))
o:value("trojan", translate("Trojan"))
o:value("wireguard", translate("WireGuard"))
if api.compare_versions(xray_version, ">=", "26.1.13") then
	o:value("hysteria2", translate("Hysteria2"))
end
if api.compare_versions(xray_version, ">=", "1.8.12") then
	o:value("_balancing", translate("Balancing"))
	o:value("_failover", translate("Priority Failover"))
end
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))
function o.custom_cfgvalue(self, section)
	if arg_select_proto ~= "" then
		return arg_select_proto
	else
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end

local load_balancing_options = s.val["protocol"] == "_balancing" or arg_select_proto == "_balancing"
local load_failover_options = s.val["protocol"] == "_failover" or arg_select_proto == "_failover"
local load_shunt_options = s.val["protocol"] == "_shunt" or arg_select_proto == "_shunt"
local load_iface_options = s.val["protocol"] == "_iface" or arg_select_proto == "_iface"
local load_normal_options = true
if load_balancing_options or load_failover_options or load_shunt_options or load_iface_options then
	load_normal_options = nil
end
if not arg_select_proto:find("_") then
	load_normal_options = true
end

local netdev_list = api.get_network_devices()
local node_list = api.get_node_list()
local fallback_list = {}
local is_balancer = nil
for k, e in ipairs(node_list.balancing_list or {}) do
	if e.id ~= arg[1] then
		fallback_list[#fallback_list + 1] = {
			id = e["id"],
			remark = e["remark"],
			group = e["group"],
			fallback = e.o["fallback_node"],
		}
	else
		is_balancer = true
	end
end

if load_balancing_options then -- [[ Load balancing Start ]]
	o = s:option(ListValue, _n("node_add_mode"), translate("Node Addition Method"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o.default = "manual"
	o:value("manual", translate("Manual"))
	o:value("batch", translate("Batch"))

	o = s:option(MultiValue, _n("balancing_node"), translate("Load balancing node list"), translate("Load balancing node list, <a target='_blank' href='https://xtls.github.io/config/routing.html#balancerobject'>document</a>"))
	o:depends({ [_n("node_add_mode")] = "manual" })
	o.widget = "checkbox"
	o.template = appname .. "/cbi/nodes_multivalue"
	o.group = {}
	for k1, v1 in pairs(node_list) do
		if k1 == "socks_list" or k1 == "normal_list" then
			for i, v in ipairs(v1) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = v.group or ""
			end
		end
	end
	-- Reading the old DynamicList
	function o.cfgvalue(self, section)
		return m.uci:get_list(appname, section, "balancing_node") or {}
	end
	-- Write-and-hold DynamicList
	function o.custom_write(self, section, value)
		local old = m.uci:get_list(appname, section, "balancing_node") or {}
		local new, set = {}, {}
		for v in value:gmatch("%S+") do
			new[#new + 1] = v
			set[v] = 1
		end
		for _, v in ipairs(old) do
			if not set[v] then
				m.uci:set_list(appname, section, "balancing_node", new)
				return
			end
			set[v] = nil
		end
		for _ in pairs(set) do
			m.uci:set_list(appname, section, "balancing_node", new)
			return
		end
	end

	o = s:option(MultiValue, _n("node_group"), translate("Select Group"))
	o:depends({ [_n("node_add_mode")] = "batch" })
	o.widget = "checkbox"
	o:value("default", translate("default"))
	for k, v in pairs(groups) do
		o:value(api.UrlEncode(k), k)
	end

	o = s:option(Value, _n("node_match_rule"), translate("Node Matching Rules"))
	o:depends({ [_n("node_add_mode")] = "batch" })
	local descrStr = "Example: <code>^A && B && !C && D$</code><br>"
	descrStr = descrStr .. "This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>"
	descrStr = descrStr .. "Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>"
	descrStr = descrStr .. "Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>"
	descrStr = descrStr .. "Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D)."
	o.description = translate(descrStr)

	o = s:option(ListValue, _n("balancingStrategy"), translate("Balancing Strategy"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o:value("random")
	o:value("roundRobin")
	o:value("leastPing")
	o:value("leastLoad")
	o.default = "random"

	-- Fallback Node
	o = s:option(ListValue, _n("fallback_node"), translate("Fallback Node"))
	o.group = {"",""}
	o:value("", translate("Close(Not use)"))
	o:value("_direct", translate("Direct Connection"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o.template = appname .. "/cbi/nodes_listvalue"
	-- Maximum number of fallback nesting layers
	local MAX_FALLBACK_DEPTH = 3
	-- Check if a loop will form.
	local function will_loop(start_id, target_id, depth)
		depth = depth or 0
		-- Recursion stops after the maximum depth is exceeded.
		if depth >= MAX_FALLBACK_DEPTH then
			return false
		end
		for _, v in ipairs(fallback_list) do
			if v.id == target_id then
				local fb = v.fallback
				-- No fallback
				if not fb or fb == "" or fb == "_direct" then
					return false
				end
				-- Loopback detected
				if fb == start_id then
					return true
				end
				-- Continue recursive checking
				return will_loop(start_id, fb, depth + 1)
			end
		end
		return false
	end
	-- Get fallback chain depth
	local function get_fallback_depth(id, depth)
		depth = depth or 0
		if depth >= MAX_FALLBACK_DEPTH then
			return depth
		end
		for _, v in ipairs(fallback_list) do
			if v.id == id then
				local fb = v.fallback
				if not fb or fb == "" or fb == "_direct" then
					return depth
				end
				return get_fallback_depth(fb, depth + 1)
			end
		end
		return depth
	end
	for _, v in ipairs(fallback_list) do
		local depth = get_fallback_depth(v.id)
		-- Once the maximum number of nested doll layers is exceeded, further selection of the balancer is not allowed.
		if depth < MAX_FALLBACK_DEPTH
			and not will_loop(arg[1], v.id)
		then
			o:value(v.id, v.remark)
			o.group[#o.group + 1] = (v.group and v.group ~= "") and v.group or translate("default")
		end
	end
	for k1, v1 in pairs(node_list) do
		if k1 == "socks_list" or k1 == "normal_list" or k1 == "urltest_list" then
			for i, v in ipairs(v1) do
				o:value(v.id, v.remark)
				o.group[#o.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
			end
		end
	end

	o = s:option(Flag, _n("useCustomProbeUrl"), translate("Use Custom Probe URL"), translate("By default the built-in probe URL will be used, enable this option to use a custom probe URL."))
	o:depends({ [_n("protocol")] = "_balancing" })

	o = s:option(Value, _n("probeUrl"), translate("Probe URL"))
	o:depends({ [_n("useCustomProbeUrl")] = true })
	o:value("https://cp.cloudflare.com/", "Cloudflare")
	o:value("https://www.gstatic.com/generate_204", "Gstatic")
	o:value("https://www.google.com/generate_204", "Google")
	o:value("https://www.youtube.com/generate_204", "YouTube")
	o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
	o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
	o:value("https://wifi.vivo.com.cn/generate_204", "VIVO (CN)")
	o.default = o.keylist[3]
	o.description = translate("The URL used to detect the connection status.")

	o = s:option(Value, _n("probeInterval"), translate("Probe Interval"))
	o:depends({ [_n("protocol")] = "_balancing" })
	o.default = "1m"
	o.placeholder = "1m"
	o.description = translate("The interval between initiating probes.") .. "<br>" ..
			translate("The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.") .. "<br>" ..
			translate("When the unit is not filled in, it defaults to seconds.")

	o = s:option(Value, _n("expected"), translate("Preferred Node Count"))
	o:depends({ [_n("balancingStrategy")] = "leastLoad" })
	o.datatype = "uinteger"
	o.default = "2"
	o.placeholder = "2"
	o.description = translate("The load balancer selects the optimal number of nodes, and traffic is randomly distributed among them.")

	o = s:option(Value, _n("tolerance"), translate("Failure Tolerance (%)"))
	o:depends({ [_n("balancingStrategy")] = "leastLoad" })
	o.datatype = "uinteger"
	o.default = "10"
	o.placeholder = "10"
	o.description = translate("The maximum acceptable speed test failure rate. For example, 1 means allowing a 1% failure rate.")
end -- [[ Load balancing End ]]

if load_failover_options then -- [[ Priority failover Start ]]
	local candidate_ids = {}
	local candidate_groups = {}
	local function is_failover_candidate(candidate)
		local chain_proxy = candidate.chain_proxy
		local self_contained = not chain_proxy or chain_proxy == "" or chain_proxy == "3"
		return candidate.id ~= arg[1] and candidate.type == "Xray" and self_contained
	end
	for _, candidate in ipairs(node_list.normal_list or {}) do
		if is_failover_candidate(candidate) then
			candidate_ids[candidate.id] = true
			candidate_groups[candidate.id] = (candidate.group and candidate.group ~= "") and candidate.group or translate("default")
		end
	end

	local configured_primary = m.uci:get(appname, arg[1], "failover_primary_node")
	local configured_backups = m.uci:get_list(appname, arg[1], "failover_backup_node") or {}

	o = s:option(DummyValue, _n("failover_status"), translate("Failover status"))
	o:depends({ [_n("protocol")] = "_failover" })
	o.cfgvalue = function()
		local raw = api.sys.exec("for f in /tmp/etc/passwall2/failover/*_" .. arg[1] .. ".state; do [ -s \"$f\" ] && { cat \"$f\"; break; }; done 2>/dev/null")
		local status = raw and jsonc.parse(raw) or nil
		if not status then return translate("Not running") end
		local current = status.current_id or translate("Unknown")
		local current_node = m.uci:get_all(appname, current)
		if current_node then current = api.get_node_remarks(current_node) end
		return string.format("%s: %s; %s: %s; %s: %s", translate("State"), status.state or translate("Unknown"), translate("Current Node"), current, translate("Reason"), status.reason or translate("Unknown"))
	end

	o = s:option(ListValue, _n("failover_primary_node"), translate("Primary Node"))
	o:depends({ [_n("protocol")] = "_failover" })
	o.template = appname .. "/cbi/nodes_listvalue"
	o.group = {}
	o.rmempty = false
	for _, candidate in ipairs(node_list.normal_list or {}) do
		if is_failover_candidate(candidate) then
			o:value(candidate.id, candidate.remark)
			o.group[#o.group + 1] = candidate_groups[candidate.id]
		end
	end
	if configured_primary and not candidate_ids[configured_primary] then
		o:value(configured_primary, translate("Missing node") .. ": " .. configured_primary)
		o.group[#o.group + 1] = translate("Missing")
	end

	o = s:option(DynamicList, _n("failover_backup_node"), translate("Backup Nodes"), translate("Backup nodes are tested serially in this order. The primary and backup list are limited to 10 nodes in total."))
	o:depends({ [_n("protocol")] = "_failover" })
	o.template = appname .. "/cbi/nodes_dynamiclist"
	o.group = {}
	for _, candidate in ipairs(node_list.normal_list or {}) do
		if is_failover_candidate(candidate) then
			o:value(candidate.id, candidate.remark)
			o.group[#o.group + 1] = candidate_groups[candidate.id]
		end
	end
	for _, candidate_id in ipairs(configured_backups) do
		if not candidate_ids[candidate_id] then
			o:value(candidate_id, translate("Missing node") .. ": " .. candidate_id)
			o.group[#o.group + 1] = translate("Missing")
		end
	end
	o.write = function(self, section, value)
		local primary = s.fields[_n("failover_primary_node")]:formvalue(section)
		local values = type(value) == "table" and value or { value }
		local result, seen = {}, {}
		local backup_limit = 10
		if primary and primary ~= "" then seen[primary] = true end
		if primary and primary ~= "" then backup_limit = 9 end
		for _, candidate_id in ipairs(values) do
			if candidate_id and candidate_id ~= "" and candidate_id ~= arg[1] and not seen[candidate_id] and #result < backup_limit then
				result[#result + 1] = candidate_id
				seen[candidate_id] = true
			end
		end
		return DynamicList.write(self, section, result)
	end

	o = s:option(Flag, _n("failover_restore_primary"), translate("Return to primary when stable"))
	o:depends({ [_n("protocol")] = "_failover" })
	o.default = "1"
	o.rmempty = false

	o = s:option(Flag, _n("failover_show_advanced"), translate("Show advanced failover settings"))
	o:depends({ [_n("protocol")] = "_failover" })
	o.default = "0"
	o.rmempty = false

	o = s:option(Flag, _n("failover_direct_fallback"), translate("Direct fallback if all nodes fail"), translate("Warning: enabling this option exposes the direct public IP and sends remote DNS directly while all configured nodes are unavailable."))
	o:depends({ [_n("protocol")] = "_failover", [_n("failover_show_advanced")] = "1" })
	o.default = "0"
	o.rmempty = false

	local function advanced_value(name, title, default, datatype, description)
		local option = s:option(Value, _n(name), title, description)
		option:depends({ [_n("protocol")] = "_failover", [_n("failover_show_advanced")] = "1" })
		option.default = default
		option.placeholder = default
		option.datatype = datatype
		option.rmempty = false
		return option
	end

	advanced_value("failover_check_interval", translate("Active check interval"), "20", "min(10)", translate("Units: seconds"))
	advanced_value("failover_connect_timeout", translate("Connection timeout"), "3", "range(1,10)", translate("Units: seconds"))
	advanced_value("failover_failure_threshold", translate("Failure threshold"), "2", "range(2,5)")
	advanced_value("failover_minimum_failure_duration", translate("Minimum failure duration"), "10", "range(0,60)", translate("The next failed probe cycle must be separated from the first failure by at least this duration.") .. "<br>" .. translate("Units: seconds"))
	advanced_value("failover_recovery_interval", translate("Primary recovery interval"), "300", "min(60)", translate("Units: seconds"))
	advanced_value("failover_recovery_successes", translate("Recovery success threshold"), "2", "range(1,5)")
	advanced_value("failover_minimum_dwell", translate("Minimum backup dwell time"), "600", "min(0)", translate("Units: seconds"))
	advanced_value("failover_primary_url", translate("Primary probe URL"), "https://www.gstatic.com/generate_204", "string", translate("Any final HTTP 2xx response is treated as healthy."))
	advanced_value("failover_secondary_url", translate("Secondary probe URL"), "https://cp.cloudflare.com/generate_204", "string", translate("Any final HTTP 2xx response is treated as healthy."))
end -- [[ Priority failover End ]]

if load_iface_options then -- [[ Custom Interface Start ]]
	o = s:option(Value, _n("iface"), translate("Interface"))
	o:depends({ [_n("protocol")] = "_iface" })
	for _, d in ipairs(netdev_list) do
		o:value(d.name, d.label)
	end
end -- [[ Custom Interface End ]]


-- [[ Normal single node Start ]]
if load_normal_options then

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"

o = s:option(Value, _n("uuid"), translate("ID"))
o.password = true
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })

o = s:option(Value, _n("username"), translate("Username"))
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(ListValue, _n("security"), translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Value, _n("encryption"), translate("Encrypt Method") .. " (encryption)")
o.default = "none"
o.placeholder = "none"
o:depends({ [_n("protocol")] = "vless" })
o.validate = function(self, value)
	value = api.trim(value)
	return (value == "" and "none" or value)
end

o = s:option(ListValue, _n("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(ListValue, _n("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:value("xtls-rprx-vision-udp443")
o:depends({ [_n("protocol")] = "vless" })

---- [[hysteria2]]
o = s:option(Value, _n("hysteria2_hop"), translate("Port hopping range"))
o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_realms")] = false })

o = s:option(Value, _n("hysteria2_hop_interval"), translate("Hop Interval(second)"), translate("Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5."))
o.datatype = "or(uinteger,portrange)"
o.placeholder = "30"
o.default = "30"
o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_realms")] = false })

o = s:option(Flag, _n("hysteria2_realms"), translate("Realms"))
o.default = "0"
if api.compare_versions(xray_version, ">", "26.5.9") then
	o:depends({ [_n("protocol")] = "hysteria2"})
else
	o:depends({ [_n("protocol")] = "__hide"})
end

o = s:option(Value, _n("hysteria2_realm_url"), translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
o:depends({ [_n("hysteria2_realms")] = "1" })
o.validate = function(self, value)
	value = api.trim(value)
	local realm = api.parse_realm_uri(value)
	if realm then return value end
	return nil, translate("Invalid Realm URL.")
end

o = s:option(DynamicList, _n("hysteria2_realm_stun"), translate("Realm STUN"))
o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
o:depends({ [_n("hysteria2_realms")] = "1" })

o = s:option(Value, _n("hysteria2_auth_password"), translate("Auth Password"))
o.password = true
o:depends({ [_n("protocol")] = "hysteria2"})

o = s:option(ListValue, _n("hysteria2_obfs_type"), translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_obfs_password"), translate("Obfs Password"))
o:depends({ [_n("hysteria2_obfs_type")] = "salamander" })
o:depends({ [_n("hysteria2_obfs_type")] = "gecko" })

o = s:option(Value, _n("hysteria2_obfs_MinPacketSize"), translate("Gecko Packet Size (min)"))
o.datatype = "uinteger"
o.placeholder = "512"
o.default = "512"
o:depends({ [_n("hysteria2_obfs_type")] = "gecko" })

o = s:option(Value, _n("hysteria2_obfs_MaxPacketSize"), translate("Gecko Packet Size (max)"))
o.datatype = "uinteger"
o.placeholder = "1200"
o.default = "1200"
o:depends({ [_n("hysteria2_obfs_type")] = "gecko" })

o = s:option(Value, _n("hysteria2_up_mbps"), translate("Max upload Mbps"))
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_down_mbps"), translate("Max download Mbps"))
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("hysteria2_idle_timeout"), translate("Idle Timeout"), translate("Units:seconds") .. " (4~120)")
o.datatype = "range(4,120)"
o:depends({ [_n("protocol")] = "hysteria2"})

o = s:option(Value, _n("hysteria2_keep_alive_period"), translate("QUIC KeepAlive interval"), translate("Units:seconds") .. " (2~60)")
o.datatype = "range(2,60)"
o:depends({ [_n("protocol")] = "hysteria2"})

o = s:option(Flag, _n("hysteria2_disable_mtu_discovery"), translate("Disable MTU detection"))
o.default = "0"
o:depends({ [_n("protocol")] = "hysteria2"})
---- [[hysteria2 end]]

o = s:option(Flag, _n("tls"), translate("TLS"))
o.default = 0
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("reality"), translate("REALITY"))
o.default = 0
o:depends({ [_n("tls")] = true, [_n("transport")] = "raw" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "ws" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "grpc" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "httpupgrade" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "xhttp" })

o = s:option(ListValue, _n("alpn"), translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

-- o = s:option(Value, _n("minversion"), translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- o:depends({ [_n("tls")] = true })

o = s:option(Value, _n("tls_serverName"), "SNI " .. translate("Domain"))
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Value, _n("tls_pinSHA256"), translate("TLS Chain Fingerprint (SHA256)"))
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria2" })
o.description = translate("Once set, connects only when the server’s chain fingerprint matches.") ..
		string.format("<a href='javascript:void(0)' onclick='javascript:fetchCertSha256(this)'>%s</a>", "→ " .. translate("Fetch Manually"))

o = s:option(Value, _n("tls_CertByName"), translate("TLS Certificate Name (CertName)"), translate("TLS is used to verify the leaf certificate name."))
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(Flag, _n("tls_certificate"), translate("TLS Certificate (PEM)"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria2" })

o = s:option(TextValue, _n("tls_certificate_pem"), "　", translate("Full certificate (chain), PEM format."))
o.default = ""
o.rows = 5
o.wrap = "off"
o:depends({ [_n("tls_certificate")] = true })
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	return value
end

o = s:option(Flag, _n("ech"), translate("ECH"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })
o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_realms")] = false })

o = s:option(TextValue, _n("ech_config"), translate("ECH Config"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ [_n("ech")] = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

-- [[ REALITY ]] --
o = s:option(Value, _n("reality_publicKey"), translate("Public Key"))
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("reality_shortId"), translate("Short Id"))
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("reality_spiderX"), translate("Spider X"))
o.placeholder = "/"
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Flag, _n("utls"), translate("uTLS"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

o = s:option(ListValue, _n("fingerprint"), translate("Finger Print"))
o:value("chrome")
o:value("firefox")
o:value("edge")
o:value("safari")
o:value("360")
o:value("qq")
o:value("ios")
o:value("android")
o:value("random")
o:value("randomized")
o:value("unsafe")
o.default = "chrome"
o:depends({ [_n("tls")] = true, [_n("utls")] = true })
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Flag, _n("use_mldsa65Verify"), translate("ML-DSA-65"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("cipherSuites"), translate("Cipher Suites"), '<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a>' .. " " .. translate("Configures the list of supported cipher suites, separated by :"))
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

o = s:option(TextValue, _n("reality_mldsa65Verify"), "ML-DSA-65 " .. translate("Public key"))
o.default = ""
o.rows = 5
o.wrap = "soft"
o:depends({ [_n("use_mldsa65Verify")] = true })
o.validate = function(self, value)
	return api.trim(value:gsub("[\r\n]", ""))
end

o = s:option(ListValue, _n("transport"), translate("Transport"))
o:value("raw", "RAW (TCP)")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("xhttp", "XHTTP")
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(Value, _n("wireguard_public_key"), translate("Public Key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_secret_key"), translate("Private Key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_preSharedKey"), translate("Pre shared key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(DynamicList, _n("wireguard_local_address"), translate("Local Address"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_mtu"), translate("MTU"))
o.default = "1420"
o:depends({ [_n("protocol")] = "wireguard" })

if api.compare_versions(xray_version, ">=", "1.8.0") then
	o = s:option(Value, _n("wireguard_reserved"), translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ [_n("protocol")] = "wireguard" })
end

o = s:option(Value, _n("wireguard_keepAlive"), translate("Keep Alive"))
o.default = "0"
o:depends({ [_n("protocol")] = "wireguard" })

-- [[ RAW ]]--
o = s:option(ListValue, _n("tcp_guise"), translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ [_n("transport")] = "raw" })

o = s:option(DynamicList, _n("tcp_guise_http_host"), translate("HTTP Host"))
o:depends({ [_n("tcp_guise")] = "http" })

o = s:option(DynamicList, _n("tcp_guise_http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [_n("tcp_guise")] = "http" })

-- [[ mKCP ]]--
o = s:option(ListValue, _n("mkcp_guise"), translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_domain"), translate("Camouflage Domain"), translate("Use it together with the DNS disguised type. You can fill in any domain."))
o:depends({ [_n("mkcp_guise")] = "dns" })

o = s:option(Value, _n("mkcp_mtu"), translate("KCP MTU"))
o.datatype = "uinteger"
o.default = 1350
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_seed"), translate("KCP Seed"))
o:depends({ [_n("transport")] = "mkcp" })

-- [[ WebSocket  ]]--
o = s:option(Value, _n("ws_host"), translate("WebSocket Host"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_heartbeatPeriod"), translate("HeartbeatPeriod(second)"))
o.datatype = "integer"
o:depends({ [_n("transport")] = "ws" })

-- [[ gRPC  ]]--
o = s:option(Value, _n("grpc_serviceName"), "ServiceName")
o:depends({ [_n("transport")] = "grpc" })

o = s:option(ListValue, _n("grpc_mode"), "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
o:depends({ [_n("transport")] = "grpc" })

o = s:option(Flag, _n("grpc_health_check"), translate("Health check"))
o:depends({ [_n("transport")] = "grpc" })

o = s:option(Value, _n("grpc_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Value, _n("grpc_health_check_timeout"), translate("Health check timeout"))
o.default = "20"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Flag, _n("grpc_permit_without_stream"), translate("Permit without stream"))
o.default = "0"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Value, _n("grpc_initial_windows_size"), translate("Initial Windows Size"))
o.default = "0"
o:depends({ [_n("transport")] = "grpc" })

-- [[ HttpUpgrade ]]--
o = s:option(Value, _n("httpupgrade_host"), translate("HttpUpgrade Host"))
o:depends({ [_n("transport")] = "httpupgrade" })

o = s:option(Value, _n("httpupgrade_path"), translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ XHTTP ]]--
o = s:option(ListValue, _n("xhttp_mode"), "XHTTP " .. translate("Mode"))
o:depends({ [_n("transport")] = "xhttp" })
o.default = "auto"
o:value("auto")
o:value("packet-up")
o:value("stream-up")
o:value("stream-one")

o = s:option(Value, _n("xhttp_host"), translate("XHTTP Host"))
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(Value, _n("xhttp_path"), translate("XHTTP Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(Flag, _n("use_xhttp_extra"), translate("XHTTP Extra"))
o.default = "0"
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(TextValue, _n("xhttp_extra"), "　", translate("An XHttpObject in JSON format, used for sharing."))
o:depends({ [_n("use_xhttp_extra")] = true })
o.rows = 10
o.wrap = "off"
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	local v = o_validate(self, value)
	if v then return v end
	return nil, "XHTTP Extra " .. translate("Must be JSON text!")
end
o.custom_cfgvalue = function(self, section, value)
	local raw = m:get(section, "xhttp_extra")
	if raw then
		return api.base64Decode(raw)
	end
end
o.custom_write = function(self, section, value)
	m:set(section, "xhttp_extra", api.base64Encode(value) or "")
	local success, data = pcall(jsonc.parse, value)
	if success and data then
		local address = (data.extra and data.extra.downloadSettings and data.extra.downloadSettings.address)
			or (data.downloadSettings and data.downloadSettings.address)
		if address and address ~= "" then
			address = address:gsub("^%[", ""):gsub("%]$", "")
			m:set(section, "download_address", address)
		else
			m:del(section, "download_address")
		end
	else
		m:del(section, "download_address")
	end
end
o.custom_remove = function(self, section, value)
	m:del(section, "xhttp_extra")
	m:del(section, "download_address")
end

-- [[ User-Agent ]]--
o = s:option(Value, _n("user_agent"), translate("User-Agent"))
o.default = ""
o:value("", translate("default"))
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "chrome")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0", "firefox")
o:value("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15", "safari")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.70", "edge")
o:value("Go-http-client/1.1", "golang")
o:value("curl/7.68.0", "curl")
o:depends({ [_n("tcp_guise")] = "http" })
o:depends({ [_n("transport")] = "ws" })
o:depends({ [_n("transport")] = "httpupgrade" })
o:depends({ [_n("transport")] = "xhttp" })
o:depends({ [_n("transport")] = "grpc" })

-- [[ Mux.Cool ]]--
o = s:option(Flag, _n("mux"), "Mux", translate("Enable Mux.Cool"))
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "raw" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "ws" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "grpc" })
o:depends({ [_n("protocol")] = "vless", [_n("transport")] = "httpupgrade" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(Value, _n("mux_concurrency"), translate("Mux concurrency"))
o.default = -1
o:depends({ [_n("mux")] = true })

o = s:option(Value, _n("xudp_concurrency"), translate("XUDP Mux concurrency"))
o.default = 8
o:depends({ [_n("mux")] = true })

--[[FinalMask]]
o = s:option(Flag, _n("use_finalmask"), "FinalMask")
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "wireguard" })
o:depends({ [_n("protocol")] = "hysteria2", [_n("hysteria2_realms")] = false })

o = s:option(TextValue, _n("finalmask"), "　")
o:depends({ [_n("use_finalmask")] = true })
o.rows = 10
o.wrap = "off"
o.description = translate("An FinalMaskObject in JSON format, used for sharing.") .. "<br>" ..
		translate("Custom finalmask overrides mkcp, hysteria2, fragment, noise, and related settings.")
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	local v = o_validate(self, value)
	if v then return v end
	return nil, "FinalMask " .. translate("Must be JSON text!")
end
o.custom_cfgvalue = function(self, section, value)
	local raw = m:get(section, "finalmask")
	if raw then
		return api.base64Decode(raw)
	end
end
o.custom_write = function(self, section, value)
	m:set(section, "finalmask", api.base64Encode(value) or "")
end

--[[Fast Open]]
o = s:option(Flag, _n("tcp_fast_open"), "TCP " .. translate("Fast Open"), translate("Need node support required"))
o.default = 0

--[[tcpMptcp]]
o = s:option(Flag, _n("tcpMptcp"), "tcpMptcp", translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.default = 0

o = s:option(ListValue, _n("domain_resolver"), translate("Domain DNS Resolve"), translate("If the node address is a domain name, this DNS will be used for resolution."))
o:value("", translate("Auto"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("https", "HTTPS")

o = s:option(Value, _n("domain_resolver_dns"), "DNS")
o.datatype = "or(ipaddr,ipaddrport)"
o:value("114.114.114.114")
o:value("223.5.5.5:53")
o.default = o.keylist[1]
o:depends({ [_n("domain_resolver")] = "tcp" })
o:depends({ [_n("domain_resolver")] = "udp" })

o = s:option(Value, _n("domain_resolver_dns_https"), "DNS")
o:value("https://120.53.53.53/dns-query", "DNSPod")
o:value("https://223.5.5.5/dns-query", "AliDNS")
o.default = o.keylist[1]
o:depends({ [_n("domain_resolver")] = "https" })

o = s:option(ListValue, _n("domain_strategy"), translate("Domain Strategy"), translate("If is domain name, The requested domain name will be resolved to IP before connect."))
o.default = ""
o:value("", translate("Auto"))
o:value("UseIPv4", translate("IPv4 Only"))
o:value("UseIPv6", translate("IPv6 Only"))

o = s:option(Flag, _n("happy_eyeballs"), translate("Enable Happy Eyeballs"), translate("Attempts IPv4 and IPv6 simultaneously; automatically uses the faster connection."))
o.default = 0

local protocols = s.fields[_n("protocol")].keylist
if #protocols > 0 then
	for i, v in ipairs(protocols) do
		if not v:find("^_") then
			local depends_condition = { [_n("protocol")] = v }
			if v == "hysteria2" then
				depends_condition[_n("hysteria2_realms")] = false
			end
			s.fields[_n("address")]:depends(depends_condition)
			s.fields[_n("port")]:depends(depends_condition)
			s.fields[_n("domain_resolver")]:depends(depends_condition)
			s.fields[_n("happy_eyeballs")]:depends(depends_condition)

			local strategy_depends = api.clone(depends_condition)
			strategy_depends[_n("happy_eyeballs")] = false
			s.fields[_n("domain_strategy")]:depends(strategy_depends)

			if v ~= "hysteria2" then
				s.fields[_n("tcp_fast_open")]:depends({ [_n("protocol")] = v })
				s.fields[_n("tcpMptcp")]:depends({ [_n("protocol")] = v })
			end
		end
	end
end
end
-- [[ Normal single node End ]]

if not load_shunt_options and not load_failover_options then
	o = s:option(ListValue, _n("chain_proxy"), translate("Chain Proxy"))
	o:value("", translate("Close(Not use)"))
	if not (load_iface_options or load_balancing_options or load_failover_options) then
		-- Special node cannot be use pre-proxy.
		o:value("1", translate("Preproxy Node"))
		o:value("3", translate("Outbound Interface"))
	end
	o:value("2", translate("Landing Node"))

	o1 = s:option(ListValue, _n("preproxy_node"), translate("Preproxy Node"), translate("Only support a layer of proxy."))
	o1:depends({ [_n("chain_proxy")] = "1", [_n("hysteria2_realms")] = false })
	o1.template = appname .. "/cbi/nodes_listvalue"
	o1.group = {}

	o3 = s:option(Value, _n("outbound_iface"), translate("Outbound Interface"))
	o3:depends({ [_n("chain_proxy")] = "3" })
	o3:value("", translate("All"))
	for _, d in ipairs(netdev_list) do
		o3:value(d.name, d.label)
	end

	o2 = s:option(ListValue, _n("to_node"), translate("Landing Node"), translate("Only support a layer of proxy."))
	o2:depends({ [_n("chain_proxy")] = "2", [_n("hysteria2_realms")] = false })
	o2.template = appname .. "/cbi/nodes_listvalue"
	o2.group = {}

	for k1, v1 in pairs(node_list) do
		if k1 ~= "shunt_list" and k1 ~= "iface_list" and k1 ~= "failover_list" then
			for i, v in ipairs(v1) do
				if v.id ~= arg[1] then
					o1:value(v.id, v.remark)
					o1.group[#o1.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					if k1 == "normal_list" then
						-- Landing Node not support use special node.
						o2:value(v.id, v.remark)
						o2.group[#o2.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
					end
				end
			end
		end
	end
end

api.luci_types(arg[1], m, s, type_name, option_prefix)

if load_shunt_options then
	local current_node = m.uci:get_all(appname, arg[1]) or {}
	local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall2/client/include/shunt_options.lua")
	setfenv(shunt_lua, getfenv(1))(m, s, {
		node_id = arg[1],
		node = current_node,
		node_list = node_list,
	})
end
