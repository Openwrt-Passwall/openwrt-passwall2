#!/usr/bin/lua

------------------------------------------------
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require 'luci.util'
require 'luci.jsonc'
require 'luci.sys'
local api = require "luci.passwall2.api"
local c_config = api.c_config

local datatypes = api.datatypes
local split = api.split
local base64Decode = api.base64Decode
local jsonParse, jsonStringify = api.jsonc.parse, api.jsonc.stringify
local UrlEncode, UrlDecode = api.UrlEncode, api.UrlDecode
local fs = api.fs
local log_buffer
local function log(...)
	if log_buffer then
		table.insert(log_buffer, {...})
	else
		api.log(...)
	end
end

local function flush_log_buffer()
	local buffered = log_buffer
	log_buffer = nil
	for _, args in ipairs(buffered or {}) do
		log(unpack(args))
	end
end
local i18n = api.i18n
local uci, uci_get, uci_set, uci_del, uci_foreach, uci_save = api.uci, api.uci_get_c, api.uci_set_c, api.uci_del_c, api.uci_foreach_c, api.uci_save_c

-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub

-- Both update scripts use the same lockf lock; the kernel releases it on exit.
if not arg[1] then os.exit(0) end
local update_lock = api.nixio.open(api.LOCK_PREFIX .. "_sub_rule.lock", api.nixio.open_flags("rdwr", "creat"))
if not update_lock then
	log(0, i18n.translate("Unable to open the subscription/rule update lock. Exiting."))
	os.exit(1)
end
-- Scheduled updates wait for the lock; manual requests skip a busy lock.
if not update_lock:lock("tlock") then
	if arg[3] ~= "cron" then
		log(0, i18n.translate("A subscription or rule update is already running. Skipping this request."))
		os.exit(0)
	end
	local running = ({s = i18n.translate("Subscription"), r = i18n.translate("Rule Update")})[update_lock:read(1)] or i18n.translate("Subscription/Rule Update")
	update_lock:seek(0, "set")
	log(0, i18n.translatef("[%s] is running; [%s] is queued and waiting...", running, i18n.translate("Subscription")))
	if not update_lock:lock("lock") then
		log(0, i18n.translate("Unable to acquire the update lock. Scheduled task failed."))
		os.exit(1)
	end
end
-- Record the running task in the same file: s = subscription, r = rule update.
update_lock:write("s")
update_lock:seek(0, "set")
uci:revert(c_config)
math.randomseed(os.time() + math.floor(os.clock() * 1000))
local restart_required = false

local lyaml = require "lyaml"

local has_ss_rust = api.is_finded("sslocal")
local has_ssr = api.is_finded("ssr-local") and api.is_finded("ssr-redir")
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")
local DEFAULT_ALLOWINSECURE = true
-- Expand each DynamicList row, preserving spaces and ignoring empty or duplicate keywords.
local function split_filter_keywords(list)
	local keywords, seen = {}, {}
	if type(list) == "string" then list = {list} end
	for _, row in ipairs(list or {}) do
		for keyword in row:gmatch("[^|]+") do
			if not seen[keyword] then
				seen[keyword] = true
				keywords[#keywords + 1] = keyword
			end
		end
	end
	return keywords
end

local DEFAULT_FILTER_KEYWORD = {
	mode = uci_get("@global_subscribe[0]", "filter_keyword_mode") or "0",
	discard_list = split_filter_keywords(uci_get("@global_subscribe[0]", "filter_discard_list")),
	keep_list = split_filter_keywords(uci_get("@global_subscribe[0]", "filter_keep_list"))
}
-- Nodes should be retrieved using the core type (if not set on the node subscription page, the default type will be used automatically).
local DEFAULT_SS_TYPE = api.get_core("ss_type", {{has_ss_rust,"shadowsocks-rust"},{has_singbox,"sing-box"},{has_xray,"xray"}})
local DEFAULT_TROJAN_TYPE = api.get_core("trojan_type", {{has_singbox,"sing-box"},{has_xray,"xray"}})
local DEFAULT_VMESS_TYPE = api.get_core("vmess_type", {{has_xray,"xray"},{has_singbox,"sing-box"}})
local DEFAULT_VLESS_TYPE = api.get_core("vless_type", {{has_xray,"xray"},{has_singbox,"sing-box"}})
local DEFAULT_HYSTERIA2_TYPE = api.get_core("hysteria2_type", {{has_singbox,"sing-box"},{has_xray,"xray"}})
local core_has = {
	["xray"] = has_xray,
	["sing-box"] = has_singbox,
	["shadowsocks-rust"] = has_ss_rust,
}
-- Prepare once per subscription; mode 5 or an unset mode inherits the global filter.
local function prepare_keyword_filter(sub_cfg)
	local mode = sub_cfg and sub_cfg.filter_keyword_mode
	if mode == "0" or mode == "1" or mode == "2" or mode == "3" or mode == "4" then
		return {
			mode = mode,
			discard_list = split_filter_keywords(sub_cfg.filter_discard_list),
			keep_list = split_filter_keywords(sub_cfg.filter_keep_list)
		}
	end
	return DEFAULT_FILTER_KEYWORD
end

local function match_filter_keywords(value, keywords)
	for _, keyword in ipairs(keywords) do
		if value:find(keyword, 1, true) then
			return true
		end
	end
	return false
end

-- Decide whether to discard a parsed node using the current subscription's filter.
local function is_filter_keyword(filter, value)
	if filter.mode == "1" then
		return match_filter_keywords(value, filter.discard_list)
	elseif filter.mode == "2" then
		return not match_filter_keywords(value, filter.keep_list)
	elseif filter.mode == "3" then
		return match_filter_keywords(value, filter.discard_list) and not match_filter_keywords(value, filter.keep_list)
	elseif filter.mode == "4" then
		return match_filter_keywords(value, filter.discard_list) or not match_filter_keywords(value, filter.keep_list)
	end
	return false
end

local nodeResult = {} -- update result
local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = e
	end
end

-- To retrieve the current server's dynamic configurations, you can use `get` and `set`. `get` requires access to the node table.
local CONFIG = {}
do
	if true then
		local szType = "@global[0]"
		local option = "node"

		local node_id = uci_get(szType, option)
		CONFIG[#CONFIG + 1] = {
			log = true,
			remarks = i18n.translatef("Node"),
			currentNode = node_id and uci_get(node_id) or nil,
			set = function(o, server)
				uci_set(szType, option, server)
				o.newNodeId = server
			end
		}
	end

	if true then
		local i = 0
		local option = "node"
		uci_foreach("socks", function(t)
			i = i + 1
			local id = t[".name"]
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = id,
				remarks = i18n.translatef("Socks node list [%s]", i),
				currentNode = node_id and uci_get(node_id) or nil,
				set = function(o, server)
					if not server or server == "" then
						if #nodes_table > 0 then
							server = nodes_table[1][".name"]
						end
					end
					uci_set(t[".name"], option, server)
					o.newNodeId = server
				end
			}
			if t.autoswitch_backup_node and #t.autoswitch_backup_node > 0 then
				local flag = i18n.translatef("Socks node list [%s]", i) .. " " .. i18n.translatef("Backup node list")
				local currentNodes = {}
				local newNodes = {}
				for k, asb_node_id in ipairs(t.autoswitch_backup_node) do
					if asb_node_id then
						local currentNode = uci_get(asb_node_id) or {}
						if currentNode[".type"] == "nodes" then
							currentNodes[#currentNodes + 1] = {
								log = true,
								remarks = flag .. "[" .. k .. "]",
								currentNode = currentNode,
								set = function(o, server)
									if server and server ~= "nil" then
										table.insert(o.newNodes, server)
									end
								end
							}
						end
					end
				end
				CONFIG[#CONFIG + 1] = {
					remarks = flag,
					currentNodes = currentNodes,
					newNodes = newNodes,
					set = function(o, newNodes)
						if o then
							if not newNodes then newNodes = o.newNodes end
							uci_set(id, "autoswitch_backup_node", newNodes or {})
						end
					end
				}
			end
		end)
	end

	if true then
		local i = 0
		local option = "lbss"
		local function is_ip_port(str)
			if type(str) ~= "string" then return false end
			local ip, port = str:match("^([%d%.]+):(%d+)$")
			return ip and datatypes.ipaddr(ip) and tonumber(port) and tonumber(port) <= 65535
		end
		uci_foreach("haproxy_config", function(t)
			i = i + 1
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = t[".name"],
				remarks = i18n.translatef("HAProxy node list [%s]", i),
				currentNode = node_id and uci_get(node_id) or nil,
				set = function(o, server)
					-- Modify the LBS value only if it is not in IP:Port format.
					if not is_ip_port(t[option]) then
						uci_set(t[".name"], option, server)
						o.newNodeId = server
					end
				end,
				delete = function(o)
					-- Deletion is only performed if the current LBS value is not in IP:port format.
					if not is_ip_port(t[option]) then
						uci_del(t[".name"])
					end
				end
			}
		end)
	end

	if true then
		local i = 0
		uci_foreach("acl_rule", function(t)
			i = i + 1
			local option = "node"
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = t[".name"],
				remarks = i18n.translatef("ACL list [%s]", i),
				currentNode = node_id and uci_get(node_id) or nil,
				set = function(o, server)
					uci_set(t[".name"], option, server)
					o.newNodeId = server
				end
			}
		end)
	end

	uci_foreach("nodes", function(node)
		local node_id = node[".name"]
		if node.protocol and node.protocol == '_shunt' then
			local rules = {}
			uci_foreach("shunt_rules", function(e)
				if e[".name"] and e.remarks then
					table.insert(rules, e)
					table.insert(rules, {
						[".name"] = e[".name"] .. "_proxy_tag",
						remarks = e.remarks .. " " .. i18n.translate("Preproxy")
					})
				end
			end)
			table.insert(rules, {
				[".name"] = "default_node",
				remarks = i18n.translatef("Default")
			})
			table.insert(rules, {
				[".name"] = "default_proxy_tag",
				remarks = i18n.translatef("Default") .. " " .. i18n.translate("Preproxy")
			})

			for k, e in pairs(rules) do
				local _node_id = node[e[".name"]] or nil
				if _node_id then
					local section = uci_get(_node_id) or {}
					if section[".type"] == "nodes" then
						CONFIG[#CONFIG + 1] = {
							log = false,
							currentNode = section,
							remarks = i18n.translatef("Shunt [%s] node", e.remarks),
							set = function(o, server)
								if not server then server = "" end
								uci_set(node_id, e[".name"], server)
								o.newNodeId = server
							end
						}
					end
				end
			end
		elseif node.protocol and node.protocol == '_balancing' then
			local flag = i18n.translatef("Xray Load Balancing node [%s] list", node_id)
			local currentNodes = {}
			local newNodes = {}
			if node.balancing_node then
				for k, b_node_id in pairs(node.balancing_node) do
					currentNodes[#currentNodes + 1] = {
						log = true,
						node = b_node_id,
						currentNode = (function()
							local section = uci_get(b_node_id) or {}
							if section[".type"] == "socks" then
								return { Socks = b_node_id }
							end
							return section
						end)(),
						remarks = b_node_id,
						set = function(o, server)
							if o and server and server ~= "nil" then
								table.insert(o.newNodes, server)
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = flag,
				currentNodes = currentNodes,
				newNodes = newNodes,
				set = function(o, newNodes)
					if o then
						if not newNodes then newNodes = o.newNodes end
						uci_set(node_id, "balancing_node", newNodes or {})
					end
				end
			}

			-- Backup Node
			local currentNode = uci_get(node_id) or nil
			if currentNode and currentNode.fallback_node then
				local section = uci_get(currentNode.fallback_node) or {}
				if section[".type"] == "nodes" then
					CONFIG[#CONFIG + 1] = {
						log = true,
						id = node_id,
						remarks = i18n.translatef("Xray Load Balancing node [%s] backup node", node_id),
						currentNode = section,
						set = function(o, server)
							uci_set(node_id, "fallback_node", server)
							o.newNodeId = server
						end,
						delete = function(o)
							uci_del(node_id, "fallback_node")
						end
					}
				end
			end
		elseif node.protocol and node.protocol == '_urltest' then
			local flag = i18n.translatef("Sing-Box URLTest node [%s] list", node_id)
			local currentNodes = {}
			local newNodes = {}
			if node.urltest_node then
				for k, u_node_id in pairs(node.urltest_node) do
					currentNodes[#currentNodes + 1] = {
						log = true,
						node = u_node_id,
						currentNode = (function()
							local section = uci_get(u_node_id) or {}
							if section[".type"] == "socks" then
								return { Socks = u_node_id }
							end
							return section
						end)(),
						remarks = u_node_id,
						set = function(o, server)
							if o and server and server ~= "nil" then
								table.insert(o.newNodes, server)
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = flag,
				currentNodes = currentNodes,
				newNodes = newNodes,
				set = function(o, newNodes)
					if o then
						if not newNodes then newNodes = o.newNodes end
						uci_set(node_id, "urltest_node", newNodes or {})
					end
				end
			}
		else
			-- Preproxy Node
			local currentNode = uci_get(node_id) or nil
			if currentNode and currentNode.preproxy_node then
				local section = uci_get(currentNode.preproxy_node) or {}
				if section[".type"] == "nodes" then
					CONFIG[#CONFIG + 1] = {
						log = true,
						id = node_id,
						remarks = i18n.translatef("Node [%s] preproxy node", node_id),
						currentNode = uci_get(currentNode.preproxy_node) or nil,
						set = function(o, server)
							uci_set(node_id, "preproxy_node", server)
							o.newNodeId = server
						end,
						delete = function(o)
							uci_del(node_id, "preproxy_node")
						end
					}
				end
			end
			-- Landing node
			local currentNode = uci_get(node_id) or nil
			if currentNode and currentNode.to_node then
				local section = uci_get(currentNode.to_node) or {}
				if section[".type"] == "nodes" then
					CONFIG[#CONFIG + 1] = {
						log = true,
						id = node_id,
						remarks = i18n.translatef("Node [%s] landing node", node_id),
						currentNode = uci_get(currentNode.to_node) or nil,
						set = function(o, server)
							uci_set(node_id, "to_node", server)
							o.newNodeId = server
						end,
						delete = function(o)
							uci_del(node_id, "to_node")
						end
					}
				end
			end
		end
	end)

	for k, v in pairs(CONFIG) do
		if v.currentNodes and type(v.currentNodes) == "table" then
			for kk, vv in pairs(v.currentNodes) do
				if vv.currentNode == nil then
					CONFIG[k].currentNodes[kk] = nil
				end
			end
		else
			if v.currentNode == nil then
				if v.delete then
					v.delete()
				end
				CONFIG[k] = nil
			end
		end
	end
end

-- Retrieve subscribe information (remaining data allowance, expiration time).
local subscribe_info = {}
local function get_subscribe_info(cfgid, value)
	if type(cfgid) ~= "string" or cfgid == "" or type(value) ~= "string" then
		return
	end
	value = value:gsub("%s+", "")
	local date_patterns = {"套餐到期：(.+)", "过期时间：(.+)", "有效期至：(.+)", "到期时间：(.+)", "截止日期：(.+)"}
	local expired_date
	for _, p in ipairs(date_patterns) do expired_date = value:match(p) or expired_date end
	local rem_patterns = {"剩余流量：(.+)", "流量剩余：(.+)", "可用流量：(.+)", "套餐剩余：(.+)"}
	local rem_traffic
	for _, p in ipairs(rem_patterns) do rem_traffic = value:match(p) or rem_traffic end
	subscribe_info[cfgid] = subscribe_info[cfgid] or {expired_date = "", rem_traffic = ""}
	if expired_date then
		subscribe_info[cfgid]["expired_date"] = expired_date
	end
	if rem_traffic then
		subscribe_info[cfgid]["rem_traffic"] = rem_traffic
	end
end

-- Configure the SS protocol implementation type
local function set_ss_implementation(ss_type, result)
	if ss_type == "shadowsocks-rust" and has_ss_rust then
		result.type = 'SS-Rust'
	elseif ss_type == "xray" and has_xray then
		result.type = 'Xray'
		result.protocol = 'shadowsocks'
		result.transport = 'raw'
	elseif ss_type == "sing-box" and has_singbox then
		result.type = 'sing-box'
		result.protocol = 'shadowsocks'
	else
		log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "SS", "SS"))
		return nil
	end
	return result
end

local function parseClashNode(node, add_mode, group, sub_cfg)
	local sub_allowinsecure = DEFAULT_ALLOWINSECURE
	local sub_ss_type = DEFAULT_SS_TYPE
	local sub_trojan_type = DEFAULT_TROJAN_TYPE
	local sub_vmess_type = DEFAULT_VMESS_TYPE
	local sub_vless_type = DEFAULT_VLESS_TYPE
	local sub_hysteria2_type = DEFAULT_HYSTERIA2_TYPE
	local sub_hy_up_mbps, sub_hy_down_mbps
	if sub_cfg then
		if sub_cfg.allowInsecure and sub_cfg.allowInsecure ~= "1" then
			sub_allowinsecure = nil
		end
		local ss_type = sub_cfg.ss_type or "global"
		if ss_type ~= "global" and core_has[ss_type] then
			sub_ss_type = ss_type
		end
		local trojan_type = sub_cfg.trojan_type or "global"
		if trojan_type ~= "global" and core_has[trojan_type] then
			sub_trojan_type = trojan_type
		end
		local vmess_type = sub_cfg.vmess_type or "global"
		if vmess_type ~= "global" and core_has[vmess_type] then
			sub_vmess_type = vmess_type
		end
		local vless_type = sub_cfg.vless_type or "global"
		if vless_type ~= "global" and core_has[vless_type] then
			sub_vless_type = vless_type
		end
		local hysteria2_type = sub_cfg.hysteria2_type or "global"
		if hysteria2_type ~= "global" and core_has[hysteria2_type] then
			sub_hysteria2_type = hysteria2_type
		end
		sub_hy_up_mbps = sub_cfg.hysteria_up_mbps
		sub_hy_down_mbps = sub_cfg.hysteria_down_mbps
	end
	local result = {
		timeout = 60,
		add_mode = add_mode, -- `0` for manual configuration, `1` for import, `2` for subscription
		group = group
	}
	result.remarks = node.name
	result.address = node.server
	result.port = node.port

	if node.type == 'ss' then
		result = set_ss_implementation(sub_ss_type, result)
		if not result then return nil end
		result.method = node.cipher
		result.ss_method = node.cipher
		result.password = node.password
		if node.plugin == "obfs" then
			result.plugin = "obfs-local"
		elseif node.plugin == "v2ray-plugin" then
			result.plugin = "v2ray-plugin"
		end
		if result.plugin then
			result.plugin_enabled = "1"
			if result.type == 'Xray' then
				if result.plugin ~= "obfs-local" then
					result.plugin_enabled = nil
					result.error_msg = i18n.translatef("%s unsupport SS %s plugin.", "Xray", result.plugin)
				end
			elseif result.type == 'sing-box' then
				if result.plugin ~= "obfs-local" and result.plugin ~= "v2ray-plugin" then
					result.plugin_enabled = nil
					result.error_msg = i18n.translatef("%s unsupport SS %s plugin.", "Sing-Box", result.plugin)
				end
			end
			if node["plugin-opts"] and result.plugin_enabled == "1" then
				if node.plugin == "obfs" then
					local plugin_opts = ""
					local opts_mode = node["plugin-opts"].mode
					if opts_mode then
						plugin_opts = plugin_opts .. "obfs=" .. opts_mode .. ";"
					end
					local opts_host = node["plugin-opts"].host
					if opts_host then
						plugin_opts = plugin_opts .. "obfs-host=" .. opts_host
					end
					result.plugin_opts = plugin_opts
				elseif node.plugin == "v2ray-plugin" then
					local plugin_opts = ""
					local opts_mode = node["plugin-opts"].mode
					local opts_tls = node["plugin-opts"].tls
					if opts_tls then
						plugin_opts = plugin_opts .. "tls;"
					end
					local opts_skip_cert_verify = node["plugin-opts"]["skip-cert-verify"]
					local opts_host = node["plugin-opts"].host
					if opts_host then
						plugin_opts = plugin_opts .. "host=" .. opts_host .. ";"
					end
					local opts_path = node["plugin-opts"].path
					local opts_mux = node["plugin-opts"].mux
					if node["plugin-opts"].headers then
						--todo
					end
					result.plugin_opts = plugin_opts
				end
			end
		end
	elseif node.type == 'ssr' then
		if not has_ssr then
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "SSR", "shadowsocksr-libev"))
			return nil
		end
		result.type = "SSR"
		result.method = node.cipher
		result.password = node.password
		result.obfs = node.obfs
		result.protocol = node.protocol
		result.obfs_param = node["obfs-param"]
		result.protocol_param = node["protocol-param"]
	elseif node.type == 'vmess' then
		if sub_vmess_type == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif sub_vmess_type == "xray" and has_xray then
			result.type = "Xray"
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "VMess", "VMess"))
			return nil
		end
		result.protocol = 'vmess'
		result.uuid = node.uuid
		result.alter_id = node.alterId
		result.security = node.cipher or "auto"
		result.tcp_fast_open = node.tfo
		result.tls = "0"
		if node.tls then
			result.tls = "1"
			result.tls_serverName = node.servername or ""
			local insecure = node["skip-cert-verify"]
			result.tls_allowInsecure = insecure and "1" or "0"
			if sub_allowinsecure then
				result.tls_allowInsecure = "1"
			end
		end
		result.transport = node.network and string.lower(node.network) or "tcp"
		if result.type == "sing-box" and result.transport == "raw" then
			result.transport = "tcp"
		elseif result.type == "Xray" and result.transport == "tcp" then
			result.transport = "raw"
		end
		if result.transport == 'ws' then
			local ws_opts = node["ws-opts"]
			if ws_opts then
				if ws_opts.headers then
					result.ws_host = ws_opts.headers.Host or ws_opts.headers.host
				end
				if ws_opts.path then
					result.ws_path = ws_opts.path
					if ws_opts["max-early-data"] then
						if result.type == "sing-box" then
							result.ws_enableEarlyData = "1"
							result.ws_maxEarlyData = tonumber(ws_opts["max-early-data"])
							result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
						elseif result.type == "Xray" then
							result.ws_path = result.ws_path .. "?ed=" .. ws_opts["max-early-data"]
						end
					end
				end
			end
		elseif result.transport == 'h2' then
			local h2_opts = node["h2-opts"]
			if h2_opts then
				if result.type == "sing-box" then
					result.http_path = h2_opts.path
					result.http_host = h2_opts.host
				elseif result.type == "Xray" then
					result.xhttp_mode = "stream-one"
					result.xhttp_path = h2_opts.path
					result.xhttp_host = h2_opts.host
				end
			end
		elseif result.transport == 'grpc' then
			local grpc_opts = node["grpc-opts"]
			if grpc_opts then
				result.grpc_serviceName = grpc_opts["grpc-service-name"]
			end
		end
	elseif node.type == 'vless' then
		if sub_vless_type == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif sub_vless_type == "xray" and has_xray then
			result.type = "Xray"
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "VLESS", "VLESS"))
			return nil
		end
		result.protocol = "vless"
		result.uuid = node.uuid
		result.tcp_fast_open = node.tfo
		result.encryption = node.cipher or "none"
		result.flow = node.flow
		result.tls = "0"
		if node.tls then
			result.tls = "1"
			result.tls_serverName = node.servername or ""
			local insecure = node["skip-cert-verify"]
			result.tls_allowInsecure = insecure and "1" or "0"
			if sub_allowinsecure then
				result.tls_allowInsecure = "1"
			end
		end
		if node.tls and node["reality-opts"] and node["reality-opts"]["public-key"] then
			result.reality = "1"
			result.reality_publicKey = (node["reality-opts"] and node["reality-opts"]["public-key"]) or nil
			result.reality_shortId = (node["reality-opts"] and node["reality-opts"]["short-id"]) or nil
		end
		result.transport = node.network and string.lower(node.network) or "tcp"
		if result.type == "sing-box" and result.transport == "raw" then
			result.transport = "tcp"
		elseif result.type == "Xray" and result.transport == "tcp" then
			result.transport = "raw"
		end
		if result.transport == 'ws' then
			local ws_opts = node["ws-opts"]
			if ws_opts then
				if ws_opts.headers then
					result.ws_host = ws_opts.headers.Host or ws_opts.headers.host
				end
				if ws_opts.path then
					result.ws_path = ws_opts.path
					if ws_opts["max-early-data"] then
						if result.type == "sing-box" then
							result.ws_enableEarlyData = "1"
							result.ws_maxEarlyData = tonumber(ws_opts["max-early-data"])
							result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
						elseif result.type == "Xray" then
							result.ws_path = result.ws_path .. "?ed=" .. ws_opts["max-early-data"]
						end
					end
				end
			end
		end
	elseif node.type == 'trojan' then
		if sub_trojan_type == "sing-box" and has_singbox then
			result.type = 'sing-box'
			result.protocol = 'trojan'
		elseif sub_trojan_type == "xray" and has_xray then
			result.type = 'Xray'
			result.protocol = 'trojan'
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "Trojan", "Trojan"))
			return nil
		end
		result.password = node.password
		result.tls = '1'
		result.tls_serverName = node.sni or ""
		local insecure = node["skip-cert-verify"]
		result.tls_allowInsecure = insecure and "1" or "0"
		if sub_allowinsecure then
			result.tls_allowInsecure = "1"
		end
		if node.alpn then
			--todo
		end
		if node.network == "grpc" then
			if node["grpc-opts"] then
				result.grpc_serviceName = node["grpc-opts"]["grpc-service-name"]
			end
		elseif node.network == "ws" then
			local ws_opts = node["ws-opts"]
			if ws_opts then
				result.ws_path = ws_opts.path
				if ws_opts.headers then
					result.ws_host = ws_opts.headers.Host or ws_opts.headers.host
				end
			end
		end
	elseif node.type == 'anytls' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "anytls"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "AnyTLS", "Sing-Box 1.12"))
			return nil
		end
		result.password = node.password
		result.tls = '1'
		result.tls_serverName = node.sni or ""
		local insecure = node["skip-cert-verify"]
		result.tls_allowInsecure = insecure and "1" or "0"
		if sub_allowinsecure then
			result.tls_allowInsecure = "1"
		end
		if node["client-fingerprint"] then
			result.utls = "1"
			result.fingerprint = node["client-fingerprint"]
		end
		if node.tls and node["reality-opts"] and node["reality-opts"]["public-key"] then
			result.reality = "1"
			result.reality_publicKey = node["reality-opts"]["public-key"]
			result.reality_shortId = node["reality-opts"]["short-id"]
		end
		if node["disable-reuse"] then
			result.anytls_disable_reuse = "1"
		end
	elseif node.type == 'snell' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "snell"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "Snell", "Sing-Box 1.14"))
			return nil
		end
		result.password = node.password
		result.snell_psk = node.psk
		result.snell_version = node.version or "4"
		if result.snell_version == "4" then
			local obfs_opts = node["obfs-opts"] or {}
			result.snell_obfs_mode = obfs_opts.mode or "none"
			result.snell_obfs_host = obfs_opts.host
		else
			result.snell_mode = "default"
		end
		result.snell_reuse = node.reuse and "1" or "0"
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	return result
end

-- Processing Clash data
local function processClashData(content, add_mode, group, sub_cfg)
	local results = {}
	for i, node in ipairs(content.proxies or {}) do
		local result = parseClashNode(node, add_mode, group, sub_cfg)
		if result then
			table.insert(results, result)
		end
	end
	return results
end

-- Processing data
local function processData(szType, content, add_mode, group, sub_cfg)
	--log(2, content, add_mode, group)
	local sub_allowinsecure = DEFAULT_ALLOWINSECURE
	local sub_ss_type = DEFAULT_SS_TYPE
	local sub_trojan_type = DEFAULT_TROJAN_TYPE
	local sub_vmess_type = DEFAULT_VMESS_TYPE
	local sub_vless_type = DEFAULT_VLESS_TYPE
	local sub_hysteria2_type = DEFAULT_HYSTERIA2_TYPE
	local sub_hy_up_mbps, sub_hy_down_mbps
	if sub_cfg then
		if sub_cfg.allowInsecure and sub_cfg.allowInsecure ~= "1" then
			sub_allowinsecure = nil
		end
		local ss_type = sub_cfg.ss_type or "global"
		if ss_type ~= "global" and core_has[ss_type] then
			sub_ss_type = ss_type
		end
		local trojan_type = sub_cfg.trojan_type or "global"
		if trojan_type ~= "global" and core_has[trojan_type] then
			sub_trojan_type = trojan_type
		end
		local vmess_type = sub_cfg.vmess_type or "global"
		if vmess_type ~= "global" and core_has[vmess_type] then
			sub_vmess_type = vmess_type
		end
		local vless_type = sub_cfg.vless_type or "global"
		if vless_type ~= "global" and core_has[vless_type] then
			sub_vless_type = vless_type
		end
		local hysteria2_type = sub_cfg.hysteria2_type or "global"
		if hysteria2_type ~= "global" and core_has[hysteria2_type] then
			sub_hysteria2_type = hysteria2_type
		end
		sub_hy_up_mbps = sub_cfg.hysteria_up_mbps
		sub_hy_down_mbps = sub_cfg.hysteria_down_mbps
	end
	local result = {
		timeout = 60,
		add_mode = add_mode, -- `0` for manual configuration, `1` for import, `2` for subscription
		group = group
	}
	--ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks&group=base64group&udpport=0&uot=0)
	if szType == 'ssr' then
		if not has_ssr then
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "SSR", "shadowsocksr-libev"))
			return nil
		end
		result.type = "SSR"

		local dat = split(content:gsub("/%?", "?"), "%?")
		local hostInfo = split(dat[1], ':')
		if dat[1]:match('%[(.*)%]') then
			result.address = dat[1]:match('%[(.*)%]')
		else
			result.address = hostInfo[#hostInfo-5]
		end
		result.port = hostInfo[#hostInfo-4]
		result.protocol = hostInfo[#hostInfo-3]
		result.method = hostInfo[#hostInfo-2]
		result.obfs = hostInfo[#hostInfo-1]
		result.password = base64Decode(hostInfo[#hostInfo])
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local s = v:find("=", 1, true)
			if s and s > 1 then
				params[v:sub(1, s - 1)] = v:sub(s + 1)
			end
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		-- local ssr_group = base64Decode(params.group)
		-- if ssr_group then result.ssr_group = ssr_group end
		result.remarks = base64Decode(params.remarks)
	elseif szType == 'vmess' then
		if sub_vmess_type == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif sub_vmess_type == "xray" and has_xray then
			result.type = "Xray"
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "VMess", "VMess"))
			return nil
		end
		-- vmess://base64(json)
		local info = jsonParse(content)
		if not info then
			-- vmess://base64(auto:uuid@host:port)?tfo=1&remark=xxx&&alterId=0&obfs=websocket&path=%2F&obfsParam=host (obfs ~= ws obfsParam={})
			if content:find("?", 1, true) then
				info = {}
				local Info = split(content:gsub("/%?", "?"), "%?")
				local sp = split(base64Decode(Info[1]), "@")
				local id_info = split(sp[1], ":")
				info.security = (#id_info > 1 and id_info[1] ~= "") and id_info[1] or "auto"
				info.id = id_info[#id_info]

				local addr, port = sp[2], "443"
				if api.is_ipv6addrport(addr) then
					local a, p = addr:match("^%[(.+)%]:(%d+)$")
					if a then addr, port = a, p end
					addr = api.get_ipv6_only(addr)
				else
					local host_port = split(addr, ":")
					addr = host_port[1]
					if #host_port > 1 then port = host_port[#host_port] end
				end
				info.add, info.port = addr, port

				local params = {}
				for _, v in pairs(split(Info[2], '&')) do
					local s = v:find("=", 1, true)
					if s and s > 1 then
						params[v:sub(1, s - 1)] = UrlDecode(v:sub(s + 1))
					end
				end
				info.ps = params.remark or params.remarks
				info.net = (params.obfs == "websocket") and "ws" or (params.obfs or "tcp")
				info.path = params.path
				info.aid = params.alterId or "0"
				info.tls = params.tls
				info.sni = params.peer
				info.tfo = params.tfo
				local op_info = jsonParse(params.obfsParam)
				if op_info then
					if op_info.header then info.type = op_info.header end
					if op_info.Host then info.host = op_info.Host end
				else
					info.host = params.obfsParam
				end
				info.allowinsecure = params.allowInsecure
			else
				log(2, i18n.translatef("Skipping %s node. This node URI format cannot be parsed."))
				return nil
			end
		end

		result.address = info.add
		result.port = info.port
		result.protocol = 'vmess'
		result.alter_id = info.aid
		result.uuid = info.id
		result.remarks = info.ps
		-- result.mux = 1
		-- result.mux_concurrency = 8

		info.path = (info.path and info.path ~= "") and UrlDecode(info.path) or nil

		if not info.net then info.net = "tcp" end
		info.net = string.lower(info.net)
		if result.type == "sing-box" and info.net == "raw" then
			info.net = "tcp"
		elseif result.type == "Xray" and info.net == "tcp" then
			info.net = "raw"
		end
		if info.net == 'h2' or info.net == 'http' then
			info.net = "http"
			result.transport = (result.type == "Xray") and "xhttp" or "http"
		else
			result.transport = info.net
		end
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
			if result.type == "sing-box" and info.path then
				local ws_path_dat = split(info.path, "?")
				local ws_path = ws_path_dat[1]
				local ws_path_params = {}
				for _, v in pairs(split(ws_path_dat[2], '&')) do
					local t = split(v, '=')
					ws_path_params[t[1]] = t[2]
				end
				if ws_path_params.ed and tonumber(ws_path_params.ed) then
					result.ws_path = ws_path
					result.ws_enableEarlyData = "1"
					result.ws_maxEarlyData = tonumber(ws_path_params.ed)
					result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
				end
			end
		end
		if info.net == "http" then
			if result.type == "Xray" then
				result.xhttp_mode = "stream-one"
				result.xhttp_host = info.host
				result.xhttp_path = info.path
			else
				result.http_host = (info.host and info.host ~= "") and { info.host } or nil
				result.http_path = info.path
			end
		end
		if info.net == 'raw' or info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.tcp_guise_http_host = (info.host and info.host ~= "") and { info.host } or nil
			result.tcp_guise_http_path = (info.path and info.path ~= "") and { info.path } or nil
		end
		if info.net == 'kcp' or info.net == 'mkcp' then
			info.net = "mkcp"
			result.mkcp_guise = info.type
			result.mkcp_seed = info.seed
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if info.net == 'grpc' then
			result.grpc_serviceName = info.path
		end
		if info.net == 'xhttp' or info.net == 'splithttp' then
			result.xhttp_host = info.host
			result.xhttp_path = info.path
			result.xhttp_mode = params.mode or "auto"
			result.xhttp_extra = params.extra
			local success, Data = pcall(jsonParse, params.extra)
				if success and Data then
					local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
							or (Data.downloadSettings and Data.downloadSettings.address)
					result.download_address = address and address ~= "" and address or nil
				else
					result.download_address = nil
				end
		end
		if info.net == 'httpupgrade' then
			result.httpupgrade_host = info.host
			result.httpupgrade_path = info.path
		end
		result.security = info.security or info.scy or "auto"
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.alpn = info.alpn
			if info.fp and info.fp ~= "" then
				result.utls = "1"
				result.fingerprint = info.fp
			end
			result.tls_serverName = (info.sni and info.sni ~= "") and info.sni or info.host
			result.tls_pinSHA256 = info.pcs
			result.tls_CertByName = info.vcn
			local insecure = info.allowinsecure or info.allowInsecure or info.insecure
			result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
		else
			result.tls = "0"
		end

		if info.ech and info.ech ~= "" then
			result.ech = "1"
			result.ech_config = info.ech
		end

		result.tcp_fast_open = info.tfo

		info.fm = (info.fm and info.fm ~= "") and UrlDecode(info.fm) or nil
		result.use_finalmask = (info.fm and info.fm ~= "") and "1" or nil
		result.finalmask = (info.fm and info.fm ~= "") and api.base64Encode(info.fm) or nil

		if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp") then
			log(2, i18n.translatef("Skip node: %s. Because Sing-Box does not support the %s protocol's %s transmission method, Xray needs to be used instead.", result.remarks, szType, result.transport))
			return nil
		end
	elseif szType == "ss" then
		result = set_ss_implementation(sub_ss_type, result)
		if not result then return nil end

		--SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
		--userinfo = websafe-base64-encode-utf8(method  ":" password)
		--ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1
		--ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888/?plugin=v2ray-plugin%3Bserver#Example3
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@xxxxxx.com:443?type=ws&path=%2Ftestpath&host=xxxxxx.com&security=tls&fp=&alpn=h3%2Ch2%2Chttp%2F1.1&sni=xxxxxx.com#test-1%40ss

		local idx_sp = content:find("#") or 0
		local alias = ""
		if idx_sp > 0 then
			alias = content:sub(idx_sp + 1, -1)
		end
		result.remarks = UrlDecode(alias)
		local info = content:sub(1, idx_sp - 1):gsub("/%?", "?")
		local params = {}
		if info:find("%?") then
			local find_index = info:find("%?")
			local query = split(info, "%?")
			for _, v in pairs(split(query[2], '&')) do
				local s = v:find("=", 1, true)
				if s and s > 1 then
					params[v:sub(1, s - 1)] = UrlDecode(v:sub(s + 1))
				end
			end
			if params.plugin then
				local plugin_info = params.plugin
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts = plugin_info:sub(idx_pn + 1, #plugin_info)
					-- Some ShadowTLS subscriptions utilize SIP003.
					result.plugin_opts = result.plugin_opts:gsub("^password=", "passwd=")
					result.plugin_opts = result.plugin_opts:gsub(";password=", ";passwd=")
					result.plugin_opts = result.plugin_opts:gsub("^version=([123])", "v%1=1")
					result.plugin_opts = result.plugin_opts:gsub(";version=([123])", ";v%1=1")
				else
					result.plugin = plugin_info
				end
			end
			if result.plugin and result.plugin == "simple-obfs" then
				result.plugin = "obfs-local"
			end
			info = info:sub(1, find_index - 1)
		end

		local hostInfo = split(base64Decode(UrlDecode(info)), "@")
		if hostInfo and #hostInfo > 0 then
			local host_port = hostInfo[#hostInfo]
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				result.port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local userinfo = nil
			if #hostInfo > 2 then
				userinfo = {}
				for i = 1, #hostInfo - 1 do
					tinsert(userinfo, hostInfo[i])
				end
				userinfo = table.concat(userinfo, '@')
			else
				userinfo = base64Decode(hostInfo[1])
			end
			local method, password
			if userinfo:find(":") then
				method = userinfo:sub(1, userinfo:find(":") - 1)
				password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
			else
				password = hostInfo[1]  -- Some links use plaintext UUIDs as passwords.
			end

			-- Determine if the password is URL encoded
			local function isURLEncodedPassword(pwd)
				if not pwd:find("%%[0-9A-Fa-f][0-9A-Fa-f]") then
					return false
				end
				local ok, decoded = pcall(UrlDecode, pwd)
				return ok and UrlEncode(decoded) == pwd
			end

			local decoded = UrlDecode(password)
			if isURLEncodedPassword(password) and decoded then
				password = decoded
			end

			local _method = (method or "none"):lower()
			method = (_method == "chacha20-poly1305" and "chacha20-ietf-poly1305") or
				(_method == "xchacha20-poly1305" and "xchacha20-ietf-poly1305") or _method

			result.method = method
			result.ss_method = method
			result.password = password
			result.tcp_fast_open = params.tfo
			result.use_finalmask = (params.fm and params.fm ~= "") and "1" or nil
			result.finalmask = (params.fm and params.fm ~= "") and api.base64Encode(params.fm) or nil

			local need_upgrade = (result.type ~= "Xray" and result.type ~= "sing-box")
				and (params.type and params.type ~= "tcp")
				and (params.headerType and params.headerType ~= "none")
			if has_xray and (need_upgrade or params.type == "xhttp") then
				result.type = "Xray"
				result.protocol = "shadowsocks"
			elseif has_singbox and need_upgrade then
				result.type = "sing-box"
				result.protocol = "shadowsocks"
			end

			if result.plugin then
				if result.type == 'Xray' then
					-- The obfs-local plugin converts data to a format supported by xray.
					if result.plugin ~= "obfs-local" then
						result.error_msg = i18n.translatef("%s unsupport SS %s plugin.", "Xray", result.plugin)
					else
						local obfs = result.plugin_opts:match("obfs=([^;]+)") or ""
						local obfs_host = result.plugin_opts:match("obfs%-host=([^;]+)") or ""
						if obfs == "" or obfs_host == "" then
							result.error_msg = "SS " .. result.plugin .. " " .. i18n.translatef("Plugin options Incomplete.")
						end
						if obfs == "http" then
							result.transport = "raw"
							result.tcp_guise = "http"
							result.tcp_guise_http_host = (obfs_host and obfs_host ~= "") and { obfs_host } or nil
							result.tcp_guise_http_path = { "/" }
						elseif obfs == "tls" then
							result.tls = "1"
							result.tls_serverName = obfs_host
							result.tls_allowInsecure = "1"
						end
						result.plugin = nil
						result.plugin_opts = nil
					end
				elseif result.type == 'sing-box' then
					if result.plugin ~= "obfs-local" and result.plugin ~= "v2ray-plugin" and result.plugin ~= "shadow-tls" then
						result.error_msg = i18n.translatef("%s unsupport SS %s plugin.", "Sing-Box", result.plugin)
					else
						result.plugin_enabled = "1"
						-- Some ShadowTLS subscriptions utilize SIP003.
						if result.plugin == "shadow-tls" then
							for item in result.plugin_opts:gmatch("[^;]+") do
								local key, value = item:match("^([^=]+)=(.*)$")
								if key == "host" then result.shadowtls_serverName = value end
								if key == "passwd" then result.shadowtls_password = value end
								if key:match("^v[123]$") then result.shadowtls_version = key:sub(2) end
							end
							result.shadowtls = "1"
							result.plugin_opts = nil
							result.plugin_enabled = nil
						end
					end
				else
					result.plugin_enabled = "1"
				end
			end

			if params.type then
				params.type = string.lower(params.type)
				if result.type == "sing-box" and params.type == "raw" then
					params.type = "tcp"
				elseif result.type == "Xray" and params.type == "tcp" then
					params.type = "raw"
				end
				if params.type == "h2" or params.type == "http" then
					params.type = "http"
					result.transport = (result.type == "Xray") and "xhttp" or "http"
				else
					result.transport = params.type
				end
				if result.type ~= "SS-Rust" then
					if params.type == 'ws' then
						result.ws_host = params.host
						result.ws_path = params.path
						if result.type == "sing-box" and params.path then
							local ws_path_dat = split(params.path, "%?")
							local ws_path = ws_path_dat[1]
							local ws_path_params = {}
							for _, v in pairs(split(ws_path_dat[2], '&')) do
								local t = split(v, '=')
								ws_path_params[t[1]] = t[2]
							end
							if ws_path_params.ed and tonumber(ws_path_params.ed) then
								result.ws_path = ws_path
								result.ws_enableEarlyData = "1"
								result.ws_maxEarlyData = tonumber(ws_path_params.ed)
								result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
							end
						end
					end
					if params.type == "http" then
						if result.type == "sing-box" then
							result.transport = "http"
							result.http_host = (params.host and params.host ~= "") and { params.host } or nil
							result.http_path = params.path
						elseif result.type == "Xray" then
							result.transport = "xhttp"
							result.xhttp_mode = "stream-one"
							result.xhttp_host = params.host
							result.xhttp_path = params.path
						end
					end
					if params.type == 'raw' or params.type == 'tcp' then
						result.tcp_guise = params.headerType or "none"
						result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
						result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
					end
					if params.type == 'kcp' or params.type == 'mkcp' then
						result.transport = "mkcp"
						result.mkcp_guise = params.headerType or "none"
						result.mkcp_seed = params.seed
					end
					if params.type == 'quic' then
						result.quic_guise = params.headerType or "none"
						result.quic_key = params.key
						result.quic_security = params.quicSecurity or "none"
					end
					if params.type == 'grpc' then
						if params.path then result.grpc_serviceName = params.path end
						if params.serviceName then result.grpc_serviceName = params.serviceName end
						result.grpc_mode = params.mode or "gun"
					end
					if params.type == 'xhttp' then
						if result.type ~= "Xray" then
							result.error_msg = i18n.translatef("Please replace %s to support %s transmission method.", "Xray", "xhttp")
						end
						result.xhttp_host = params.host
						result.xhttp_path = params.path
						result.xhttp_mode = params.mode or "auto"
						result.use_xhttp_extra = (params.extra and params.extra ~= "") and "1" or nil
						result.xhttp_extra = (params.extra and params.extra ~= "") and api.base64Encode(params.extra) or nil
						local success, Data = pcall(jsonParse, params.extra)
						if success and Data then
							local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
									or (Data.downloadSettings and Data.downloadSettings.address)
							result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "") or nil
						end
					end
					result.tls = "0"
					if params.security == "tls" or params.security == "reality" then
						result.tls = "1"
						result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
						result.alpn = params.alpn
						if params.fp and params.fp ~= "" then
							result.utls = "1"
							result.fingerprint = params.fp
						end
						if params.ech and params.ech ~= "" then
							result.ech = "1"
							result.ech_config = params.ech
						end
						result.tls_pinSHA256 = params.pcs
						result.tls_CertByName = params.vcn
						if params.security == "reality" then
							result.reality = "1"
							result.reality_publicKey = params.pbk or nil
							result.reality_shortId = params.sid or nil
							result.reality_spiderX = params.spx or nil
							result.use_mldsa65Verify = (params.pqv and params.pqv ~= "") and "1" or nil
							result.reality_mldsa65Verify = params.pqv or nil
						end
					end
					local insecure = params.allowinsecure or params.allowInsecure or params.insecure
					result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
					result.uot = params.udp
				else
					result.error_msg = i18n.translatef("Please replace Xray or Sing-Box to support more transmission methods in Shadowsocks.")
				end
			end

			if params["shadow-tls"] then
				if result.type ~= "sing-box" and result.type ~= "SS-Rust" then
					result.error_msg =  sub_ss_type .. " " .. i18n.translatef("unsupport %s plugin.", "shadow-tls")
				else
					-- Parsing SS Shadow-TLS plugin parameters
					local function parseShadowTLSParams(b64str, out)
						local ok, data = pcall(jsonParse, base64Decode(b64str))
						if not ok or type(data) ~= "table" then return "" end
						if type(out) == "table" then
							for k, v in pairs(data) do out[k] = v end
						end
						local t = {}
						if data.version then t[#t+1] = "v" .. data.version .. "=1" end
						if data.password then t[#t+1] = "passwd=" .. data.password end
						for k, v in pairs(data) do
							if k ~= "version" and k ~= "password" then
								t[#t+1] = k .. "=" .. tostring(v)
							end
						end
						return table.concat(t, ";")
					end

					if result.type == "SS-Rust" then
						result.plugin_enabled = "1"
						result.plugin = "shadow-tls"
						result.plugin_opts = parseShadowTLSParams(params["shadow-tls"])
					elseif result.type == "sing-box" then
						local shadowtlsOpt = {}
						parseShadowTLSParams(params["shadow-tls"], shadowtlsOpt)
						if next(shadowtlsOpt) then
							result.shadowtls = "1"
							result.shadowtls_version = shadowtlsOpt.version or "1"
							result.shadowtls_password = shadowtlsOpt.password
							result.shadowtls_serverName = shadowtlsOpt.host
							if shadowtlsOpt.fingerprint then
								result.shadowtls_utls = "1"
								result.shadowtls_fingerprint = shadowtlsOpt.fingerprint or "chrome"
							end
						end
					end
				end
			end
		end
	elseif szType == "trojan" then
		if sub_trojan_type == "sing-box" and has_singbox then
			result.type = 'sing-box'
			result.protocol = 'trojan'
		elseif sub_trojan_type == "xray" and has_xray then
			result.type = 'Xray'
			result.protocol = 'trojan'
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "Trojan", "Trojan"))
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "%?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local s = v:find("=", 1, true)
				if s and s > 1 then
					params[v:sub(1, s - 1)] = UrlDecode(v:sub(s + 1))
				end
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			result.port = port

			params.security = params.security or "tls"
			if params.security == "tls" or params.security == "reality" then
				result.tls = '1'
				result.tls_serverName = params.peer or params.sni or ""
				result.alpn = params.alpn
				if params.fp and params.fp ~= "" then
					result.utls = "1"
					result.fingerprint = params.fp
				end
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
				end
				if params.ech and params.ech ~= "" then
					result.ech = "1"
					result.ech_config = params.ech
				end
				result.tls_pinSHA256 = params.pcs
				result.tls_CertByName = params.vcn
				local insecure = params.allowinsecure or params.allowInsecure or params.insecure
				result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
			end

			if not params.type then params.type = "tcp" end
			params.type = string.lower(params.type)
			if result.type == "sing-box" and params.type == "raw" then
				params.type = "tcp"
			elseif result.type == "Xray" and params.type == "tcp" then
				params.type = "raw"
			end
			if params.type == "h2" or params.type == "http" then
				params.type = "http"
				result.transport = (result.type == "Xray") and "xhttp" or "http"
			else
				result.transport = params.type
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "%?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == "http" then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = (params.host and params.host ~= "") and { params.host } or nil
					result.http_path = params.path
				elseif result.type == "Xray" then
					result.transport = "xhttp"
					result.xhttp_mode = "stream-one"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
				end
			end
			if params.type == 'raw' or params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
				result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				result.grpc_serviceName = params.serviceName or params.path
				result.grpc_mode = params.mode or "gun"
			end
			if params.type == 'xhttp' then
				result.xhttp_host = params.host
				result.xhttp_path = params.path
			end
			if params.type == 'httpupgrade' then
				result.httpupgrade_host = params.host
				result.httpupgrade_path = params.path
			end

			result.tcp_fast_open = params.tfo
			result.use_finalmask = (params.fm and params.fm ~= "") and "1" or nil
			result.finalmask = (params.fm and params.fm ~= "") and api.base64Encode(params.fm) or nil

			if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp") then
				log(2, i18n.translatef("Skip node: %s. Because Sing-Box does not support the %s protocol's %s transmission method, Xray needs to be used instead.", result.remarks, szType, result.transport))
				return nil
			end
		end
	elseif szType == "ssd" then
		result = set_ss_implementation(sub_ss_type, result)
		if not result then return nil end
		result.address = content.server
		result.port = content.port
		result.password = content.password
		result.method = content.encryption
		result.ss_method = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.group = content.airport
		result.remarks = content.remarks
	elseif szType == "vless" then
		if sub_vless_type == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif sub_vless_type == "xray" and has_xray then
			result.type = "Xray"
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "VLESS", "VLESS"))
			return nil
		end
		result.protocol = "vless"
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.uuid = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "%?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local s = v:find("=", 1, true)
				if s and s > 1 then
					params[v:sub(1, s - 1)] = UrlDecode(v:sub(s + 1))
				end
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			if not params.type then params.type = "tcp" end
			params.type = string.lower(params.type)
			if ({ xhttp=true, kcp=true, mkcp=true })[params.type] and result.type ~= "Xray" and has_xray then
				result.type = "Xray"
			end
			if result.type == "sing-box" and params.type == "raw" then
				params.type = "tcp"
			elseif result.type == "Xray" and params.type == "tcp" then
				params.type = "raw"
			end
			if params.type == "h2" or params.type == "http" then
				params.type = "http"
				result.transport = (result.type == "Xray") and "xhttp" or "http"
			else
				result.transport = params.type
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "%?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == "http" then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = (params.host and params.host ~= "") and { params.host } or nil
					result.http_path = params.path
				elseif result.type == "Xray" then
					result.transport = "xhttp"
					result.xhttp_mode = "stream-one"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
				end
			end
			if params.type == 'raw' or params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = (params.host and params.host ~= "") and { params.host } or nil
				result.tcp_guise_http_path = (params.path and params.path ~= "") and { params.path } or nil
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode or "gun"
			end
			if params.type == 'xhttp' or params.type == 'splithttp' then
				result.xhttp_host = params.host
				result.xhttp_path = params.path
				result.xhttp_mode = params.mode or "auto"
				result.use_xhttp_extra = (params.extra and params.extra ~= "") and "1" or nil
				result.xhttp_extra = (params.extra and params.extra ~= "") and api.base64Encode(params.extra) or nil
				local success, Data = pcall(jsonParse, params.extra)
				if success and Data then
					local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
							or (Data.downloadSettings and Data.downloadSettings.address)
					result.download_address = (address and address ~= "") and address:gsub("^%[", ""):gsub("%]$", "") or nil
				end
			end
			if params.type == 'httpupgrade' then
				result.httpupgrade_host = params.host
				result.httpupgrade_path = params.path
			end
			result.encryption = params.encryption or "none"
			result.flow = params.flow

			if (not params.security or params.security == "") and params.flow then
				params.security = "tls"
			end

			result.tls = "0"
			if params.security == "tls" or params.security == "reality" then
				result.tls = "1"
				result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
				result.alpn = params.alpn
				if params.fp and params.fp ~= "" then
					result.utls = "1"
					result.fingerprint = params.fp
				end
				if params.ech and params.ech ~= "" then
					result.ech = "1"
					result.ech_config = params.ech
				end
				result.tls_pinSHA256 = params.pcs
				result.tls_CertByName = params.vcn
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
					result.reality_spiderX = params.spx or nil
					result.use_mldsa65Verify = (params.pqv and params.pqv ~= "") and "1" or nil
					result.reality_mldsa65Verify = params.pqv or nil
				end
				local insecure = params.allowinsecure or params.allowInsecure or params.insecure
				result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
			end

			result.port = port
			result.tcp_fast_open = params.tfo
			result.use_finalmask = (params.fm and params.fm ~= "") and "1" or nil
			result.finalmask = (params.fm and params.fm ~= "") and api.base64Encode(params.fm) or nil

			if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp") then
				log(2, i18n.translatef("Skip node: %s. Because Sing-Box does not support the %s protocol's %s transmission method, Xray needs to be used instead.", result.remarks, szType, result.transport))
				return nil
			end
		end
	elseif szType == 'hysteria' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "hysteria"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "Hysteria", "Sing-Box"))
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)

		local query = split(content:gsub("/%?", "?"), '%?')
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local s = v:find("=", 1, true)
			if s and s > 1 then
				params[v:sub(1, s - 1)] = v:sub(s + 1)
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.hysteria_obfs = params.obfsParam
		result.hysteria_auth_type = "string"
		result.hysteria_auth_password = params.auth
		result.tls_serverName = params.peer or params.sni or ""
		result.tls_pinSHA256 = params.pcs or params.pinSHA256
		local insecure = params.allowinsecure or params.allowInsecure or params.insecure
		result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
		result.alpn = params.alpn
		result.hysteria_up_mbps = params.upmbps or sub_hy_up_mbps
		result.hysteria_down_mbps = params.downmbps or sub_hy_down_mbps
		result.hysteria_hop = params.mport

	elseif szType == 'hysteria2' or szType == 'hy2' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local contents = split(content, "@")
			result.hysteria2_auth_password = UrlDecode(contents[1])
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local s = v:find("=", 1, true)
			if s and s > 1 then
				params[v:sub(1, s - 1):lower()] = UrlDecode(v:sub(s + 1))
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		result.tls_pinSHA256 = params.pcs or params.pinsha256
		result.tls_CertByName = params.vcn
		local insecure = params.allowinsecure or params.insecure
		result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
		result.hysteria2_up_mbps = params.upmbps or sub_hy_up_mbps
		result.hysteria2_down_mbps = params.downmbps or sub_hy_down_mbps
		result.hysteria2_hop = params.mport
		if params["obfs-password"] or params["obfs_password"] then
			result.hysteria2_obfs_type = params.obfs or "salamander"
			result.hysteria2_obfs_password = params["obfs-password"] or params["obfs_password"]
		end
		if params.obfs == "gecko" then
			result.hysteria2_obfs_MinPacketSize = params.minpacketsize or "512"
			result.hysteria2_obfs_MaxPacketSize = params.maxpacketsize or "1200"
		end

		if (sub_hysteria2_type == "sing-box" and has_singbox) or (sub_hysteria2_type == "xray" and has_xray) then
			local is_singbox = sub_hysteria2_type == "sing-box" and has_singbox
			result.type = is_singbox and 'sing-box' or 'Xray'
			result.protocol = "hysteria2"
			result.use_finalmask = (params.fm and params.fm ~= "") and "1" or nil
			result.finalmask = (params.fm and params.fm ~= "") and api.base64Encode(params.fm) or nil
		else
			log(2, i18n.translatef("Skipping the %s node is due to incompatibility with the %s core program or incorrect node usage type settings.", "Hysteria2", "Hysteria2"))
			return nil
		end
	elseif szType == 'tuic' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "tuic"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "Tuic", "Sing-Box"))
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@", 1, true) then
			local contents = split(content, "@")
			local auth = contents[1] or ""
			local idx = auth:find(":", 1, true)
			if not idx then -- Fix for some links will encode the ':' between the UUID and password.
				auth = UrlDecode(auth)
				idx = auth:find(":", 1, true)
			end
			if idx then
				result.uuid = UrlDecode(auth:sub(1, idx - 1))
				result.password = UrlDecode(auth:sub(idx + 1))
			end
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local s = v:find("=", 1, true)
			if s and s > 1 then
				params[v:sub(1, s - 1):lower()] = UrlDecode(v:sub(s + 1))
			end
		end
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		result.tls_disable_sni = params.disable_sni
		result.tls_pinSHA256 = params.pcs or params.pinsha256
		result.tuic_alpn = params.alpn or "h3"
		result.tuic_congestion_control = params.congestion_control or "cubic"
		result.tuic_udp_relay_mode = params.udp_relay_mode or "native"
		local insecure = params.allowinsecure or params.insecure or params.allow_insecure
		result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
	elseif szType == "anytls" then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "anytls"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "AnyTLS", "Sing-Box 1.12"))
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "%?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local s = v:find("=", 1, true)
				if s and s > 1 then
					params[v:sub(1, s - 1):lower()] = UrlDecode(v:sub(s + 1))
				end
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end
			result.tls = "0"
			if not params.security or params.security == "" then
				params.security = "tls"
			end
			if params.security == "tls" or params.security == "reality" then
				result.tls = "1"
				result.tls_serverName = params.sni or params.peer
				result.tls_pinSHA256 = params.pcs or params.pinsha256
				result.alpn = params.alpn
				if params.fp and params.fp ~= "" then
					result.utls = "1"
					result.fingerprint = params.fp
				end
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
				end
				if params.ech and params.ech ~= "" then
					result.ech = "1"
					result.ech_config = params.ech
				end
			end
			result.port = port
			local insecure = params.allowinsecure or params.insecure
			result.tls_allowInsecure = (insecure == "1" or insecure == "0") and insecure or (sub_allowinsecure and "1" or "0")
		end
	elseif szType == 'naive+https' or szType == 'naive+quic' then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "naive"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "NaïveProxy", "Sing-Box"))
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@", 1, true) then
			local contents = split(content, "@")
			local auth = contents[1] or ""
			local idx = auth:find(":", 1, true)
			if not idx then -- Fixed some links that encode the colon between username and password.
				auth = UrlDecode(auth)
				idx = auth:find(":", 1, true)
			end
			if idx then
				result.username = UrlDecode(auth:sub(1, idx - 1))
				result.password = UrlDecode(auth:sub(idx + 1))
			end
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local s = v:find("=", 1, true)
			if s and s > 1 then
				params[v:sub(1, s - 1)] = UrlDecode(v:sub(s + 1))
			end
		end
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		result.uot = params.uot
		result.naive_insecure_concurrency = params["insecure-concurrency"] or "0"
		if params.ech and params.ech ~= "" then
			result.ech = "1"
			result.ech_config = params.ech
		end
		if szType == "naive+quic" then
			result.naive_quic = "1"
			result.naive_congestion_control = params.congestion_control or "bbr"
		end
	elseif szType == "snell" then
		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "snell"
		else
			log(2, i18n.translatef("Skip the %s node because the %s core program is not installed.", "Snell", "Sing-Box 1.14"))
			return nil
		end

		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local info = split(content, "@")
			result.snell_psk = UrlDecode(info[1])
			Info = info[2]
		end
		Info = (Info or ""):gsub("/%?", "?")
		local query = split(Info, "%?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local s = v:find("=", 1, true)
			if s and s > 1 then
				params[UrlDecode(v:sub(1, s - 1)):lower()] = UrlDecode(v:sub(s + 1))
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		result.port = "443"
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.snell_psk = params.psk or result.snell_psk
		result.password = params.userkey
		result.snell_version = params.version or "4"
		if result.snell_version == "4" then
			result.snell_obfs_mode = params.obfs or "none"
			result.snell_obfs_host = params['obfs-host'] or params.obfs_host
		else
			result.snell_mode = params.mode or "default"
		end
		result.snell_reuse = (params.reuse == "1") and "1" or "0"
	else
		log(2, i18n.translatef("%s type node subscriptions are not currently supported, skip this node.", szType))
		return nil
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	return result
end

local function curl(url, file, ua, mode, hwid)
	if not url or url == "" then return 22, 404 end
	local curl_args = {
		"-fskL", "-w %{http_code}", "--retry 3", "--connect-timeout 3", "-H 'Accept: */*'", "-H 'Accept-Encoding: identity'"
	}
	if ua and ua ~= "" and ua ~= "curl" then
		ua = (ua == "passwall2") and ("passwall2/" .. (api.get_version():match("^([^-]+)") or "")) or ua
		curl_args[#curl_args + 1] = '--user-agent "' .. ua .. '"'
	end
	if hwid == "1" then
		curl_args[#curl_args + 1] = get_headers()
	end
	local cookie_file = "/tmp/cookie_" .. api.gen_random_char(5)
	curl_args[#curl_args + 1] = '-c "' .. cookie_file .. '" -b "' .. cookie_file .. '"'

	local return_code, result
	if mode == "direct" then
		return_code, result = api.curl_direct(url, file, curl_args)
	elseif mode == "proxy" then
		return_code, result = api.curl_proxy(url, file, curl_args)
	else
		return_code, result = api.curl_auto(url, file, curl_args)
	end
	luci.sys.call('rm -f "%s"' % cookie_file)

	return return_code, tonumber(result)
end

function get_headers()
	local cache_file = api.CACHE_PATH .. "/sub_curl_headers"
	if fs.access(cache_file) then
		return luci.sys.exec("cat " .. cache_file)
	end
	local headers = {}

	local function readfile(path)
		local f = io.open(path, "r")
		if not f then return nil end
		local c = f:read("*a")
		f:close()
		return api.trim(c)
	end

	headers[#headers + 1] = "x-device-os: OpenWrt"

	local rel = readfile("/etc/openwrt_release")
	local os_ver = rel and rel:match("DISTRIB_RELEASE='([^']+)'")
	if os_ver then
		headers[#headers + 1] = "x-ver-os: " .. os_ver
	end

	local model = readfile("/tmp/sysinfo/model")
	if model then
		headers[#headers + 1] = "x-device-model: " .. model
	end

	local mac = readfile("/sys/class/net/eth0/address")
	if mac and model then
		local raw = mac .. "-" .. model
		local p = io.popen("printf '%s' '" .. raw:gsub("'", "'\\''") .. "' | sha256sum")
		if p then
			local hash = p:read("*l")
			p:close()
			hash = hash and hash:match("^%w+")
			if hash then
				headers[#headers + 1] = "x-hwid: " .. hash
			end
		end
	end

	local out = {}
	for i = 1, #headers do
		out[i] = "-H '" .. headers[i]:gsub("'", "'\\''") .. "'"
	end
	local headers_str = table.concat(out, " ")
	local f = io.open(cache_file, "w"); if f then f:write(headers_str); f:close() end
	return headers_str
end

local function truncate_nodes(group)
	for _, config in pairs(CONFIG) do
		if config.currentNodes and #config.currentNodes > 0 then
			local newNodes = {}
			local removeNodesSet = {}
			for k, v in pairs(config.currentNodes) do
				if v.currentNode and v.currentNode.add_mode == "2" then
					if (not group) or (group:lower() == (v.currentNode.group or ""):lower()) then
						removeNodesSet[v.currentNode[".name"]] = true
					end
				end
			end
			for _, value in ipairs(config.currentNodes) do
				if not removeNodesSet[value.currentNode[".name"]] then
					newNodes[#newNodes + 1] = value.currentNode[".name"]
				end
			end
			if config.set then
				config.set(config, newNodes)
			end
		else
			if config.currentNode and config.currentNode.add_mode == "2" then
				if (not group) or (group:lower() == (config.currentNode.group or ""):lower()) then
					if config.delete then
						config.delete(config)
					elseif config.set then
						config.set(config, "")
					end
				end
			end
		end
	end
	uci_foreach("nodes", function(node)
		if node.add_mode == "2" then
			if (not group) or (group:lower() == (node.group or ""):lower()) then
				uci_del(node['.name'])
			end
		end
	end)
	uci_foreach("subscribe_list", function(o)
		if (not group) or (group:lower() == (o.remark or ""):lower()) then
			uci_del(o['.name'], "md5")
		end
	end)
	uci_save(true)
end

local function select_node(nodes, config, parentConfig)
	local log_level = 1
	if parentConfig then
		log_level = log_level + 1
	end
	if config.currentNode then
		local server
		-- Load balancing, keeping the original ID of the Socks [port] node in urltest.
		if config.currentNode["Socks"] then
			server = config.currentNode.Socks
		end
		-- Special priority: cfgid
		if config.currentNode[".name"] then
			for index, node in pairs(nodes) do
				if node[".name"] == config.currentNode[".name"] then
					if config.log == nil or config.log == true then
						log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("Matching node:") .. " " .. node.remarks)
					end
					server = node[".name"]
					break
				end
			end
		end
		-- First priority: Type + Notes + IP + Port + Group
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.remarks and config.currentNode.address and config.currentNode.port then
					if node.type and node.remarks and node.address and node.port then
						if node.type == config.currentNode.type and node.remarks == config.currentNode.remarks and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("First Matching node:") .. " " .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- Second priority: Type + IP + Port + Group
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.address and config.currentNode.port then
					if node.type and node.address and node.port then
						if node.type == config.currentNode.type and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("Second Matching node:") .. " " .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- Third priority: IP + Port + Group
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address and config.currentNode.port then
					if node.address and node.port then
						if node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("Third Matching node:") .. " " .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- Fourth priority: IP + Group
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address then
					if node.address then
						if node.address == config.currentNode.address and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("Fourth Matching node:") .. " " .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- Fifth priority: remarks + Group
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.remarks then
					if node.remarks then
						if node.remarks == config.currentNode.remarks and node.group == config.currentNode.group then
							if config.log == nil or config.log == true then
								log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("Fifth Matching node:") .. " " .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		if not parentConfig then
			-- If that doesn't work, just find one.
			if not server then
				if #nodes_table > 0 then
					if config.log == nil or config.log == true then
						log(log_level, i18n.translatef("Update [%s]", config.remarks) .. " " .. i18n.translatef("Unable to find the best matching node, now replaced with:") .. " " .. nodes_table[1].remarks)
					end
					server = nodes_table[1][".name"]
				end
			end
		end
		if server then
			if parentConfig then
				config.set(parentConfig, server)
			else
				config.set(config, server)
			end
		end
	else
		if not parentConfig then
			config.set(config, "")
		end
	end
end

-- Write account information only when it changes; commit together with node updates.
local function update_subscribe_info()
	local changed = {}
	for cfgid, info in pairs(subscribe_info) do
		for key, value in pairs(info) do
			value = value and value ~= "" and value or nil
			if uci_get(cfgid, key) ~= value then
				if value then
					uci_set(cfgid, key, value)
				else
					uci_del(cfgid, key)
				end
				changed[cfgid] = true
			end
		end
	end
	return changed
end

local function update_node(manual)
	if next(nodeResult) == nil then
		log(1, i18n.translatef("No node information updates are available."))
		return false
	end

	local group = {}
	for _, v in ipairs(nodeResult) do
		group[v["remark"]:lower()] = true
	end

	if manual == 0 and next(group) then
		uci_foreach("nodes", function(node)
			-- Do not delete nodes if no new nodes are found or nodes were manually imported...
			if node.add_mode == "2" and (node.group and group[node.group:lower()] == true) then
				uci_del(node['.name'])
			end
		end)
	end
	for _, v in ipairs(nodeResult) do
		local remark = v["remark"]
		local list = v["list"]
		local sub_cfg = v["sub_cfg"]
		local domain_resolver, domain_resolver_dns, domain_resolver_dns_https, domain_strategy
		local preproxy_node_group, to_node_group, outbound_iface_group, chain_node_type = "", "", "", ""
		-- Subscription Group Chain Agent
		local function valid_chain_node(node)
			if not node then return "" end
			local cp = uci_get(node, "chain_proxy") or ""
			local am = uci_get(node, "add_mode") or "0"
			chain_node_type = (cp == "" and am ~= "2") and (uci_get(node, "type") or "") or ""
			if chain_node_type ~= "Xray" and chain_node_type ~= "sing-box" then
				chain_node_type = ""
				return ""
			end
			return node
		end
		if sub_cfg then
			domain_resolver = sub_cfg.domain_resolver
			domain_resolver_dns = sub_cfg.domain_resolver_dns
			domain_resolver_dns_https = sub_cfg.domain_resolver_dns_https
			domain_strategy = (sub_cfg.domain_strategy == "UseIPv4" or sub_cfg.domain_strategy == "UseIPv6") and sub_cfg.domain_strategy or nil
			preproxy_node_group = (sub_cfg.chain_proxy == "1") and valid_chain_node(sub_cfg.preproxy_node) or ""
			to_node_group = (sub_cfg.chain_proxy == "2") and valid_chain_node(sub_cfg.to_node) or ""
			outbound_iface_group = (sub_cfg.chain_proxy == "3") and sub_cfg.outbound_iface or ""
			chain_node_type = (outbound_iface_group ~= "") and "iface" or chain_node_type
		end
		for _, vv in ipairs(list) do
			local cfgid = uci:section(c_config, "nodes", api.gen_random_char())
			for kkk, vvv in pairs(vv) do
				if type(vvv) == "table" and next(vvv) ~= nil then
					uci_set(cfgid, kkk, vvv)
				else
					if kkk ~= "group" or vvv ~= "default" then
						uci_set(cfgid, kkk, vvv)
					end
					-- Sing-Box Node Domain resolver
					if kkk == "type" and (vvv == "Xray" or vvv == "sing-box") then
						if domain_resolver then
							uci_set(cfgid, "domain_resolver", domain_resolver)
							if domain_resolver_dns then
								uci_set(cfgid, "domain_resolver_dns", domain_resolver_dns)
							elseif domain_resolver_dns_https then
								uci_set(cfgid, "domain_resolver_dns_https", domain_resolver_dns_https)
							end
						end
						if domain_strategy then
							if vvv == "sing-box" then
								domain_strategy = (domain_strategy == "UseIPv4" and "ipv4_only") or (domain_strategy == "UseIPv6" and "ipv6_only") or domain_strategy
							end
							uci_set(cfgid, "domain_strategy", domain_strategy)
						end
					end
					-- Subscription Group Chain Agent
					if chain_node_type ~= "" and kkk == "type" and (vvv == "Xray" or vvv == "sing-box") then
						if preproxy_node_group ~="" then
							uci_set(cfgid, "chain_proxy", "1")
							uci_set(cfgid, "preproxy_node", preproxy_node_group)
						elseif to_node_group ~= "" then
							uci_set(cfgid, "chain_proxy", "2")
							uci_set(cfgid, "to_node", to_node_group)
						elseif outbound_iface_group ~= "" then
							uci_set(cfgid, "chain_proxy", "3")
							uci_set(cfgid, "outbound_iface", outbound_iface_group)
						end
					end
				end
			end
		end
	end
	if next(CONFIG) then
		local nodes = {}
		uci_foreach("nodes", function(node)
			nodes[#nodes + 1] = node
		end)

		for _, config in pairs(CONFIG) do
			if config.currentNodes and #config.currentNodes > 0 then
				if config.remarks and config.currentNodes[1].log ~= false then
					log(1, i18n.translatef("Update [%s]", config.remarks))
				end
				for kk, vv in pairs(config.currentNodes) do
					select_node(nodes, vv, config)
				end
				config.set(config)
				if not config.newNodes or #config.newNodes == 0 then
					log(1, i18n.translatef("[%s]", config.remarks) .. " " .. i18n.translate("Unable to find a new node. Please confirm and process manually."))
				end
			else
				select_node(nodes, config)
			end
		end
	end

	return true
end

local function parse_link(raw, add_mode, group, sub_cfg)
	if raw and #raw > 0 then
		local cfgid
		if sub_cfg then
			cfgid = sub_cfg[".name"]
		end
		local keyword_filter = add_mode == "2" and prepare_keyword_filter(sub_cfg)
		local nodes, szType, clashTable
		local node_list = {}
		-- ssd appear to be in this format, starting with ssd://.
		if raw:find('ssd://') then
			szType = 'ssd'
			local nEnd = select(2, raw:find('ssd://'))
			nodes = base64Decode(raw:sub(nEnd + 1, #raw))
			nodes = jsonParse(nodes)
			local extra = {
				airport = nodes.airport,
				port = nodes.port,
				encryption = nodes.encryption,
				password = nodes.password
			}
			local servers = {}
			-- SS is wrapped inside, so let's just like this.
			for _, server in ipairs(nodes.servers) do
				tinsert(servers, setmetatable(server, { __index = extra }))
			end
			nodes = servers
		else
			-- Try parseYAML, if success, is clash.
			local yamlTable = lyaml.load(raw)
			if yamlTable and type(yamlTable) == "table" then
				-- clash
				szType = "clash"
				clashTable = yamlTable
			else
				-- Formats other than ssd
				if add_mode == "1" then
					nodes = split(raw, "\n")
				else
					nodes = split(base64Decode(raw):gsub("\r\n", "\n"), "\n")
				end
			end
		end

		function nodeFilter(node)
			if node then
				if node.error_msg then
					log(2, i18n.translatef("Discard node: %s, Reason:", node.remarks) .. " " .. node.error_msg)
				elseif not node.type then
					log(2, i18n.translatef("Discard node: %s, Reason:", node.remarks) .. " " .. i18n.translatef("No usable binary was found."))
				elseif (add_mode == "2" and is_filter_keyword(keyword_filter, node.remarks)) or not node.address or node.remarks == "NULL" or node.address == "127.0.0.1" or
						(not datatypes.hostname(node.address) and not (api.is_ip(node.address))) then
					log(2, i18n.translatef("Discard filter nodes: %s type node %s", node.type, node.remarks))
				else
					tinsert(node_list, node)
				end
				if add_mode == "2" then
					get_subscribe_info(cfgid, node.remarks)
				end
			end
		end

		if szType == "clash" and clashTable then
			nodes = {}
			local clashNodes = processClashData(clashTable, add_mode, group, sub_cfg)
			for _, v in ipairs(clashNodes) do
				nodeFilter(v)
			end
		end

		for _, v in ipairs(nodes) do
			if v and (szType == 'ssd' or not string.match(v, "^%s*$")) then
				xpcall(function ()
					local result
					if szType == 'ssd' then
						result = processData(szType, v, add_mode, group, sub_cfg)
					elseif not szType then
						local node = api.trim(v)
						local dat = split(node, "://")
						if dat and dat[1] and dat[2] then
							if dat[1] == 'vmess' or dat[1] == 'ssr' then
								local link = api.trim(dat[2]:gsub("#.*$", ""))
								result = processData(dat[1], base64Decode(link), add_mode, group, sub_cfg)
							else
								local link = dat[2]:gsub("&amp;", "&"):gsub("%s*#%s*", "#")  -- Some odd links use "&" as "&", and include spaces before and after "#".
								result = processData(dat[1], link, add_mode, group, sub_cfg)
							end
						end
					else
						log(2, i18n.translatef("Skip unknown types:") .. " " .. szType)
					end
					-- log(2, result)
					nodeFilter(result)
				end, function (err)
					--log(2, err)
					log(2, v, i18n.translatef("Parsing error, skip this node."))
				end
			)
			end
		end
		if add_mode ~= "2" and #node_list > 0 then
			nodeResult[#nodeResult + 1] = {
				remark = group,
				list = node_list,
				sub_cfg = sub_cfg
			}
		end
		log(2, i18n.translatef("Successfully resolved the [%s] node, number: %s", group, #node_list))
		return node_list
	else
		if add_mode == "2" then
			log(2, i18n.translatef("Get subscription content for [%s] is empty. This may be due to an invalid subscription address or a network problem. Please diagnose the issue!", group))
		end
		return {}
	end
end

local execute = function()
	do
		local subscribe_list = {}
		local fail_list = {}
		if arg[2] ~= "all" then
			string.gsub(arg[2], '[^' .. "," .. ']+', function(w)
				subscribe_list[#subscribe_list + 1] = uci_get(w) or {}
			end)
		else
			uci_foreach("subscribe_list", function(o)
				subscribe_list[#subscribe_list + 1] = o
			end)
		end

		local manual_sub = arg[3] == "manual"

		for index, value in ipairs(subscribe_list) do
			local cfgid = value[".name"]
			local remark = value.remark or ""
			local url = value.url or ""

			local url_is_local
			if fs.access(url) then
				-- debug, reads local files.
				log(1, i18n.translatef("Start subscribing: %s", '【' .. remark .. '】' .. url))
				url_is_local = true
				tmp_file = url
			else
				local ua = value.user_agent
				local access_mode = value.access_mode
				local result = (not access_mode) and i18n.translatef("Auto") or (access_mode == "direct" and i18n.translatef("Direct") or (access_mode == "proxy" and i18n.translatef("Proxy") or i18n.translatef("Auto")))
				log(1, i18n.translatef("Start subscribing: %s", '【' .. remark .. '】' .. url .. ' [' .. result .. ']'))
				tmp_file = "/tmp/" .. cfgid
				local return_code
				return_code, value.http_code = curl(url, tmp_file, ua, access_mode, value.hwid)
				if return_code ~= 0 then
					fail_list[#fail_list + 1] = value
					luci.sys.call("rm -f " .. tmp_file)
				end
			end
			if fs.access(tmp_file) then
				if luci.sys.call("[ -f " .. tmp_file .. " ] && sed -i -e '/^[ \t]*$/d' -e '/^[ \t]*\r$/d' " .. tmp_file) == 0 then
					local f = io.open(tmp_file, "r")
					local stdout = f:read("*all")
					f:close()
					local raw_data = api.trim(stdout)
					-- Buffer parsing details until the parsed nodes are known to have changed.
					log_buffer = {}
					local parsed_nodes = parse_link(raw_data, "2", remark, value)
					local old_md5 = value.md5 or ""
					local new_md5 = #parsed_nodes > 0 and api.md5_string(jsonStringify(parsed_nodes)) or ""
					if not manual_sub and new_md5 ~= "" and old_md5 == new_md5 then
						log_buffer = nil
						log(1, i18n.translatef("Subscription: [%s] No changes, no update required.", remark))
					else
						flush_log_buffer()
						if #parsed_nodes > 0 then
							nodeResult[#nodeResult + 1] = {
								remark = remark,
								list = parsed_nodes,
								sub_cfg = value,
								md5 = new_md5
							}
						end
					end
				else
					fail_list[#fail_list + 1] = value
				end
				if url_is_local then
					value.http_code = 0
				else
					luci.sys.call("rm -f " .. tmp_file)
				end
			end
		end

		if #fail_list > 0 then
			for index, value in ipairs(fail_list) do
				log(1, i18n.translatef("[%s] Subscription failed. This could be due to an invalid subscription address or a network issue. Please diagnose the problem! [%s]", value.remark, tostring(value.http_code)))
			end
		end
		local nodes_changed = update_node(0)
		local info_changed = update_subscribe_info()
		-- Save nodes, references and their MD5 in the same commit.
		for _, result in ipairs(nodeResult) do
			uci_set(result.sub_cfg[".name"], "md5", result.md5)
		end
		if nodes_changed or next(info_changed) then
			uci_save(true)
			restart_required = nodes_changed
			for _, value in ipairs(subscribe_list) do
				if info_changed[value[".name"]] then
					log(1, i18n.translatef("Refresh subscription [%s] account usage and expiration information.", value.remark or ""))
				end
			end
		end
	end
end

if arg[1] == "start" then
	log(0, i18n.translate("Start subscribing..."))
	xpcall(execute, function(e)
		flush_log_buffer()
		log(1, e)
		if type(debug) == "table" and type(debug.traceback) == "function" then
			log(1, debug.traceback())
		end
		log(1, i18n.translate("An error occurred during subscription."))
	end)
	log(0, i18n.translate("Subscription complete...") .. "\n")
elseif arg[1] == "add" then
	local f = assert(io.open("/tmp/links.conf", 'r'))
	local raw = f:read('*all')
	f:close()
	parse_link(raw, "1", arg[2])
	if update_node(1) then uci_save(true) end
	luci.sys.call("rm -f /tmp/links.conf")
elseif arg[1] == "truncate" then
	truncate_nodes(arg[2])
end

update_lock:close()
if restart_required then
	local action = arg[3] == "cron" and " cron" or ""
	luci.sys.call("/etc/init.d/passwall2 restart" .. action .. " > /dev/null 2>&1 &")
end
