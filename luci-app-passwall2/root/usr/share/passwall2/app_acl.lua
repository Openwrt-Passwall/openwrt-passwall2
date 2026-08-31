-- Copyright (C) 2026 xiaorouji

local api = require "luci.passwall2.api"
local jsonc = api.jsonc
local sys = api.sys
local fs = api.fs
local i18n = api.i18n
local log = api.log
local uci, uci_get, uci_set, uci_del, uci_foreach, uci_save = api.uci, api.uci_get_c, api.uci_set_c, api.uci_del_c, api.uci_foreach_c, api.uci_save_c

local VAR = {} -- Set VAR
local D = {} -- Default Global Access Control
local L = {
	acl = {},
	node = {},
	node_order = {}
}

function add_args(t, k, v)
	if not t or not k or not v then return end
	table.insert(t, k .. "=" .. '"' .. v .. '"')
end

function init_acl()
	if true then
		-- Get Default AC
		D.flag = "default"
		D.remarks = api.i18n.translatef("Default")
		D.tcp_no_redir_ports = uci_get("@global_forwarding[0]", "tcp_no_redir_ports")
		D.udp_no_redir_ports = uci_get("@global_forwarding[0]", "udp_no_redir_ports")
		D.tcp_redir_ports = uci_get("@global_forwarding[0]", "tcp_redir_ports")
		D.udp_redir_ports = uci_get("@global_forwarding[0]", "udp_redir_ports")
		D.node = uci_get("@global[0]", "node")
		D.local_proxy = uci_get("@global[0]", "localhost_proxy")
		D.client_proxy = uci_get("@global[0]", "client_proxy")
		if D.node then
			local node = uci_get(D.node)
			if node and node[".type"] == "nodes" then
				local n = {
					config = node,
					enabled = uci_get("@global[0]", "enabled") or "0",
					log = uci_get("@global[0]", "log_node") or "0",
					loglevel = uci_get("@global[0]", "loglevel") or "warn",
					socks_listen = uci_get("@global[0]", "node_socks_bind_local") == "0" and "0.0.0.0" or "127.0.0.1",
					socks_port = uci_get("@global[0]", "node_socks_port"),
					redir_port = api.get_new_port(),
					dns_port = api.get_new_port(),
					direct_dns_query_strategy = uci_get("@global[0]", "direct_dns_query_strategy") or "UseIP",
					remote_dns_protocol = uci_get("@global[0]", "remote_dns_protocol") or "tcp",
					remote_dns_detour = uci_get("@global[0]", "remote_dns_detour") or "remote",
					remote_dns = uci_get("@global[0]", "remote_dns") or "1.1.1.1:53",
					remote_dns_doh = uci_get("@global[0]", "remote_dns_doh") or "https://1.1.1.1/dns-query",
					remote_dns_client_ip = uci_get("@global[0]", "remote_dns_client_ip"),
					remote_dns_query_strategy = uci_get("@global[0]", "remote_dns_query_strategy") or "UseIPv4",
					remote_rewrite_ttl = uci_get("@global[0]", "remote_rewrite_ttl"),
					remote_fakedns = uci_get("@global[0]", "remote_fakedns") or "0",
				}
				L.node[D.flag] = n
				D.use = D.flag
				if n.enabled == "1" then
					L.node_order[#L.node_order + 1] = D.flag
				end
			end
		end
	end
	local acl_num = 0
	if uci_get("@global[0]", "acl_enable") == "1" then
		uci_foreach("acl_rule", function(o)
			if o.enabled == "1" then
				acl_num = acl_num + 1
				local a = {}
				a.flag = o[".name"]
				a.remarks = o.remarks
				a.interface = o.interface
				a.sources = o.sources
				a.tcp_no_redir_ports = o.tcp_no_redir_ports
				a.udp_no_redir_ports = o.udp_no_redir_ports
				a.tcp_redir_ports = o.tcp_redir_ports
				a.udp_redir_ports = o.udp_redir_ports
				a.client_proxy = "1"
				a.local_proxy = "0"
				a.node = o.node
				if o.mode == "0" then
					a.tcp_no_redir_ports = "1:65535"
					a.udp_no_redir_ports = "1:65535"
				elseif o.mode == "2" then
					local U = L.node[D.use]
					if U.enabled == "0" then
						U.enabled = "1"
						D.local_proxy = "0"
						D.client_proxy = "0"
					end
					a.use = D.use
				end
				if a.tcp_no_redir_ports == "1:65535" and a.udp_no_redir_ports == "1:65535" then
					a.node = nil
				end
				if a.node then
					local node = uci_get(a.node)
					if node and node[".type"] == "nodes" then
						local n = {
							config = node,
							enabled = "1",
							log = o.log or "0",
							loglevel = o.loglevel or "warn",
							redir_port = api.get_new_port(),
							dns_port = api.get_new_port(),
							direct_dns_query_strategy = o.direct_dns_query_strategy,
							remote_dns_protocol = o.remote_dns_protocol,
							remote_dns_detour = o.remote_dns_detour,
							remote_dns = o.remote_dns,
							remote_dns_doh = o.remote_dns_doh,
							remote_dns_client_ip = o.remote_dns_client_ip,
							remote_dns_query_strategy = o.remote_dns_query_strategy,
							remote_rewrite_ttl = o.remote_rewrite_ttl,
							remote_fakedns = o.remote_fakedns,
						}
						L.node[a.flag] = n
						a.use = a.flag
						if n.enabled == "1" then
							L.node_order[#L.node_order + 1] = a.flag
						end
					end
				end
				L.acl[#L.acl + 1] = a
			end
		end)
	end
	if next(D) then
		L.acl[#L.acl + 1] = D
	end
	VAR["ENABLED_ACLS"] = acl_num > 0 and 1 or 0
	return L
end

function acl_app(l)
	if not l then l = L end
	for i, v in ipairs(l.acl) do
		local sid = v.flag
		local acl_path = api.TMP_ACL_PATH .. "/" .. sid
		sys.call("mkdir -p " .. acl_path)
		local out = io.open(acl_path .. "/var", "a")
		for k2, v2 in pairs(v) do
			if type(v2) == "string" then
				out:write(k2 .. "=" .. '"' .. v2 .. '"' .. "\n")
			end
		end
		if v.use then
			local node = l.node[v.use]
			if node.config then
				out:write("node" .. "=" .. '"' .. node.config[".name"] .. '"' .. "\n")
				out:write("node_remarks" .. "=" .. '"' .. node.config.remarks .. '"' .. "\n")
			end
			out:write("redir_port" .. "=" .. '"' .. node.redir_port .. '"' .. "\n")
		end
		out:close()
		local source_list = "any"
		if v.sources and #v.sources > 0 then
			local s1 = {}
			for i, w in ipairs(v.sources) do
				if api.iprange(w) then
					s1[#s1 + 1] = "iprange:" .. w
				elseif w:find("ipset:") == 1 then
					s1[#s1 + 1] = "ipset:" .. w
				else
					local _ip_or_mac = api.ip_or_mac(w)
					if _ip_or_mac == "ip" then
						s1[#s1 + 1] = "ip:" .. w
					elseif _ip_or_mac == "mac" then
						s1[#s1 + 1] = "mac:" .. w
					end
				end
			end
			if #s1 > 0 then
				source_list = table.concat(s1, "\n")
			end
		end
		if #source_list > 0 then
			local out = io.open(acl_path .. "/source_list", "a")
			out:write(source_list)
			out:close()
		end
	end
	-- Gen shell param
	for _, v1 in ipairs(l.node_order) do
		local v = l.node[v1]
		if v.enabled == "1" then
			local flag = v1
			local node = v.config
			local run_args = {}
			local config_path = api.TMP_ACL_PATH .. "/" .. flag
			local config_file = config_path .. ".json"
			local log_file = v.log == "0" and "/dev/null" or config_path .. ".log"
			local dns_server, dns_port = api.parseDNS(v.remote_dns)
			add_args(run_args, "flag", flag)
			add_args(run_args, "node", node[".name"])
			add_args(run_args, "redir_port", v.redir_port)
			add_args(run_args, "socks_address", v.socks_listen)
			add_args(run_args, "socks_port", v.socks_port)
			add_args(run_args, "dns_listen_port", v.dns_port)
			add_args(run_args, "direct_dns_query_strategy", v.direct_dns_query_strategy)
			add_args(run_args, "remote_dns_protocol", v.remote_dns_protocol)
			add_args(run_args, "remote_dns_tcp_server", dns_server)
			add_args(run_args, "remote_dns_tcp_port", dns_port)
			add_args(run_args, "remote_dns_udp_server", dns_server)
			add_args(run_args, "remote_dns_udp_port", dns_port)
			add_args(run_args, "remote_dns_doh", v.remote_dns_doh)
			add_args(run_args, "remote_dns_client_ip", v.remote_dns_client_ip)
			add_args(run_args, "remote_dns_detour", v.remote_dns_detour)
			add_args(run_args, "remote_dns_query_strategy", v.remote_dns_query_strategy)
			add_args(run_args, "remote_fakedns", v.remote_fakedns)
			add_args(run_args, "remote_rewrite_ttl", v.remote_rewrite_ttl)
			add_args(run_args, "config_file", config_file)
			add_args(run_args, "loglevel", v.loglevel)
			add_args(run_args, "log_file", log_file)
			
			local out = io.open(api.TMP_ACL_PATH .. "/acl_node_" .. flag , "a")
			out:write(table.concat(run_args, " "))
			out:close()
		end
	end

	for k, v in pairs(VAR) do
		api.set_cache_var(k, v)
	end
end

local acls = init_acl()
acl_app()
print(jsonc.stringify(acls, 1))
