local api = require "luci.passwall2.api"
api.set_default_cbi()

m = Map()
m.redirect = api.url("acl")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:appendTemplate("/cbi/nodes_listvalue_com")

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local doh_validate = function(self, value, t)
	if value ~= "" then
		local flag = 0
		local util = require "luci.util"
		local val = util.split(value, ",")
		local url = val[1]
		val[1] = nil
		for i = 1, #val do
			local v = val[i]
			if v then
				if not datatypes.ipmask4(v) then
					flag = 1
				end
			end
		end
		if flag == 0 then
			return value
		end
	end
	return nil, translate("DoH request address") .. " " .. translate("Format must be:") .. " URL,IP"
end

-- [[ ACLs Settings ]]--
s = m:section(NamedSection, arg[1], translate("ACLs"), translate("ACLs"))
s.addremove = false
s.dynamic = false

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.default = arg[1]
o.rmempty = false

o = s:option(Value, "interface", translate("Source Interface"))
o:value("", translate("All"))
local iface = api.get_network_devices()
for _, d in ipairs(iface) do
	o:value(d.name, d.label)
end
o.validate = function(self, value, section)
	if value == "" or value:match("^[a-zA-Z0-9][a-zA-Z0-9%.%_%-]*$") then
		return value
	end
	return nil, translate("Invalid interface name")
end

local mac_t = {}
api.sys.net.mac_hints(function(e, t)
	mac_t[#mac_t + 1] = {
		ip = t,
		mac = e
	}
end)
table.sort(mac_t, function(a,b)
	if #a.ip < #b.ip then
		return true
	elseif #a.ip == #b.ip then
		if a.ip < b.ip then
			return true
		else
			return #a.ip < #b.ip
		end
	end
	return false
end)

---- Source
sources = s:option(DynamicList, "sources", translate("Source"))
sources.description = "<ul><li>" .. translate("Example:")
.. "</li><li>" .. translate("MAC") .. ": 00:00:00:FF:FF:FF"
.. "</li><li>" .. translate("IP") .. ": 192.168.1.100"
.. "</li><li>" .. translate("IP CIDR") .. ": 192.168.1.0/24"
.. "</li><li>" .. translate("IP range") .. ": 192.168.1.100-192.168.1.200"
.. "</li><li>" .. translate("IPSet") .. ": ipset:lanlist"
.. "</li></ul>"
sources.cast = "string"
for _, key in pairs(mac_t) do
	sources:value(key.mac, "%s (%s)" % {key.mac, key.ip})
end

sources.cfgvalue = function(self, section)
	local value
	if self.tag_error[section] then
		value = self:formvalue(section)
	else
		value = self.map:get(section, self.option)
		if type(value) == "string" then
			local value2 = {}
			string.gsub(value, '[^' .. " " .. ']+', function(w) table.insert(value2, w) end)
			value = value2
		end
	end
	return value
end
sources.validate = function(self, value, t)
	local err = {}
	for _, v in ipairs(value) do
		local flag = false
		if v:find("ipset:") and v:find("ipset:") == 1 then
			local ipset = v:gsub("ipset:", "")
			if ipset and ipset ~= "" then
				flag = true
			end
		end

		if flag == false and datatypes.macaddr(v) then
			flag = true
		end

		if flag == false and datatypes.ip4addr(v) then
			flag = true
		end

		if flag == false and api.iprange(v) then
			flag = true
		end

		if flag == false then
			err[#err + 1] = v
		end
	end

	if #err > 0 then
		self:add_error(t, "invalid", translate("Not true format, please re-enter!"))
		for _, v in ipairs(err) do
			self:add_error(t, "invalid", v)
		end
	end

	return value
end

o = s:option(ListValue, "mode", translate("Mode"))
o:value("0", translate("No Proxy"))
o:value("1", translate("Proxy"))

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_no_redir_ports")
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o:depends("mode", "1")
o.validate = port_validate

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_no_redir_ports")
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"))
o:value("", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o:depends("mode", "1")
o.validate = port_validate

o = s:option(DummyValue, "_hide_node_option", "")
o.template = m:template_path("/cbi/hidevalue")
o.value = "1"
o:depends("mode", "0")
o:depends({ tcp_no_redir_ports = "1:65535", udp_no_redir_ports = "1:65535" })
if TCP_NO_REDIR_PORTS == "1:65535" and UDP_NO_REDIR_PORTS == "1:65535" then
	o:depends({ tcp_no_redir_ports = "", udp_no_redir_ports = "" })
end

local GLOBAL_ENABLED = m:get("@global[0]", "enabled")
local NODE = m:get("@global[0]", "node")
o = s:option(ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
if GLOBAL_ENABLED == "1" and NODE then
	o:value("", translate("Use global config") .. "(" .. api.get_node_name(NODE) .. ")")
	o.group = {""}
else
	o.group = {}
end
o:depends({ _hide_node_option = "1",  ['!reverse'] = true })
o.template = m:template_path("/cbi/nodes_listvalue")

current_node_id = o:formvalue(arg[1])
if not current_node_id then
	current_node_id = m:get(arg[1], "node")
end
current_node = current_node_id and m:get(current_node_id) or {}

o = s:option(Flag, "log", translate("Enable Node Log"))
o:depends({ node = "",  ['!reverse'] = true })

o = s:option(ListValue, "loglevel", translate("Log Level"))
o.default = "warn"
o:value("debug", "Debug")
o:value("info", "Info")
o:value("warn", "Warning")
o:value("error", "Error")
o:depends("log", "1")

o = s:option(DummyValue, "_acl_log", translate("Log File"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	local log_path = api.TMP_PATH .. "/acl/" .. arg[1] .. "/node.log"
	local log_url = api.url("get_acl_log") .. "?id=" .. arg[1]
	return string.format(
		'<code>%s</code>&nbsp;&nbsp;<input class="btn cbi-button cbi-button-apply" type="button" value="%s" onclick="window.open(\'%s\', \'_blank\')" />',
		log_path,
		translate("View Log"),
		log_url
	)
end
o:depends("log", "1")

---- TCP Redir Ports
local TCP_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_redir_ports")
o = s:option(Value, "tcp_redir_ports", translate("TCP Redir Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o:value("22,25,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418", translate("Common Use"))
o:value("80,443", "80,443")
o.validate = port_validate
o:depends({ _hide_node_option = "1",  ['!reverse'] = true })

---- UDP Redir Ports
local UDP_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_redir_ports")
o = s:option(Value, "udp_redir_ports", translate("UDP Redir Ports"))
o:value("", translate("Use global config") .. "(" .. UDP_REDIR_PORTS .. ")")
o:value("1:65535", translate("All"))
o.validate = port_validate
o:depends({ _hide_node_option = "1",  ['!reverse'] = true })

o = s:option(DummyValue, "tips", "　")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>',
	translate("The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000."))
end
o:depends({ _hide_node_option = "1",  ['!reverse'] = true })

o = s:option(DummyValue, "_hide_dns_option", "")
o.template = m:template_path("/cbi/hidevalue")
o.value = "1"
o:depends({ node = "" })
if GLOBAL_ENABLED == "1" and NODE then
	o:depends({ node = NODE })
end

o = s:option(ListValue, "direct_dns_query_strategy", translate("Direct Query Strategy"))
o.default = "UseIP"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")
o:depends({ _hide_dns_option = "1",  ['!reverse'] = true })

o = s:option(ListValue, "remote_dns_protocol", translate("Remote DNS Protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("udp", "UDP")
if current_node.type == "sing-box" then
	o:value("tls", "TLS(DoT)")
	o:value("quic", "QUIC(DoQ)")
	o:value("http3", "HTTP3(DoH3)")
end
o:depends({ _hide_dns_option = "1",  ['!reverse'] = true })

---- DNS over TCP or UDP or TLS (DoT) or QUIC (DoQ)
o = s:option(Value, "remote_dns", translate("Remote DNS"))
o.datatype = "or(ipaddr,ipaddrport)"
o.default = "1.1.1.1"
o:value("1.1.1.1", "1.1.1.1 (CloudFlare)")
o:value("1.1.1.2", "1.1.1.2 (CloudFlare-Security)")
o:value("8.8.4.4", "8.8.4.4 (Google)")
o:value("8.8.8.8", "8.8.8.8 (Google)")
o:value("9.9.9.9", "9.9.9.9 (Quad9-Recommended)")
o:value("149.112.112.112", "149.112.112.112 (Quad9-Recommended)")
o:value("208.67.220.220", "208.67.220.220 (OpenDNS)")
o:value("208.67.222.222", "208.67.222.222 (OpenDNS)")
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "udp")
o:depends("remote_dns_protocol", "quic")
o:depends("remote_dns_protocol", "tls")

---- DNS over HTTP (DoH) or DNS over HTTP3(DoH3)
o = s:option(Value, "remote_dns_doh", translate("Remote DNS DoH"))
o:value("https://1.1.1.1/dns-query", "CloudFlare")
o:value("https://1.1.1.2/dns-query", "CloudFlare-Security")
o:value("https://8.8.4.4/dns-query", "Google 8844")
o:value("https://8.8.8.8/dns-query", "Google 8888")
o:value("https://9.9.9.9/dns-query", "Quad9-Recommended 9.9.9.9")
o:value("https://149.112.112.112/dns-query", "Quad9-Recommended 149.112.112.112")
o:value("https://208.67.222.222/dns-query", "OpenDNS")
o:value("https://dns.adguard.com/dns-query,94.140.14.14", "AdGuard")
o:value("https://doh.libredns.gr/dns-query,116.202.176.26", "LibreDNS")
o:value("https://doh.libredns.gr/ads,116.202.176.26", "LibreDNS (No Ads)")
o.default = "https://1.1.1.1/dns-query"
o.validate = doh_validate
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "http3")

o = s:option(Value, "remote_dns_client_ip", translate("Remote DNS EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "udp")
o:depends("remote_dns_protocol", "http3")
o:depends("remote_dns_protocol", "quic")
o:depends("remote_dns_protocol", "tls")

o = s:option(ListValue, "remote_dns_detour", translate("Remote DNS Outbound"))
o.default = "remote"
o:value("remote", translate("Remote"))
o:value("direct", translate("Direct"))
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "udp")
o:depends("remote_dns_protocol", "http3")
o:depends("remote_dns_protocol", "quic")
o:depends("remote_dns_protocol", "tls")

o = s:option(Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the domain that proxy."))
o.default = "0"
o.rmempty = false

o = s:option(ListValue, "remote_dns_query_strategy", translate("Remote Query Strategy"))
o.default = "UseIPv4"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")
o:depends("remote_dns_protocol", "tcp")
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "udp")
o:depends("remote_dns_protocol", "http3")
o:depends("remote_dns_protocol", "quic")
o:depends("remote_dns_protocol", "tls")

o = s:option(Value, "remote_rewrite_ttl", translate("Remote DNS") .. " TTL")
o.datatype = "min(1)"
o.default = "30"

o = s:option(ListValue, "dns_hosts_mode", translate("Domain Override"))
o:value("default", translate("Use global config"))
o:value("disable", translate("No patterns are used"))
o:value("custom", translate("-- custom --"))
o:depends({ _hide_dns_option = "1",  ['!reverse'] = true })

o = s:option(TextValue, "dns_hosts", translate("Domain Override"))
o.rows = 5
o.wrap = "off"
o:depends("dns_hosts_mode", "custom")
o.remove = function(self, section)
	local node_value = s.fields["node"]:formvalue(arg[1])
	if node_value then
		local node_t = m:get(node_value) or {}
		if node_t.type == "Xray" or node_t.type == "sing-box" then
			AbstractValue.remove(self, section)
		end
	end
end

local o_node = s.fields["node"]

for k, v in pairs(nodes_table) do
	o_node:value(v.id, v["remark"])
	o_node.group[#o_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	if v.type == "sing-box" then
		s.fields["remote_rewrite_ttl"]:depends({ node = v.id })
	end
	if v.node_type == "normal" or v.protocol == "_balancing" or v.protocol == "_urltest" then
		--Shunt node has its own separate options.
		s.fields["remote_fakedns"]:depends({ node = v.id, remote_dns_protocol = "tcp" })
		s.fields["remote_fakedns"]:depends({ node = v.id, remote_dns_protocol = "doh" })
		s.fields["remote_fakedns"]:depends({ node = v.id, remote_dns_protocol = "udp" })
		s.fields["remote_fakedns"]:depends({ node = v.id, remote_dns_protocol = "http3" })
		s.fields["remote_fakedns"]:depends({ node = v.id, remote_dns_protocol = "quic" })
		s.fields["remote_fakedns"]:depends({ node = v.id, remote_dns_protocol = "tls" })
	end
end

return api.return_map(m)
