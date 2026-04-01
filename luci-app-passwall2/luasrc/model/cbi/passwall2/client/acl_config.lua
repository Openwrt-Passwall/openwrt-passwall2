local api = require "luci.passwall2.api"
local appname = api.appname

m = Map(appname)
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(api.url("acl"))
end

m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

local sys = api.sys

local port_validate = function(self, value, t)
	return value:gsub("-", ":")
end

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local dynamicList_write = function(self, section, value)
	local t = {}
	local t2 = {}
	if type(value) == "table" then
		local x
		for _, x in ipairs(value) do
			if x and #x > 0 then
				if not t2[x] then
					t2[x] = x
					t[#t+1] = x
				end
			end
		end
	else
		t = { value }
	end
	t = table.concat(t, " ")
	return DynamicList.write(self, section, t)
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
-- Populate with actual kernel network devices instead of UCI interface names,
-- because the backend (nftables iifname / iptables -i) matches kernel device names.
do
	local nfs = require "nixio.fs"
	local _cursor = require("luci.model.uci").cursor()
	local _sysnet = "/sys/class/net/"

	-- Map UCI interface names to their device names and vice versa
	local _iface_to_dev = {}
	local _dev_to_ifaces = {}
	local _iface_proto = {}
	_cursor:foreach("network", "interface", function(sec)
		local name = sec[".name"]
		if name ~= "loopback" then
			_iface_proto[name] = sec.proto
			if sec.device then
				_iface_to_dev[name] = sec.device
				_dev_to_ifaces[sec.device] = _dev_to_ifaces[sec.device] or {}
				table.insert(_dev_to_ifaces[sec.device], name)
			end
		end
	end)

	-- Classify device type using sysfs attributes
	local function classify_sysfs(dev)
		if nfs.stat(_sysnet .. dev .. "/bridge", "type") == "dir" then
			return translate("Bridge")
		elseif nfs.stat(_sysnet .. dev .. "/wireless", "type") == "dir" then
			return translate("Wireless Adapter")
		elseif dev:match("^tun") or dev:match("^tap") or dev:match("^wg") or dev:match("^ppp") then
			return translate("Tunnel Interface")
		else
			return translate("Ethernet Adapter")
		end
	end

	-- Classify offline UCI interfaces by config hints
	local function classify_uci(dev_name, proto)
		if dev_name and dev_name:match("^br%-") then
			return translate("Bridge")
		elseif proto == "wireguard" or proto == "pppoe" or proto == "pptp" or proto == "l2tp" then
			return translate("Tunnel Interface")
		else
			return translate("Interface")
		end
	end

	local _seen = {}
	local _devices = {}

	-- Active kernel devices from /sys/class/net/.
	-- Skip bridge member ports (/master) and DSA master devices (/dsa) because
	-- nftables iifname matches the parent bridge for routed traffic, not
	-- individual member ports. Also skip internal virtual devices.
	local _iter = nfs.dir(_sysnet)
	if _iter then
		for dev in _iter do
			if dev ~= "lo"
				and not dev:match("^veth")
				and not dev:match("^ifb")
				and not dev:match("^gre")
				and not dev:match("^sit")
				and not dev:match("^ip6tnl")
				and not dev:match("^erspan")
				and not nfs.stat(_sysnet .. dev .. "/master", "type")
				and not nfs.stat(_sysnet .. dev .. "/dsa", "type")
			then
				local dtype = classify_sysfs(dev)
				local label = dtype .. ': "' .. dev .. '"'
				if _dev_to_ifaces[dev] then
					label = label .. " (" .. table.concat(_dev_to_ifaces[dev], ", ") .. ")"
				end
				_devices[#_devices + 1] = { name = dev, label = label, sort = dtype .. ":" .. dev }
				_seen[dev] = true
			end
		end
	end

	-- UCI interfaces whose device does not currently exist (down tunnels, VPNs, etc.).
	-- Stored by UCI name since the kernel device is not available yet.
	-- Dedup by device: if two interfaces share a device, only one is shown.
	for iface, dev in pairs(_iface_to_dev) do
		if not _seen[dev] then
			local dtype = classify_uci(dev, _iface_proto[iface])
			local label = dtype .. ': "' .. iface .. '"'
			-- Sort offline entries after active devices
			_devices[#_devices + 1] = { name = iface, label = label, sort = "zzz:" .. iface }
			_seen[dev] = true
		end
	end

	table.sort(_devices, function(a, b) return a.sort < b.sort end)
	for _, d in ipairs(_devices) do
		o:value(d.name, d.label)
	end
end

o.validate = function(self, value, section)
	if value == "" or value:match("^[a-zA-Z0-9][a-zA-Z0-9%.%_%-]*$") then
		return value
	end
	return nil, translate("Invalid interface name")
end

local mac_t = {}
sys.net.mac_hints(function(e, t)
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
sources.write = dynamicList_write

---- TCP No Redir Ports
local TCP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "tcp_no_redir_ports")
o = s:option(Value, "tcp_no_redir_ports", translate("TCP No Redir Ports"))
o:value("", translate("Use global config") .. "(" .. TCP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

---- UDP No Redir Ports
local UDP_NO_REDIR_PORTS = m:get("@global_forwarding[0]", "udp_no_redir_ports")
o = s:option(Value, "udp_no_redir_ports", translate("UDP No Redir Ports"),
	"<font color='red'>" ..
	translate("If you don't want to let the device in the list to go proxy, please choose all.") ..
	"</font>")
o:value("", translate("Use global config") .. "(" .. UDP_NO_REDIR_PORTS .. ")")
o:value("disable", translate("No patterns are used"))
o:value("1:65535", translate("All"))
o.validate = port_validate

o = s:option(DummyValue, "_hide_node_option", "")
o.template = "passwall2/cbi/hidevalue"
o.value = "1"
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
o.template = appname .. "/cbi/nodes_listvalue"

current_node_id = o:formvalue(arg[1])
if not current_node_id then
	current_node_id = m.uci:get(appname, arg[1], "node")
end
current_node = current_node_id and m.uci:get_all(appname, current_node_id) or {}

o = s:option(DummyValue, "_hide_dns_option", "")
o.template = "passwall2/cbi/hidevalue"
o.value = "1"
o:depends({ node = "" })
if GLOBAL_ENABLED == "1" and NODE then
	o:depends({ node = NODE })
end

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

o = s:option(ListValue, "dns_hosts_mode", translate("Domain Override"))
o:value("default", translate("Use global config"))
o:value("disable", translate("No patterns are used"))
o:value("custom", translate("-- custom --"))

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

return m
