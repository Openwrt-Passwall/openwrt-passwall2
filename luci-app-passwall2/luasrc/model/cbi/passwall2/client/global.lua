api = require "luci.passwall2.api"
appname = api.appname
datatypes = api.datatypes
has_singbox = api.finded_com("sing-box")
has_xray = api.finded_com("xray")

m = Map(appname)
api.set_apply_on_parse(m)

m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

local normal_list = {}
local balancing_list = {}
local urltest_list = {}
local shunt_list = {}
local iface_list = {}
for k, v in pairs(nodes_table) do
	if v.node_type == "normal" then
		normal_list[#normal_list + 1] = v
	end
	if v.protocol and v.protocol == "_balancing" then
		balancing_list[#balancing_list + 1] = v
	end
	if v.protocol and v.protocol == "_urltest" then
		urltest_list[#urltest_list + 1] = v
	end
	if v.protocol and v.protocol == "_shunt" then
		shunt_list[#shunt_list + 1] = v
	end
	if v.protocol and v.protocol == "_iface" then
		iface_list[#iface_list + 1] = v
	end
end

local socks_list = {}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " [" .. s.port .. translate("Port") .. "]",
			group = "Socks"
		}
	end
end)

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
				if not datatypes.ipmask4(v) and not datatypes.ipmask6(v) then
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

m:append(Template(appname .. "/global/status"))

global_cfgid = m:get("@global[0]")[".name"]

s = m:section(TypedSection, "global")
s.anonymous = true
s.addremove = false

s:tab("Main", translate("Main"))

-- [[ Global Settings ]]--
o = s:taboption("Main", Flag, "enabled", translate("Main switch"))
o.rmempty = false

---- Node
o = s:taboption("Main", ListValue, "node", "<a style='color: red'>" .. translate("Node") .. "</a>")
o.template = appname .. "/cbi/nodes_listvalue"
o:value("", translate("Close"))
o.group = {""}

current_node_id = m.uci:get(appname, global_cfgid, "node")
current_node = current_node_id and m.uci:get_all(appname, current_node_id) or {}

-- Shunt Start
if (has_singbox or has_xray) and #nodes_table > 0 then
	if #normal_list > 0 or #iface_list > 0 then
		if current_node.protocol == "_shunt" then
			local shunt_lua = loadfile("/usr/lib/lua/luci/model/cbi/passwall2/client/include/shunt_options.lua")
			setfenv(shunt_lua, getfenv(1))(m, s, {
				node_id = current_node_id,
				node = current_node,
				socks_list = socks_list,
				urltest_list = urltest_list,
				balancing_list = balancing_list,
				iface_list = iface_list,
				normal_list = normal_list,
				verify_option = s.fields["node"],
				tab = "Shunt",
				tab_desc = translate("Shunt Rule")
			})
		end
	else
		local tips = s:taboption("Main", DummyValue, "tips", "　")
		tips.rawhtml = true
		tips.cfgvalue = function(t, n)
			return string.format('<a style="color: red">%s</a>', translate("There are no available nodes, please add or subscribe nodes first."))
		end
		tips:depends({ node = "", ["!reverse"] = true })
		for k, v in pairs(shunt_list) do
			tips:depends("node", v.id)
		end
		for k, v in pairs(balancing_list) do
			tips:depends("node", v.id)
		end
	end
end

---- Check the transparent proxy component
local handle = io.popen("lsmod")
local mods = ""
if handle then
	mods = handle:read("*a") or ""
	handle:close()
end

local has_redir = mods:find("REDIRECT") or mods:find("nft_redir")
local has_tproxy = mods:find("TPROXY") or mods:find("nft_tproxy")

if not (has_redir and has_tproxy) then
	local kconfig_handle = io.popen("zcat /proc/config.gz 2>/dev/null")
	if kconfig_handle then
		local kconfig = kconfig_handle:read("*a") or ""
		kconfig_handle:close()
		if kconfig ~= "" then
			has_redir = has_redir or kconfig:find("CONFIG_NFT_REDIR=y")
			has_tproxy = has_tproxy or kconfig:find("CONFIG_NFT_TPROXY=y")
		end
	end
end

if (has_redir and has_tproxy) then
	o = s:taboption("Main", Flag, "localhost_proxy", translate("Localhost Proxy"), translate("When selected, localhost can transparent proxy."))
	o.default = "1"
	o.rmempty = false

	o = s:taboption("Main", Flag, "client_proxy", translate("Client Proxy"), translate("When selected, devices in LAN can transparent proxy. Otherwise, it will not be proxy. But you can still use access control to allow the designated device to proxy."))
	o.default = "1"
	o.rmempty = false
else
	local html = string.format([[<div class="cbi-checkbox"><input class="cbi-input-checkbox" type="checkbox" disabled></div><div class="cbi-value-description"><font color="red">%s</font></div>]], translate("Missing components, transparent proxy is unavailable."))
	o = s:taboption("Main", DummyValue, "localhost_proxy", translate("Localhost Proxy"))
	o.rawhtml = true
	function o.cfgvalue(self, section)
		return html
	end

	o = s:taboption("Main", DummyValue, "client_proxy", translate("Client Proxy"))
	o.rawhtml = true
	function o.cfgvalue(self, section)
		return html
	end
end

node_socks_port = s:taboption("Main", Value, "node_socks_port", translate("Node") .. " Socks " .. translate("Listen Port"))
node_socks_port.default = 1070
node_socks_port.datatype = "port"

node_socks_bind_local = s:taboption("Main", Flag, "node_socks_bind_local", translate("Node") .. " Socks " .. translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
node_socks_bind_local.default = "1"
node_socks_bind_local:depends({ node = "", ["!reverse"] = true })

s:tab("DNS", translate("DNS"))

o = s:taboption("DNS", TextValue, "direct_dns_shunt", translate("Direct domain DNS routing"))
o.description = "<br /><ul>"
.. "<li>" .. translate("Subdomain (recommended): Begining with 'domain:' and the rest is a domain. When the targeting domain is exactly the value, or is a subdomain of the value, this rule takes effect. Example: rule 'domain:v2ray.com' matches 'www.v2ray.com', 'v2ray.com', but not 'xv2ray.com'.") .. "</li>"
.. "<li>" .. translate("Full domain: Begining with 'full:' and the rest is a domain. When the targeting domain is exactly the value, the rule takes effect. Example: rule 'domain:v2ray.com' matches 'v2ray.com', but not 'www.v2ray.com'.") .. "</li>"
.. "<li>" .. translate("Such as:") .. "</li>"
.. "<li>" .. "domain:my-nodes.com tcp://223.5.5.5" .. "</li>"
.. "<li>" .. "domain:vpn.com udp://119.29.29.29:53" .. "</li>"
.. "<li>" .. "full:www.dnspod.com https://120.53.53.53/dns-query" .. "</li>"
.. "<li>" .. '<a style="color:red">' .. translate("Please note that the program will not start if the format is incorrect!") .. '</a>' .. "</li>"
.. "</ul>"
o.rows = 3
o.wrap = "off"

o = s:taboption("DNS", ListValue, "direct_dns_query_strategy", translate("Direct Query Strategy"))
o.default = "UseIP"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:taboption("DNS", ListValue, "remote_dns_protocol", translate("Remote DNS Protocol"))
o:value("tcp", "TCP")
o:value("doh", "DoH")
o:value("udp", "UDP")
if current_node.type == "sing-box" then
	o:value("tls", "TLS(DoT)")
	o:value("quic", "QUIC(DoQ)")
	o:value("http3", "HTTP3(DoH3)")
end

---- DNS over TCP or UDP or TLS (DoT) or QUIC (DoQ)
o = s:taboption("DNS", Value, "remote_dns", translate("Remote DNS"))
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
o = s:taboption("DNS", Value, "remote_dns_doh", translate("Remote DNS DoH"))
o.default = "https://1.1.1.1/dns-query"
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
o.validate = doh_validate
o:depends("remote_dns_protocol", "doh")
o:depends("remote_dns_protocol", "http3")

o = s:taboption("DNS", Value, "remote_dns_client_ip", translate("Remote DNS EDNS Client Subnet"))
o.description = translate("Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).") .. "<br />" ..
				translate("This feature requires the DNS server to support the Edns Client Subnet (RFC7871).")
o.datatype = "ipaddr"

o = s:taboption("DNS", ListValue, "remote_dns_detour", translate("Remote DNS Outbound"))
o.default = "remote"
o:value("remote", translate("Remote"))
o:value("direct", translate("Direct"))

o = s:taboption("DNS", Flag, "remote_fakedns", "FakeDNS", translate("Use FakeDNS work in the domain that proxy."))
o.default = "0"
o.rmempty = false

o = s:taboption("DNS", ListValue, "remote_dns_query_strategy", translate("Remote Query Strategy"))
o.default = "UseIPv4"
o:value("UseIP")
o:value("UseIPv4")
o:value("UseIPv6")

o = s:taboption("DNS", TextValue, "dns_hosts", translate("Domain Override"))
o.rows = 5
o.wrap = "off"
o.remove = function(self, section)
	local node_value = s.fields["node"]:formvalue(global_cfgid)
	if node_value then
		local node_t = m:get(node_value) or {}
		if node_t.type == "Xray" or node_t.type == "sing-box" then
			AbstractValue.remove(self, section)
		end
	end
end

o = s:taboption("DNS", Flag, "dns_redirect", translate("DNS Redirect"), translate("Force special DNS server to need proxy devices."))
o.default = "1"
o.rmempty = false

local prefer_nft = m:get("@global_forwarding[0]", "prefer_nft") == "1"
local set_title = api.i18n.translate(prefer_nft and "Clear NFTSET" or "Clear IPSET")
o = s:taboption("DNS", DummyValue, "clear_ipset", set_title, translate("Try this feature if the rule modification does not take effect."))
o.rawhtml = true
function o.cfgvalue(self, section)
	return string.format(
		[[<button type="button" class="cbi-button cbi-button-remove" onclick="location.href='%s'">%s</button>]],
		api.url("flush_set") .. "?redirect=1&reload=1", set_title)
end

s:tab("log", translate("Log"))
o = s:taboption("log", Flag, "log_node", translate("Enable Node Log"))
o.default = "1"
o.rmempty = false

loglevel = s:taboption("log", ListValue, "loglevel", translate("Log Level"))
loglevel.default = "warning"
loglevel:value("debug")
loglevel:value("info")
loglevel:value("warning")
loglevel:value("error")

s:tab("faq", "FAQ")

o = s:taboption("faq", DummyValue, "")
o.template = appname .. "/global/faq"

s:tab("maintain", translate("Maintain"))
o = s:taboption("maintain", DummyValue, "")
o.template = appname .. "/global/backup"

-- [[ Socks Server ]]--
o = s:taboption("Main", Flag, "socks_enabled", "Socks " .. translate("Main switch"))
o.rmempty = false

s2 = m:section(TypedSection, "socks", translate("Socks Config"))
s2.template = "cbi/tblsection"
s2.anonymous = true
s2.addremove = true
s2.extedit = api.url("socks_config", "%s")
function s2.create(e, t)
	local uuid = api.gen_short_uuid()
	t = uuid
	TypedSection.create(e, t)
	luci.http.redirect(e.extedit:format(t))
end

o = s2:option(DummyValue, "status", translate("Status"))
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<div class="_status" socks_id="%s"></div>', n)
end

---- Enable
o = s2:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

o = s2:option(ListValue, "node", translate("Socks Node"))
o.template = appname .. "/cbi/nodes_listvalue"
o.group = {}

o = s2:option(DummyValue, "now_node", translate("Current Node"))
o.rawhtml = true
o.cfgvalue = function(_, n)
	local current_node = api.get_cache_var("socks_" .. n)
	if current_node then
		local node = m:get(current_node)
		if node then
			return (api.get_node_remarks(node) or ""):gsub("(：)%[", "%1<br>[")
		end
	end
end

local n = 1
m.uci:foreach(appname, "socks", function(s)
	if s[".name"] == section then
		return false
	end
	n = n + 1
end)

o = s2:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false

if has_singbox or has_xray then
	o = s2:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	o.default = 0
	o.datatype = "port"
end

local o_node = s.fields["node"]
local o_socks = s2.fields["node"]
for k, v in pairs(nodes_table) do
	if #normal_list == 0 and #iface_list == 0 then
		break
	end
	o_node:value(v.id, v["remark"])
	o_node.group[#o_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	o_socks:value(v.id, v["remark"])
	o_socks.group[#o_socks.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
	if v.node_type == "normal" or v.protocol == "_balancing" or v.protocol == "_urltest" then
		--Shunt node has its own separate options.
		s.fields["remote_fakedns"]:depends({ node = v.id })
	end
end

local footer = Template(appname .. "/global/footer")
footer.api = api
footer.global_cfgid = global_cfgid
footer.shunt_list = api.jsonc.stringify(shunt_list)

m:append(footer)

return m
