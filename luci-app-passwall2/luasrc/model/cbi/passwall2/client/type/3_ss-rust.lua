if not api.is_finded("sslocal") then
	return
end

-- [[ Shadowsocks Rust ]]
local m, s1 = ...
local type_name = "SS-Rust"

s1.fields["type"]:value(type_name, "Shadowsocks Rust")

if s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "ssrust_"

local ssrust_encrypt_method_list = {
	"none", "plain",
	"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha8-poly1305", "2022-blake3-chacha20-poly1305"
}

o = s:option(Value, "address", translate("Address (Support Domain Name)"))

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "password", translate("Password"))
o.password = true

o = s:option(Value, "method", translate("Encrypt Method"))
for a, t in ipairs(ssrust_encrypt_method_list) do o:value(t) end

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"), translate("Need node support required"))
o.default = 0

o = s:option(Flag, "plugin_enabled", translate("plugin"))
o.default = 0

o = s:option(Value, "plugin", "SIP003 " .. translate("plugin"), translate("Supports custom SIP003 plugins, Make sure the plugin is installed."))
o.default = "none"
o:value("none", translate("none"))
if api.is_finded("xray-plugin") then o:value("xray-plugin") end
if api.is_finded("v2ray-plugin") then o:value("v2ray-plugin") end
if api.is_finded("obfs-local") then o:value("obfs-local") end
if api.is_finded("shadow-tls") then o:value("shadow-tls") end
o:depends({ plugin_enabled = true })
o.validate = function(self, value, t)
	if value and value ~= "" and value ~= "none" then
		if not api.is_finded(value) then
			return nil, value .. ": " .. translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(Value, "plugin_opts", translate("opts"))
o:depends({ plugin_enabled = true })

api.luci_types(s1, s)