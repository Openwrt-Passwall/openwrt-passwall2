if not api.is_finded("ssserver") then
	return
end

-- [[ Shadowsocks Rust ]]
local m, s1 = ...
local type_name = "SS-Rust"

s1.fields["type"]:value(type_name, translate("Shadowsocks Rust"))

if not s1.val["type"] then
	s1.val["type"] = type_name
end

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "ssrust_"

local ssrust_encrypt_method_list = {
	"plain", "none",
	"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha8-poly1305", "2022-blake3-chacha20-poly1305"
}

o = s:option(Flag, "custom", translate("Use Custom Config"))

o = s:option(TextValue, "custom_config", translate("Custom Config") .. " (JSON)")
o.rows = 10
o.wrap = "off"
o:depends({ custom = true })
o.datatype = "json"
local o_validate = o.validate
o.validate = function(self, value)
	local v = o_validate(self, value)
	if v then return v end
	return nil, translate("Custom Config") .. " " .. translate("Must be JSON text!")
end
o.custom_cfgvalue = function(self, section, value)
	local config_str = m:get(section, "config_str")
	if config_str then
		return api.base64Decode(config_str)
	end
end
o.custom_write = function(self, section, value)
	m:set(section, "config_str", api.base64Encode(value) or "")
end

o = s:option(Value, "port", translate("Listen Port"))
o.datatype = "port"
o:depends({ custom = false })

o = s:option(ListValue, "user", translate("User"))
for i, v in ipairs(user_list) do
	o:value(v[".name"], v.username)
end
o:depends({ custom = false })

o = s:option(ListValue, "method", translate("Encrypt Method"))
for a, t in ipairs(ssrust_encrypt_method_list) do o:value(t) end
o:depends({ custom = false })

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300
o:depends({ custom = false })

o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Flag, "firewall_allow", translate("Firewall Allow"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Value, "firewall_allow_src", translate("Source zone"))
o.rmempty = false
o.nocreate = true
o.allowany = true
o.default = "wan"
o.template = "cbi/firewall_zonelist"
o:depends({ custom = false, firewall_allow = true })

o = s:option(Flag, "log", translate("Log"))
o.default = "1"
o.rmempty = false

api.luci_types(s1, s)