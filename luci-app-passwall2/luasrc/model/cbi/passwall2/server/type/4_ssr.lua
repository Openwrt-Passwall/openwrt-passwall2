if not api.is_finded("ssr-server") then
	return
end

-- [[ ShadowsocksR ]]
local m, s1 = ...
local type_name = "SSR"

s1.fields["type"]:value(type_name, translate("ShadowsocksR"))

if not s1.val["type"] then
	s1.val["type"] = type_name
end

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "ssr_"

local ssr_encrypt_method_list = {
	"none", "table", "rc2-cfb", "rc4", "rc4-md5", "rc4-md5-6", "aes-128-cfb",
	"aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
	"bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
	"cast5-cfb", "des-cfb", "idea-cfb", "seed-cfb", "salsa20", "chacha20",
	"chacha20-ietf"
}

local ssr_protocol_list = {
	"origin", "verify_simple", "verify_deflate", "verify_sha1", "auth_simple",
	"auth_sha1", "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5",
	"auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c",
	"auth_chain_d", "auth_chain_e", "auth_chain_f"
}
local ssr_obfs_list = {
	"plain", "http_simple", "http_post", "random_head", "tls_simple",
	"tls1.0_session_auth", "tls1.2_ticket_auth"
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
for a, t in ipairs(ssr_encrypt_method_list) do o:value(t) end
o:depends({ custom = false })

o = s:option(ListValue, "protocol", translate("Protocol"))
for a, t in ipairs(ssr_protocol_list) do o:value(t) end
o:depends({ custom = false })

o = s:option(Value, "protocol_param", translate("Protocol_param"))
o:depends({ custom = false })

o = s:option(ListValue, "obfs", translate("Obfs"))
for a, t in ipairs(ssr_obfs_list) do o:value(t) end
o:depends({ custom = false })

o = s:option(Value, "obfs_param", translate("Obfs_param"))
o:depends({ custom = false })

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300
o:depends({ custom = false })

o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Flag, "udp_forward", translate("UDP Forward"))
o.default = "1"
o.rmempty = false

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