if not api.is_finded("ssr-local") then
	return
end

-- [[ ShadowsocksR Libev ]]
local m, s1 = ...
local type_name = "SSR"

s1.fields["type"]:value(type_name, "ShadowsocksR Libev")

if s1.val["type"] ~= type_name then
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

o = s:option(Value, "address", translate("Address (Support Domain Name)"))

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "password", translate("Password"))
o.password = true

o = s:option(ListValue, "method", translate("Encrypt Method"))
for a, t in ipairs(ssr_encrypt_method_list) do o:value(t) end

o = s:option(ListValue, "protocol", translate("Protocol"))
for a, t in ipairs(ssr_protocol_list) do o:value(t) end

o = s:option(Value, "protocol_param", translate("Protocol_param"))

o = s:option(ListValue, "obfs", translate("Obfs"))
for a, t in ipairs(ssr_obfs_list) do o:value(t) end

o = s:option(Value, "obfs_param", translate("Obfs_param"))

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(Flag, "tcp_fast_open", "TCP " .. translate("Fast Open"), translate("Need node support required"))
o.default = 0

api.luci_types(s1, s)