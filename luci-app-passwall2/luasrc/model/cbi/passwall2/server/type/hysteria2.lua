if not api.finded_com("hysteria") then
	return
end

-- [[ Hysteria2 ]]
local m, s1 = ...
local type_name = "Hysteria2"

s1.fields["type"]:value(type_name, "Hysteria2")

if s1.val["type"] and s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "hysteria2_"

o = s:option(Flag, "custom", translate("Use Custom Config"))

o = s:option(TextValue, "custom_config", translate("Custom Config"))
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

o = s:option(DynamicList, "users", translate("User"))
for i, v in ipairs(user_list) do
	o:value(v[".name"], v.username)
end
o:depends({ custom = false })

o = s:option(Flag, "realms", translate("Realms"))
o.default = "0"
o:depends({ custom = false })

o = s:option(Value, "realm_url", translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
o:depends({ realms = true })
o.validate = function(self, value)
	value = api.trim(value)
	local realm = api.parse_realm_uri(value)
	if realm then return value end
	return nil, translate("Invalid Realm URL.")
end

o = s:option(DynamicList, "realm_stun", translate("Realm STUN"))
o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
o:depends({ realms = true })

o = s:option(ListValue, "obfs_type", translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o:depends({ custom = false })

o = s:option(Value, "obfs_password", translate("Obfs Password"))
o:depends({ obfs_type = "salamander" })
o:depends({ obfs_type = "gecko" })

o = s:option(Value, "obfs_MinPacketSize", translate("Gecko Packet Size (min)"))
o.datatype = "uinteger"
o.placeholder = "512"
o.default = "512"
o:depends({ obfs_type = "gecko" })

o = s:option(Value, "obfs_MaxPacketSize", translate("Gecko Packet Size (max)"))
o.datatype = "uinteger"
o.placeholder = "1200"
o.default = "1200"
o:depends({ obfs_type = "gecko" })

o = s:option(Flag, "udp", translate("UDP"))
o.default = "1"
o:depends({ custom = false })

o = s:option(Value, "up_mbps", translate("Max upload Mbps"))
o:depends({ custom = false })

o = s:option(Value, "down_mbps", translate("Max download Mbps"))
o:depends({ custom = false })

o = s:option(Flag, "ignoreClientBandwidth", translate("ignoreClientBandwidth"))
o.default = "0"
o:depends({ custom = false })

o = s:option(FileUpload, "tls_certificateFile", translate("Public key absolute path"), translate("as:") .. "/etc/ssl/fullchain.pem")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".pem"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not api.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end
o:depends({ custom = false })

o = s:option(FileUpload, "tls_keyFile", translate("Private key absolute path"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not api.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end
o:depends({ custom = false })

o = s:option(Flag, "log", translate("Log"))
o.default = "1"
o.rmempty = false

api.luci_types(s1, s)