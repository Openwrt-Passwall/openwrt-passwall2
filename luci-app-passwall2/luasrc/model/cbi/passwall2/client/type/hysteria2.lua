local m, s = ...

if not api.finded_com("hysteria") then
	return
end

type_name = "Hysteria2"

-- [[ Hysteria2 ]]

s.fields["type"]:value(type_name, "Hysteria2")

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "hysteria2_"

local function _n(name)
	return option_prefix .. name
end

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))
o:depends({ [_n("realms")] = false })

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"
o:depends({ [_n("realms")] = false })

o = s:option(Value, _n("hop"), translate("Port hopping range"))
o.description = translate("Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).")
o.rewrite_option = o.option
o:depends({ [_n("realms")] = false })

o = s:option(Value, _n("hop_interval"), translate("Hop Interval(second)"), translate("Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5."))
o.datatype = "or(uinteger,portrange)"
o.placeholder = "30"
o.default = "30"
o.rewrite_option = o.option
o:depends({ [_n("realms")] = false })

o = s:option(Flag, _n("realms"), translate("Realms"))
o.default = "0"
o.rewrite_option = o.option

o = s:option(Value, _n("realm_url"), translate("Realm URL"), translate("Example:") .. "realm://public@realm.hy2.io/your-realm-name")
o.rewrite_option = o.option
o:depends({ [_n("realms")] = "1" })
o.validate = function(self, value)
	value = api.trim(value)
	local realm = api.parse_realm_uri(value)
	if realm then return value end
	return nil, translate("Invalid Realm URL.")
end

o = s:option(DynamicList, _n("realm_stun"), translate("Realm STUN"))
o.default = { "stun.sip.us:3478", "stun.nextcloud.com:3478", "global.stun.twilio.com:3478" }
o.rewrite_option = o.option
o:depends({ [_n("realms")] = "1" })

o = s:option(Value, _n("auth_password"), translate("Auth Password"))
o.password = true
o.rewrite_option = o.option

o = s:option(ListValue, _n("obfs_type"), translate("Obfs Type"))
o:value("", translate("Disable"))
o:value("salamander")
o:value("gecko")
o.rewrite_option = o.option

o = s:option(Value, _n("obfs_password"), translate("Obfs Password"))
o.rewrite_option = o.option
o:depends({ [_n("obfs_type")] = "salamander" })
o:depends({ [_n("obfs_type")] = "gecko" })

o = s:option(Value, _n("obfs_MinPacketSize"), translate("Gecko Packet Size (min)"))
o.datatype = "uinteger"
o.placeholder = "512"
o.default = "512"
o:depends({ [_n("obfs_type")] = "gecko" })
o.rewrite_option = o.option

o = s:option(Value, _n("obfs_MaxPacketSize"), translate("Gecko Packet Size (max)"))
o.datatype = "uinteger"
o.placeholder = "1200"
o.default = "1200"
o:depends({ [_n("obfs_type")] = "gecko" })
o.rewrite_option = o.option

o = s:option(Flag, _n("fast_open"), translate("Fast Open"))
o.default = "0"

o = s:option(Value, _n("tls_serverName"), translate("Domain"))

o = s:option(Flag, _n("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"

o = s:option(Value, _n("tls_pinSHA256"), translate("PinSHA256"),translate("Certificate fingerprint"))

o = s:option(Value, _n("up_mbps"), translate("Max upload Mbps"))
o.rewrite_option = o.option

o = s:option(Value, _n("down_mbps"), translate("Max download Mbps"))
o.rewrite_option = o.option

o = s:option(Value, _n("recv_window"), translate("QUIC stream receive window"))
o.rewrite_option = o.option

o = s:option(Value, _n("recv_window_conn"), translate("QUIC connection receive window"))
o.rewrite_option = o.option

o = s:option(Value, _n("idle_timeout"), translate("Idle Timeout"), translate("Units:seconds") .. " (4~120)")
o.datatype = "range(4,120)"
o.rewrite_option = o.option

o = s:option(Value, _n("keep_alive_period"), translate("QUIC KeepAlive interval"), translate("Units:seconds") .. " (2~60)")
o.datatype = "range(2,60)"
o.rewrite_option = o.option

o = s:option(Flag, _n("disable_mtu_discovery"), translate("Disable MTU detection"))
o.default = "0"
o.rewrite_option = o.option

o = s:option(Flag, _n("lazy_start"), translate("Lazy Start"))
o.default = "0"
o.rewrite_option = o.option

api.luci_types(arg[1], m, s, type_name, option_prefix)
