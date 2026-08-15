if not api.is_finded("naive") then
	return
end

-- [[ Naive ]]
local m, s1 = ...
local type_name = "Naiveproxy"

s1.fields["type"]:value(type_name, "NaiveProxy")

if s1.val["type"] ~= type_name then
	return
end

local s = NamedSection(m, arg[1], "server")
s.type_name = type_name
s.option_prefix = "naive_"

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("https", translate("HTTPS"))
o:value("quic", translate("QUIC"))

o = s:option(Value, "address", translate("Address (Support Domain Name)"))

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "username", translate("Username"))

o = s:option(Value, "password", translate("Password"))
o.password = true

api.luci_types(s1, s)