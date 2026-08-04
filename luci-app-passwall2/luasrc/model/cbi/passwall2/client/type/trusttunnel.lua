local m, s = ...

if not api.finded_com("trusttunnel_client") then
	return
end

type_name = "TrustTunnel"

-- [[ TrustTunnel ]]

s.fields["type"]:value(type_name, "TrustTunnel")

if s.val["type"] ~= type_name then
	return
end

local option_prefix = "trusttunnel_"

local function _n(name)
	return option_prefix .. name
end

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))
o.rmempty = false

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"
o.rmempty = false

o = s:option(Value, _n("username"), translate("Username"))
o.rmempty = false

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o.rmempty = false

-- The client reads a "|" in the hostname as an sni|remote_id separator, which turns a
-- pasted value containing it into a hard connect error.
local function no_pipe(self, value)
	value = api.trim(value)
	if value:find("|", 1, true) then
		return nil, translate("The character \"|\" is not allowed here.")
	end
	return value
end

o = s:option(Value, _n("hostname"), translate("TLS Hostname"), translate("Leave empty to use the endpoint address."))
o.validate = no_pipe

o = s:option(ListValue, _n("upstream_protocol"), translate("Upstream Protocol"))
o:value("http2", "HTTP/2")
o:value("http3", "HTTP/3")
o.default = "http2"

o = s:option(Value, _n("custom_sni"), translate("Custom SNI"))
o.validate = no_pipe

o = s:option(Value, _n("client_random"), translate("Client Random"))
o.validate = function(self, value)
	-- Lua patterns have no optional groups, so the two forms are matched separately.
	value = api.trim(value)
	if value == "" or value:match("^%x+$") or value:match("^%x+/%x+$") then
		return value
	end
	return nil, translate("Invalid Client Random.")
end

o = s:option(TextValue, _n("certificate"), translate("TLS Certificate (PEM)"), translate("Full certificate (chain), PEM format."))
o.rows = 5
o.wrap = "off"
o.validate = function(self, value)
	value = api.trim(value):gsub("\r\n", "\n"):gsub("[ \t]*\n[ \t]*", "\n"):gsub("\n+", "\n")
	-- Reject here rather than at service start: the generator aborts on a certificate
	-- it cannot represent, which would otherwise leave the node silently unstartable.
	if value ~= "" and not value:find("^%-%-%-%-%-BEGIN ") then
		return nil, translate("Must be PEM format!")
	end
	return value
end

-- rmempty = false keeps LuCI from dropping a Flag that matches its default, so the
-- generated config always states the value the form is showing.
o = s:option(Flag, _n("has_ipv6"), translate("IPv6"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, _n("anti_dpi"), translate("Anti-DPI"))
o.default = "0"

o = s:option(Flag, _n("skip_verification"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"

o = s:option(Flag, _n("post_quantum"), translate("Post-Quantum"))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, _n("loglevel"), translate("Log Level"))
o:value("error")
o:value("warn")
o:value("info")
o:value("debug")
o:value("trace")
o.default = "info"

api.luci_types(arg[1], m, s, type_name, option_prefix)
