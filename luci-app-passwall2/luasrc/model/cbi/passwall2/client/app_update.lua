local api = require "luci.passwall2.api"
api.set_default_cbi()

local com = require "luci.passwall2.com"

m = Map()

-- [[ App Settings ]]--
s = m:section(NamedSection, "@global_app[0]", "global_app", translate("App Update"))

s:appendTemplate("/app_update/app_version", {com = com})

local k, v
for k, v in pairs(com) do
	o = s:option(Value, k:gsub("%-","_") .. "_file", translatef("%s App Path", v.name))
	o.default = v.default_path or ("/usr/bin/" .. k)
	o.rmempty = false
end

o = s:option(DummyValue, "tips", " ")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<font color="red">%s</font>', translate("if you want to run from memory, change the path, /tmp beginning then save the application and update it manually."))
end

return api.return_map(m)
