local api = require "luci.passwall2.api"
local fs = api.fs

local geo_dir = (api.uci_get_c("@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"):match("^(.*)/")
local geosite_path = geo_dir .. "/geosite.dat"
local geoip_path = geo_dir .. "/geoip.dat"
if fs.access(geosite_path) and fs.access(geoip_path) then
	f = SimpleForm(api.c_config)
	f.reset = false
	f.submit = false

	local obj = Template(api.appname .. "/rule/geoview")
	obj.api = api
	f:append(obj)
end

return f
