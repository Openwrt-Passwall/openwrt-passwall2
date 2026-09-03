local api = require "luci.passwall2.api"
api.set_default_cbi()

m = Map()

-- [[ Rule Settings ]]--
s = m:section(NamedSection, "@global_rules[0]", "global_rules", translate("Rule status"))

o = s:option(Value, "geoip_url", translate("GeoIP Update URL"))
o:value("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat", translate("Loyalsoldier/geoip"))
o:value("https://gh-proxy.org/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat", translate("Loyalsoldier/geoip (gh-proxy)"))
o:value("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat", translate("Loyalsoldier/geoip (CDN)"))
o:value("https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat", translate("MetaCubeX/geoip"))
o:value("https://gh-proxy.org/https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.dat", translate("MetaCubeX/geoip (gh-proxy)"))
o:value("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat", translate("MetaCubeX/geoip (CDN)"))
o:value("https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat", translate("Chocolate4U/geoip (IR)"))
o:value("https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat", translate("runetfreedom/geoip (RU)"))
o.default = o.keylist[1]

o = s:option(Value, "geosite_url", translate("Geosite Update URL"))
o:value("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat", translate("Loyalsoldier/geosite"))
o:value("https://gh-proxy.org/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat", translate("Loyalsoldier/geosite (gh-proxy)"))
o:value("https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat", translate("Loyalsoldier/geosite (CDN)"))
o:value("https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat", translate("MetaCubeX/geosite"))
o:value("https://gh-proxy.org/https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat", translate("MetaCubeX/geosite (gh-proxy)"))
o:value("https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat", translate("MetaCubeX/geosite (CDN)"))
o:value("https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat", translate("Chocolate4U/geosite (IR)"))
o:value("https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat", translate("runetfreedom/geosite (RU)"))
o.default = o.keylist[1]

o = s:option(Value, "v2ray_location_asset", translate("Location of Geo rule files"), translate("This variable specifies a directory where geoip.dat and geosite.dat files are."))
o.default = "/usr/share/v2ray/"
o.placeholder = o.default
o.rmempty = false

o = s:option(ListValue, "update_week_mode", translate("Auto Update Mode"))
o:value("", translate("Disable"))
o:value(8, translate("Loop Mode"))
o:value(7, translate("Every day"))
o:value(1, translate("Every Monday"))
o:value(2, translate("Every Tuesday"))
o:value(3, translate("Every Wednesday"))
o:value(4, translate("Every Thursday"))
o:value(5, translate("Every Friday"))
o:value(6, translate("Every Saturday"))
o:value(0, translate("Every Sunday"))

o = s:option(Value, "update_time_mode", translate("Update Time"))
o:value("0:00")
for t = 0, 23 do
	if t == 12 then
		o:value(t .. ":30")
	elseif t == 23 then
		o:value(t .. ":59")
	else
		o:value(t .. ":00")
	end
end
o.default = "0:00"
o.datatype = "timehhmm"
o:depends("update_week_mode", "0")
o:depends("update_week_mode", "1")
o:depends("update_week_mode", "2")
o:depends("update_week_mode", "3")
o:depends("update_week_mode", "4")
o:depends("update_week_mode", "5")
o:depends("update_week_mode", "6")
o:depends("update_week_mode", "7")

o = s:option(ListValue, "update_interval_mode", translate("Update Interval(hour)"))
for t = 1, 24 do o:value(t, t .. " " .. translate("hour")) end
o.default = 2
o:depends("update_week_mode", "8")
o.rmempty = true

--- The update option is always hidden by JavaScript.
local flags = {
	"geoip_update", "geosite_update", "adblock_update"
}
for _, f in ipairs(flags) do
	o = s:option(Flag, f)
	o.rmempty = false
end

s:appendTemplate("/rule/rule_version")

if true then
	m:appendTemplate("/rule/shunt_rule_list")

	if luci.http.formvalue("cbi.submit") == "1" then
		local group_order = luci.http.formvaluetable("group.order")
		if group_order then
			for k, v in pairs(group_order) do
				if v and v~= "" then
					local new_order = {}
					string.gsub(v, "[^" .. " " .. "]+", function(w)
						new_order[#new_order + 1] = w
					end)
					for idx, name in ipairs(new_order) do
						m.uci:reorder(m.config, name, idx - 1)
					end
				end
			end
		end
	end
end

return api.return_map(m)
