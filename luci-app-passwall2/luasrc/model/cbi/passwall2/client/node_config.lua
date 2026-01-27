local api = require "luci.passwall2.api"
local appname = api.appname

m = Map(appname, translate("Node Config"))
m.redirect = api.url()
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(api.url("node_list"))
end

local header = Template(appname .. "/node_config/header")
header.api = api
header.section = arg[1]
m:append(header)

m:append(Template(appname .. "/cbi/nodes_multivalue_com"))
m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

s = m:section(NamedSection, arg[1], "nodes", "")
s.addremove = false
s.dynamic = false

o = s:option(DummyValue, "passwall2", " ")
o.rawhtml  = true
o.template = "passwall2/node_config/link_share_man"
o.value = arg[1]

o = s:option(Value, "remarks", translate("Node Remarks"))
o.default = translate("Remarks")
o.rmempty = false

o = s:option(Value, "group", translate("Group Name"))
o.default = ""
o:value("", translate("default"))
local groups = {}
m.uci:foreach(appname, "nodes", function(s)
	if s[".name"] ~= arg[1] then
		if s.group and s.group ~= "" then
			groups[s.group] = true
		end
	end
end)
for k, v in pairs(groups) do
	o:value(k)
end
o.write = function(self, section, value)
	value = api.trim(value)
	local lower = value:lower()

	if lower == "" or lower == "default" then
		return m:del(section, self.option)
	end

	for _, v in ipairs(self.keylist or {}) do
		if v:lower() == lower then
			return m:set(section, self.option, v)
		end
	end
	m:set(section, self.option, value)
end

local fs = require "nixio.fs"
local types_dir = "/usr/lib/lua/luci/model/cbi/passwall2/client/type/"
s.val = {}
s.val["type"] = m.uci:get(appname, arg[1], "type")
s.val["protocol"] = m.uci:get(appname, arg[1], "protocol")

o = s:option(ListValue, "type", translate("Type"))

local type_table = {}
for filename in fs.dir(types_dir) do
	table.insert(type_table, filename)
end
table.sort(type_table)

for index, value in ipairs(type_table) do
	local p_func = loadfile(types_dir .. value)
	setfenv(p_func, getfenv(1))(m, s)
end

local footer = Template(appname .. "/node_config/footer")
footer.api = api
footer.section = arg[1]

m:append(footer)

return m
