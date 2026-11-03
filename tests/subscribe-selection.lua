-- Run with: lua tests/subscribe-selection.lua
local file = assert(io.open("luci-app-passwall2/root/usr/share/passwall2/subscribe.lua"))
local source = file:read("*a")
file:close()
local selection = assert(source:match("(local function select_node.-)\n%-%- Write account information"))

local function profile(id, name, group, content)
	return { [".name"] = id, type = "Xray", protocol = "_custom", remarks = name,
		group = group or "subscription", custom_config = content or "{}" }
end

local function select(current, nodes, fallback)
	local chunk = "local nodes_table = ...\n" .. selection .. "\nreturn select_node"
	local compile = loadstring or load
	local choose = assert(compile(chunk, "subscribe.select_node"))(fallback or nodes)
	local result
	choose(nodes, {currentNode = current, log = false, set = function(_, id) result = id end})
	return result
end

assert(select(profile("old", "Poland", nil, '{"version":1}'), {
	profile("new-germany", "Germany"), profile("new-poland", "Poland", nil, '{"version":2}')
}) == "new-poland", "Updating profile JSON must preserve the selected country")

assert(select(profile("old", "Removed"), {
	profile("other-group", "Other", "unrelated"), profile("new-first", "Germany"), profile("new-second", "Poland")
}, {profile("stale-id", "Removed")}) == "new-first", "A removed country must use the first new profile in its group")

assert(select(profile("old", "Poland"), {
	{[".name"] = "normal", type = "sing-box", remarks = "Poland", group = "subscription", address = "example.com", port = "443"},
	profile("new-custom", "Germany")
}) == "new-custom", "A matching remark from another core must not replace a full profile")

assert(select(profile("unchanged", "Poland"), {
	profile("first", "Germany"), profile("unchanged", "Poland")
}) == "unchanged", "An unchanged node ID keeps priority")

assert(select({[".name"] = "old", type = "Xray", protocol = "vless", remarks = "Normal", group = "subscription", address = "example.com", port = "443"}, {
	{[".name"] = "normal-new", type = "Xray", protocol = "vless", remarks = "Normal", group = "subscription", address = "example.com", port = "443"}
}) == "normal-new", "Ordinary subscription matching must still work")

print("subscription selection: 5 checks passed")
