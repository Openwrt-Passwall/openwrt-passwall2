module("luci.passwall2.util_trusttunnel", package.seeall)
local api = require "luci.passwall2.api"
local uci = api.uci
local jsonc = api.jsonc

-- The client parses its config with toml++, which rejects the whole document when it is
-- not valid UTF-8. Escaping below is byte-wise, so a Latin-1 paste or junk from an
-- imported link would pass through unescaped and take the entire config down with an
-- error visible only in the client log. Validate instead of silently mangling.
local function is_utf8(s)
	local i, n = 1, #s
	while i <= n do
		local c = s:byte(i)
		local len, lo, hi
		if c < 0x80 then
			len = 1
		elseif c >= 0xC2 and c <= 0xDF then
			len, lo, hi = 2, 0x80, 0xBF
		elseif c == 0xE0 then
			len, lo, hi = 3, 0xA0, 0xBF
		elseif c == 0xED then
			len, lo, hi = 3, 0x80, 0x9F -- exclude surrogates
		elseif c >= 0xE1 and c <= 0xEF then
			len, lo, hi = 3, 0x80, 0xBF
		elseif c == 0xF0 then
			len, lo, hi = 4, 0x90, 0xBF
		elseif c == 0xF4 then
			len, lo, hi = 4, 0x80, 0x8F
		elseif c >= 0xF1 and c <= 0xF3 then
			len, lo, hi = 4, 0x80, 0xBF
		else
			return false
		end
		if i + len - 1 > n then return false end
		for j = 1, len - 1 do
			local cc = s:byte(i + j)
			local min = (j == 1) and lo or 0x80
			local max = (j == 1) and hi or 0xBF
			if cc < min or cc > max then return false end
		end
		i = i + len
	end
	return true
end

-- Escape a Lua string for use as a TOML basic string (the "..." form).
-- Everything that reaches the generated file comes from UCI, i.e. from the web UI,
-- so an unescaped quote or newline would let a password inject arbitrary TOML.
-- Returns nil when the input cannot be represented; callers must fail loudly.
local function toml_basic(s)
	s = tostring(s or "")
	if not is_utf8(s) then return nil end
	s = s:gsub("\\", "\\\\")
	s = s:gsub('"', '\\"')
	s = s:gsub("[%z\1-\31\127]", function(c)
		return string.format("\\u%04X", string.byte(c))
	end)
	return '"' .. s .. '"'
end

-- A PEM certificate is emitted as a TOML multi-line *literal* string ('''...''').
-- Literal strings perform no escape processing, and the PEM alphabet cannot contain
-- a backslash or a control character other than newline. Anything that does not look
-- like a PEM block, or that contains the literal delimiter, is rejected.
local function toml_pem(s)
	s = tostring(s or "")
	if s == "" then return nil end
	-- A literal string is copied verbatim, so it needs the same UTF-8 check as the basic
	-- strings above: toml++ rejects the whole document over one bad byte anywhere in it.
	if not is_utf8(s) then return nil end
	s = s:gsub("\r\n", "\n"):gsub("\r", "\n")
	if s:find("'''", 1, true) then return nil end
	if s:find("[%z\1-\8\11-\31\127]") then return nil end
	if not s:find("^%-%-%-%-%-BEGIN ") then return nil end
	if not s:find("%-%-%-%-%-%s*$") then return nil end
	return "'''\n" .. s .. "\n'''"
end

local function toml_bool(v)
	return (v == "1" or v == 1 or v == true) and "true" or "false"
end

function gen_config(var)
	local node_id = var["node"]
	if not node_id then
		io.stderr:write("node Cannot be empty!" .. "\n")
		return
	end
	local node = uci:get_all("passwall2", node_id)
	if not node then
		io.stderr:write("node not found!" .. "\n")
		return
	end

	local local_socks_address = var["local_socks_address"] or "127.0.0.1"
	local local_socks_port = var["local_socks_port"]
	local server_host = var["server_host"] or (node.address or ""):lower()
	local server_port = var["server_port"] or node.port

	if not local_socks_port or local_socks_port == "" then
		io.stderr:write("local socks port Cannot be empty!" .. "\n")
		return
	end
	if server_host == "" or not server_port or server_port == "" then
		io.stderr:write("endpoint address and port Cannot be empty!" .. "\n")
		return
	end

	-- TLS SNI hostname. Falls back to the node's own address rather than to server_host:
	-- when this node sits behind a preproxy or is a chain landing node, app.sh rewrites
	-- server_host to 127.0.0.1, and using that would make certificate verification
	-- impossible. node.address is the real endpoint and is never bracketed.
	local hostname = node.hostname
	if not hostname or hostname == "" then hostname = (node.address or ""):lower() end

	if api.is_ipv6(server_host) then
		server_host = api.get_ipv6_full(server_host)
	end
	if api.is_ipv6(local_socks_address) then
		local_socks_address = api.get_ipv6_full(local_socks_address)
	end
	local endpoint = server_host .. ":" .. server_port
	local listen = local_socks_address .. ":" .. local_socks_port

	-- v1.0.49 rejects a config that omits vpn_mode or endpoint.upstream_protocol,
	-- despite both being documented as having defaults. Always emit them.
	local upstream_protocol = node.upstream_protocol
	if upstream_protocol ~= "http3" then upstream_protocol = "http2" end

	local out = {}
	local bad = nil
	local function put(s) out[#out + 1] = s end
	-- toml_basic returns nil for anything it cannot represent; remember the field name
	-- so the caller gets a specific error instead of a silently truncated config.
	-- Empty is reported too for required fields: an empty username or password produces
	-- a config that loads cleanly and then fails authentication forever, which is exactly
	-- how a field-name mismatch stayed invisible once already.
	local function str(name, v, required)
		if required and (v == nil or v == "") then
			bad = bad or (name .. " (empty)")
			return '""'
		end
		local q = toml_basic(v)
		if not q then bad = bad or name end
		return q or '""'
	end

	put("# Generated by passwall2. Do not edit; changes are overwritten on restart.")
	put("loglevel = " .. str("loglevel", node.loglevel or "info"))
	-- Routing is owned by passwall2, so the client must tunnel everything it is given
	-- and must never install firewall rules of its own.
	put('vpn_mode = "general"')
	put("killswitch_enabled = false")
	put("exclusions = []")
	-- LuCI drops a Flag from UCI when it matches the form default, so an absent option
	-- means "default", not "off". Both of these default to enabled.
	put("post_quantum_group_enabled = " .. toml_bool(node.post_quantum or "1"))
	put("")
	put("[endpoint]")
	put("hostname = " .. str("hostname", hostname, true))
	put("addresses = [" .. str("address", endpoint, true) .. "]")
	put("username = " .. str("username", node.username, true))
	put("password = " .. str("password", node.password, true))
	put("upstream_protocol = " .. str("upstream_protocol", upstream_protocol, true))
	put("has_ipv6 = " .. toml_bool(node.has_ipv6 or "1"))
	put("anti_dpi = " .. toml_bool(node.anti_dpi))
	put("skip_verification = " .. toml_bool(node.skip_verification))
	if node.custom_sni and node.custom_sni ~= "" then
		put("custom_sni = " .. str("custom_sni", node.custom_sni))
	end
	if node.client_random and node.client_random ~= "" then
		put("client_random = " .. str("client_random", node.client_random))
	end
	-- A certificate that cannot be emitted must abort generation. Dropping it would
	-- silently fall back to the system trust store, which is the opposite of what a
	-- user pinning their own CA asked for, and the client only warns about a bad PEM.
	if node.certificate and node.certificate ~= "" then
		local pem = toml_pem(node.certificate)
		if not pem then
			io.stderr:write("Invalid TLS certificate (PEM)!" .. "\n")
			return
		end
		put("certificate = " .. pem)
	end
	put("")
	put("[listener.socks]")
	put("address = " .. str("local socks address", listen))

	if bad then
		io.stderr:write("Invalid or missing value for " .. bad .. "!\n")
		return
	end

	return table.concat(out, "\n") .. "\n"
end

_G.gen_config = gen_config

if arg[1] then
	local func = _G[arg[1]]
	if func then
		local var = nil
		if arg[2] then
			var = jsonc.parse(arg[2])
		end
		-- Never print a nil return: stdout is redirected straight into the config file
		-- by app.sh, so "nil" would become the config and the client would be started
		-- on it. Exit non-zero instead and leave the caller to notice.
		local out = func(var)
		if not out then os.exit(1) end
		print(out)
	end
end
