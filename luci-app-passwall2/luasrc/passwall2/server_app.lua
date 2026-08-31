#!/usr/bin/lua

local action = arg[1]
local api = require "luci.passwall2.api"
local sys = api.sys
local uci = api.uci
local jsonc = api.jsonc

local CONFIG = api.s_config
local CONFIG_PATH = api.S_TMP_PATH
local LOG_APP_FILE = "/tmp/log/" .. CONFIG .. ".log"
local TMP_BIN_PATH = CONFIG_PATH .. "/bin"
local require_dir = "luci.passwall2."

local function log(...)
	local f, err = io.open(LOG_APP_FILE, "a")
	if f and err == nil then
		local str = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
		f:write(str .. "\n")
		f:close()
	end
end

local function cmd(cmd)
	sys.call(cmd)
end

local function ln_run(s, d, command, output)
	if not output then
		output = "/dev/null"
	end
	d = TMP_BIN_PATH .. "/" .. d
	cmd(string.format('[ ! -f "%s" ] && ln -s %s %s 2>/dev/null', d, s, d))
	return string.format("%s >%s 2>&1 &", d .. " " ..command, output)
end

local function start()
	local enabled = tonumber(api.uci_get_s("@global[0]", "enable") or 0)
	if enabled == nil or enabled == 0 then
		return
	end
	cmd(string.format("mkdir -p %s %s", CONFIG_PATH, TMP_BIN_PATH))
	cmd(string.format("touch %s", LOG_APP_FILE))
	local firewall_num = 0
	api.uci_foreach_s("server", function(server)
		local id = server[".name"]
		local enable = server.enable
		if enable and tonumber(enable) == 1 then
			local enable_log = server.log
			local log_path = nil
			if enable_log and enable_log == "1" then
				log_path = CONFIG_PATH .. "/" .. id .. ".log"
			else
				log_path = nil
			end
			local remarks = server.remarks
			local port = tonumber(server.port)
			local bin
			local config = {}
			local config_file = CONFIG_PATH .. "/" .. id .. ".json"
			local udp_forward = 1
			local type = server.type or ""
			if type == "SSR" then
				if server.custom == "1" and server.config_str then
					config = jsonc.parse(api.base64Decode(server.config_str))
				else
					config = require(require_dir .. "util_shadowsocks").gen_config_server(server)
				end
				local udp_param = ""
				udp_forward = tonumber(server.udp_forward) or 1
				if udp_forward == 1 then
					udp_param = "-u"
				end
				type = type:lower()
				bin = ln_run("/usr/bin/" .. type .. "-server", type .. "-server", "-c " .. config_file .. " " .. udp_param, log_path)
			elseif type == "SS-Rust" then
				if server.custom == "1" and server.config_str then
					config = jsonc.parse(api.base64Decode(server.config_str))
				else
					config = require(require_dir .. "util_shadowsocks").gen_config_server(server)
				end
				bin = ln_run("/usr/bin/ssserver", "ssserver", "-c " .. config_file, log_path)
			elseif type == "Xray" then
				if server.custom == "1" and server.config_str then
					config = jsonc.parse(api.base64Decode(server.config_str))
					if log_path then
						if not config.log then
							config.log = {}
						end
						config.log.loglevel = server.loglevel
					end
				else
					config = require(require_dir .. "util_xray").gen_config_server(server)
				end
				bin = ln_run(api.get_app_path("xray"), "xray", "run -c " .. config_file, log_path)
			elseif type == "sing-box" then
				if server.custom == "1" and server.config_str then
					config = jsonc.parse(api.base64Decode(server.config_str))
					if log_path then
						if not config.log then
							config.log = {}
						end
						config.log.timestamp = true
						config.log.disabled = false
						config.log.level = server.loglevel
						config.log.output = log_path
					end
				else
					config = require(require_dir .. "util_sing-box").gen_config_server(server)
				end
				bin = ln_run(api.get_app_path("sing-box"), "sing-box", "run -c " .. config_file, log_path)
			end

			if next(config) then
				local f, err = io.open(config_file, "w")
				if f and err == nil then
					f:write(jsonc.stringify(config, 1))
					f:close()
				end
				log(string.format("%s %s - %s", remarks, api.i18n.translate("Generate configuration file and run"), config_file))
			end

			if bin then
				cmd(bin)
			end

			local firewall_allow = server.firewall_allow
			if firewall_allow == "1" then
				firewall_num = firewall_num + 1
				local uid = CONFIG .. "_" .. id
				uci:section("firewall", "rule", uid)
				uci:set("firewall", uid, "name", uid)
				uci:set("firewall", uid, "src", server.firewall_allow_src or "wan")
				uci:set("firewall", uid, "dest_port", port)
				uci:set("firewall", uid, "target", "ACCEPT")
			end
		end
	end)
	if firewall_num > 0 then
		api.uci_save(uci, "firewall", true, true)
	end
end

local function stop()
	cmd(string.format("/bin/busybox top -bn1 | grep -v 'grep' | grep '%s/' | awk '{print $1}' | xargs kill -9 >/dev/null 2>&1", CONFIG_PATH))
	if true then
		local num = 0
		uci:foreach("firewall", "rule", function(rule)
			if rule[".name"]:find(CONFIG) == 1 then
				num = num + 1
				uci:delete("firewall", rule[".name"])
			end
		end)
		if num > 0 then
			api.uci_save(uci, "firewall", true, true)
		end
	end
	cmd(string.format("rm -rf %s %s", CONFIG_PATH, LOG_APP_FILE))
end

if action then
	if action == "start" then
		start()
	elseif action == "stop" then
		stop()
	end
end
