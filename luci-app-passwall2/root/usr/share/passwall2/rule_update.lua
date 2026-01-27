#!/usr/bin/lua

local api = require "luci.passwall2.api"
local name = api.appname
local fs = api.fs
local log = api.log
local sys = api.sys
local uci = api.uci
local jsonc = api.jsonc

local arg1 = arg[1]
local arg2 = arg[2]
local arg3 = arg[3]

local reboot = 0
local geoip_update = "0"
local geosite_update = "0"

local geoip_url = uci:get(name, "@global_rules[0]", "geoip_url") or "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat"
local geosite_url = uci:get(name, "@global_rules[0]", "geosite_url") or "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
local asset_location = uci:get(name, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
asset_location = asset_location:match("/$") and asset_location or (asset_location .. "/")

if arg3 == "cron" then
	arg2 = nil
end

-- curl
local function curl(url, file)
	local http_code = 0
	local header_str = ""
	local args = {
		"-skL",
		"--retry 3",
		"--connect-timeout 3",
		"--max-time 300",
		"--speed-limit 51200 --speed-time 15",
		'-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"',
		"--dump-header -",
		"-w '\\n%{http_code}'"
	}
	if file then
		args[#args + 1] = "-o " .. file
	end
	local return_code, result = api.curl_auto(url, nil, args)
	if result and result ~= "" then
		local body, code = result:match("^(.-)%s*([0-9]+)$")
		if code then
			http_code = tonumber(code) or 0
			header_str = body
		else
			http_code = tonumber(result:match("(%d+)%s*$")) or 0
		end
	end
	if header_str ~= "" then
		header_str = header_str:gsub("\r", "")
	end
	return http_code, header_str
end

local function non_file_check(file_path, header_content)
	local remote_file_size = nil
	local local_file_size = tonumber(fs.stat(file_path, "size") or 0)
	if local_file_size == 0 then
		log(2, api.i18n.translate("Downloaded file is empty or an error occurred while reading it."))
		return true
	end
	if header_content and header_content ~= "" then
		for size in header_content:gmatch("[Cc]ontent%-[Ll]ength:%s*(%d+)") do
			local s = tonumber(size)
			if s and s > 0 then
				remote_file_size = s
			end
		end
	end
	if remote_file_size and remote_file_size ~= local_file_size then
		log(2, api.i18n.translatef("Download file size verification error. Original file size: %sB. Downloaded file size: %sB.", remote_file_size, local_file_size))
		return true
	end
	return false
end

local function fetch_geofile(geo_name, geo_type, url)
	local tmp_path = "/tmp/" .. geo_name
	local asset_path = asset_location .. geo_name
	local down_filename = url:match("^.*/([^/?#]+)")
	local sha_url = url:gsub(down_filename, down_filename .. ".sha256sum")
	local sha_path = tmp_path .. ".sha256sum"

	local function verify_sha256(sha_file)
		return sys.call("sha256sum -c " .. sha_file .. " > /dev/null 2>&1") == 0
	end

	local sha_verify, _ = curl(sha_url, sha_path) == 200
	if sha_verify then
		local f = io.open(sha_path, "r")
		if f then
			local content = f:read("*l")
			f:close()
			if content then
				content = content:gsub(down_filename, tmp_path)
				f = io.open(sha_path, "w")
				if f then
					f:write(content)
					f:close()
				end
			end
		end
		if fs.access(asset_path) then
			sys.call(string.format("cp -f %s %s", asset_path, tmp_path))
			if verify_sha256(sha_path) then
				log(1, api.i18n.translatef("%s version is the same and does not need to be updated.", geo_type))
				return 0
			end
		end
	end

	local sret_tmp, header = curl(url, tmp_path)
	if sret_tmp == 200 and non_file_check(tmp_path, header) then
		log(1, api.i18n.translatef("%s an error occurred during the file download process. Please try downloading again.", geo_type))
		os.remove(tmp_path)
		sret_tmp, header = curl(url, tmp_path)
		if sret_tmp == 200 and non_file_check(tmp_path, header) then
			sret_tmp = 0
			log(1, api.i18n.translatef("%s an error occurred while downloading the file. Please check your network or the download link and try again!", geo_type))
		end
	end
	if sret_tmp == 200 then
		if sha_verify then
			if verify_sha256(sha_path) then
				sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, tmp_path, asset_path))
				reboot = 1
				log(1, api.i18n.translatef("%s update success.", geo_type))
			else
				log(1, api.i18n.translatef("%s update failed, please try again later.", geo_type))
				return 1
			end
		else
			if fs.access(asset_path) and sys.call(string.format("cmp -s %s %s", tmp_path, asset_path)) == 0 then
				log(1, api.i18n.translatef("%s version is the same and does not need to be updated.", geo_type))
				return 0
			end
			sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, tmp_path, asset_path))
			reboot = 1
			log(1, api.i18n.translatef("%s update success.", geo_type))
		end
	else
		log(1, api.i18n.translatef("%s update failed, please try again later.", geo_type))
		return 1
	end
	return 0
end

local function fetch_geoip()
	fetch_geofile("geoip.dat", "geoip", geoip_url)
end

local function fetch_geosite()
	fetch_geofile("geosite.dat", "geosite", geosite_url)
end

local function remove_tmp_geofile(name)
	os.remove("/tmp/" .. name .. ".dat")
	os.remove("/tmp/" .. name .. ".dat.sha256sum")
end

if arg2 then
	string.gsub(arg2, '[^' .. "," .. ']+', function(w)
		if w == "geoip" then
			geoip_update = "1"
		end
		if w == "geosite" then
			geosite_update = "1"
		end
	end)
else
	geoip_update = uci:get(name, "@global_rules[0]", "geoip_update") or "1"
	geosite_update = uci:get(name, "@global_rules[0]", "geosite_update") or "1"
end
if geoip_update == "0" and geosite_update == "0" then
	os.exit(0)
end

log(0, api.i18n.translate("Start updating the rules..."))
local function safe_call(func, err_msg)
	xpcall(func, function(e)
		log(1, e)
		log(1, debug.traceback())
		log(1, err_msg)
	end)
end

if geoip_update == "1" then
	log(1, api.i18n.translatef("%s Start updating...", "geoip"))
	safe_call(fetch_geoip, api.i18n.translatef("%s update error!", "geoip"))
	remove_tmp_geofile("geoip")
end

if geosite_update == "1" then
	log(1, api.i18n.translatef("%s Start updating...", "geosite"))
	safe_call(fetch_geosite, api.i18n.translatef("%s update error!", "geosite"))
	remove_tmp_geofile("geosite")
end

uci:set(name, "@global_rules[0]", "geoip_update", geoip_update)
uci:set(name, "@global_rules[0]", "geosite_update", geosite_update)
api.uci_save(uci, name, true)

if reboot == 1 then
	if arg3 == "cron" then
		if not fs.access("/var/lock/" .. name .. ".lock") then
			sys.call("touch /tmp/lock/" .. name .. "_cron.lock")
		end
	end

	log(1, api.i18n.translate("Restart the service and apply the new rules."))
	uci:set(name, "@global[0]", "flush_set", "1")
	api.uci_save(uci, name, true, true)
end
log(0, api.i18n.translate("The rules have been updated..."))
