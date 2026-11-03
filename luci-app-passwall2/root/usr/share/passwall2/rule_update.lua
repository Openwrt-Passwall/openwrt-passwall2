#!/usr/bin/lua

local api = require "luci.passwall2.api"
local fs = api.fs
local log = api.log
local sys = api.sys
local uci, uci_get, uci_set, uci_del, uci_foreach, uci_save = api.uci, api.uci_get_c, api.uci_set_c, api.uci_del_c, api.uci_foreach_c, api.uci_save_c

local arg1 = arg[1]
local arg2 = arg[2]
local arg3 = arg[3]

local update_lock = api.nixio.open(api.LOCK_PREFIX .. "_sub_rule.lock", api.nixio.open_flags("rdwr", "creat"))
if not update_lock then
	log(0, api.i18n.translate("Unable to open the subscription/rule update lock. Exiting."))
	os.exit(1)
end

if not update_lock:lock("tlock") then
	if arg3 ~= "cron" then
		log(0, api.i18n.translate("A subscription or rule update is already running. Skipping this request."))
		update_lock:close()
		os.exit(0)
	end
	local running_task = update_lock:read(1)
	update_lock:seek(0, "set")
	local running_name = running_task == "s" and api.i18n.translate("Subscription")
		or running_task == "r" and api.i18n.translate("Rule Update")
		or api.i18n.translate("Subscription/Rule Update")
	log(0, api.i18n.translatef("[%s] is running; [%s] is queued and waiting...", running_name, api.i18n.translate("Rule Update")))
	if not update_lock:lock("lock") then
		log(0, api.i18n.translate("Unable to acquire the update lock. Scheduled task failed."))
		update_lock:close()
		os.exit(1)
	end
end
update_lock:write("r")
update_lock:seek(0, "set")
uci:revert(api.c_config)
math.randomseed(os.time() + math.floor(os.clock() * 1000))

local reboot = 0
local geoip_update = "0"
local geosite_update = "0"

local geoip_url = uci_get("@global_rules[0]", "geoip_url") or "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat"
local geosite_url = uci_get("@global_rules[0]", "geosite_url") or "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
local asset_location = uci_get("@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
asset_location = asset_location:match("/$") and asset_location or (asset_location .. "/")
local backup_path = "/tmp/bak_v2ray/"

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
		"-H 'Accept: */*'",
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

-- Check every Geo category boundary and sample its first rule to identify the format.
local function validate_geo_file(file_path, geo_type)
	if geo_type ~= "geoip" and geo_type ~= "geosite" then return false end
	local file = io.open(file_path, "rb")
	if not file then return false end
	local size = file:seek("end")
	if not size or size == 0 or not file:seek("set", 0) then file:close(); return false end
	local pos, rules = 0, 0
	-- Use the file's read buffer and seek past skipped content without an extra buffer.
	local function skip(length, limit)
		assert(length <= limit - pos)
		pos = pos + length
		assert(file:seek("set", pos))
	end
	-- Without a numeric limit, only validate and skip varints to avoid precision loss for 64-bit attributes.
	local function varint(limit, maximum)
		local value, factor = 0, 1
		for i = 1, 10 do
			assert(pos < limit)
			local byte = assert(file:read(1)):byte()
			pos = pos + 1
			assert(i < 10 or byte <= 1)
			if maximum then
				local digit = byte % 128
				assert(digit <= math.floor((maximum - value) / factor))
				value = value + digit * factor
			end
			if byte < 128 then return value end
			factor = factor * 128
		end
		error(false)
	end
	-- Field definitions: wire type, optional child message type, optional numeric limit.
	local schema = {
		list = {{2, geo_type}},
		geoip = {{2}, {2, "cidr"}, {0}},
		geosite = {{2}, {2, "domain"}},
		cidr = {{2}, {0, nil, 4294967295}},
		domain = {{0, nil, 3}, {2}, {2, "attribute"}},
		attribute = {{2}, {0}, {0}}
	}
	local parse
	parse = function(kind, limit)
		local values, entries = {}, 0
		local is_entry = kind == "geoip" or kind == "geosite"
		while pos < limit do
			if is_entry and values[1] and values[1] > 0 and entries > 0 then
				skip(limit - pos, limit)
				return
			end
			local tag = varint(limit, 4294967295)
			local field, wire = math.floor(tag / 8), tag % 8
			local spec = schema[kind][field]
			assert(field > 0 and (not spec or wire == spec[1]))
			local value
			if wire == 0 then
				value = varint(limit, spec and spec[3])
			elseif wire == 2 then
				value = varint(limit, limit - pos)
				assert(value <= limit - pos)
				if spec and spec[2] and not (is_entry and entries > 0) then
					parse(spec[2], pos + value)
				else
					skip(value, limit)
				end
				if spec and spec[2] then entries = entries + 1 end
			elseif wire == 1 or wire == 5 then
				skip(wire == 1 and 8 or 4, limit)
			else
				-- Geo files do not use Protobuf group fields.
				error(false)
			end
			if spec then values[field] = value end
		end
		if kind == "list" then
			assert(entries > 0 and rules > 0)
		elseif kind == "geoip" or kind == "geosite" or kind == "attribute" then
			assert(values[1] and values[1] > 0)
		elseif kind == "cidr" then
			assert(values[1] == 4 or values[1] == 16)
			assert((values[2] or 0) <= (values[1] == 4 and 32 or 128))
			rules = rules + 1
		elseif kind == "domain" then
			assert(values[2] and values[2] > 0)
			rules = rules + 1
		end
	end
	local valid = pcall(parse, "list", size)
	file:close()
	return valid
end

local function fetch_geofile(geo_name, geo_type, url)
	local tmp_path = "/tmp/" .. geo_name
	local asset_path = asset_location .. geo_name
	local down_filename = url:match("^.*/([^/?#]+)")
	local sha_url = url:gsub((down_filename:gsub("(%W)", "%%%1")), down_filename .. ".sha256sum")
	local sha_path = tmp_path .. ".sha256sum"

	local digest
	local sha_verify, _ = curl(sha_url, sha_path) == 200
	if sha_verify then
		local f = io.open(sha_path, "r")
		if f then
			local content = f:read("*l")
			f:close()
			local hash = content and content:match("^(%x+)%s")
			if hash and #hash == 64 then
				digest = "sha256:" .. hash
			end
		end
		if not digest then
			log(1, api.i18n.translatef("%s SHA256 verification information is invalid. Update failed.", geo_type))
			return 1
		end
		if fs.access(asset_path) and api.verify_sha256(asset_path, digest) then
			log(1, api.i18n.translatef("%s version is the same and does not need to be updated.", geo_type))
			return 0
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
			if api.verify_sha256(tmp_path, digest) then
				sys.call(string.format("mkdir -p %s && mv -f %s %s", backup_path, asset_path, backup_path))
				sys.call(string.format("mkdir -p %s && mv -f %s %s", asset_location, tmp_path, asset_path))
				reboot = 1
				log(1, api.i18n.translatef("%s update success.", geo_type))
			else
				log(1, api.i18n.translatef("%s update failed, please try again later or change URL.", geo_type))
				return 1
			end
		else
			if not validate_geo_file(tmp_path, geo_type) then
				log(1, api.i18n.translatef("%s file format verification failed. Update failed.", geo_type))
				return 1
			end
			if fs.access(asset_path) and sys.call(string.format("cmp -s %s %s", tmp_path, asset_path)) == 0 then
				log(1, api.i18n.translatef("%s version is the same and does not need to be updated.", geo_type))
				return 0
			end
			sys.call(string.format("mkdir -p %s && mv -f %s %s", backup_path, asset_path, backup_path))
			sys.call(string.format("mkdir -p %s && mv -f %s %s", asset_location, tmp_path, asset_path))
			reboot = 1
			log(1, api.i18n.translatef("%s update success.", geo_type))
		end
	else
		log(1, api.i18n.translatef("%s update failed, please try again later or change URL.", geo_type))
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
	geoip_update = uci_get("@global_rules[0]", "geoip_update") or "1"
	geosite_update = uci_get("@global_rules[0]", "geosite_update") or "1"
end
if geoip_update == "0" and geosite_update == "0" then
	update_lock:close()
	return
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

uci_set("@global_rules[0]", "geoip_update", geoip_update)
uci_set("@global_rules[0]", "geosite_update", geosite_update)

if reboot == 1 then
	log(1, api.i18n.translate("Restart the service and apply the new rules."))
	uci_set("@global[0]", "flush_set", "1")
end
uci_save(true)
log(0, api.i18n.translate("The rules have been updated..."))

update_lock:close()
if reboot == 1 then
	local action = arg3 == "cron" and " cron" or ""
	sys.call("/etc/init.d/passwall2 restart" .. action .. " > /dev/null 2>&1 &")
end
