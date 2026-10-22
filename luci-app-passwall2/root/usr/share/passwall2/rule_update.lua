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
local adblock_update = "0"

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

local ADBLOCK_CONF = "/usr/share/passwall2/adblock.conf"
-- Remembers which URL produced the current ADBLOCK_CONF, so that changing the
-- source invalidates the stale rules instead of keeping them in effect.
local ADBLOCK_URL_FILE = "/usr/share/passwall2/adblock.url"
-- Cap on the generated rule lines. Public lists reach roughly 100k-190k lines
-- and dnsmasq keeps every entry in memory, so bound it to stay safe on low
-- memory devices. The parser stops as soon as the cap is hit instead of
-- building the whole table first, which would defeat the purpose.
local MAX_ADBLOCK_RULES = 300000

local function get_adblock_url()
	-- Adblock is a global setting, it is not tied to any node.
	local url = uci_get("@global_rules[0]", "enable_adblock")
	if not url or url == "" or url:match("^[01]$") then
		return nil
	end
	return url
end

-- The URL is what detect_adblock() compares against the configured source, so
-- the rules only take effect once this file is written. Report a failure
-- instead of silently keeping a downloaded-but-inactive rule file.
local function save_adblock_url(url)
	local f = io.open(ADBLOCK_URL_FILE, "w")
	if not f then
		log(1, api.i18n.translate("Cannot record the adblock rule source, please check the free space of /usr/share/passwall2."))
		return false
	end
	f:write(url)
	f:close()
	return true
end

local function fetch_adblock()
	local url = get_adblock_url()
	if not url then
		log(1, api.i18n.translate("No adblock rule URL configured, skip."))
		return
	end
	local tmp = "/tmp/adblock.download"
	local new_conf = "/tmp/adblock.conf.new"
	-- Also hand the response headers to non_file_check() so a truncated download
	-- is caught by the Content-Length comparison, same as fetch_geofile().
	local http_code, header = curl(url, tmp)
	if http_code ~= 200 or non_file_check(tmp, header) then
		os.remove(tmp)
		os.remove(new_conf)
		log(1, api.i18n.translate("Failed to update the adblock rules, please try again later or change the URL."))
		return
	end
	local f = io.open(tmp, "r")
	if not f then
		os.remove(tmp)
		os.remove(new_conf)
		log(1, api.i18n.translate("Failed to update the adblock rules, please try again later or change the URL."))
		return
	end
	local raw = f:read("*a")
	f:close()
	-- Recognise the rule syntaxes we can actually consume. Anything else is
	-- treated as junk, so an unintended payload (HTML error page, JSON API
	-- response, ...) is rejected instead of being mined for domain lookalikes.
	local function is_rule_line(line)
		if line:find("^address=") == 1 then
			return true -- dnsmasq: address=/domain/ip
		end
		if line:find("^||") == 1 or line:find("^@@") == 1 or line:find("^|") == 1 then
			return true -- AdBlock: ||domain^ / @@||domain^
		end
		if line:match("^%d+%.%d+%.%d+%.%d+%s+%S") or line:match("^::%s+%S") then
			return true -- hosts: 0.0.0.0 domain
		end
		if line:match("^[%w%.%-%_]+$") then
			return true -- plain domain list
		end
		if line:find("^/") == 1 and #line > 2 and line:sub(-1) == "/" then
			return true -- /regex/
		end
		return false
	end

	-- Judge format by the proportion of lines starting with "address="
	local total_lines, dnsmasq_lines = 0, 0
	local cand_lines, rule_lines = 0, 0
	for line in raw:gmatch("[^\r\n]+") do
		total_lines = total_lines + 1
		if line:find("^address=") == 1 then
			dnsmasq_lines = dnsmasq_lines + 1
		end
		-- Count how many non comment lines use a rule syntax we understand
		local tline = line:match("^%s*(.-)%s*$")
		if tline ~= "" and not tline:match("^[!\[@#]") then
			cand_lines = cand_lines + 1
			if is_rule_line(tline) then
				rule_lines = rule_lines + 1
			end
		end
	end
	-- Convert to a clean address= rule list and validate source quality
	local lines_out = {}
	local total_out, valid_out = 0, 0
	local truncated = false
	local function is_valid_domain(domain)
		domain = domain:gsub("%.$", "")
		local last = domain:match("%.([^.]+)$")
		return last ~= nil and last:match("^[%a]") ~= nil and not domain:find("%s")
	end
	local function add_line(line, domain)
		if truncated then
			return
		end
		total_out = total_out + 1
		if is_valid_domain(domain) then
			valid_out = valid_out + 1
		end
		lines_out[#lines_out + 1] = line
		if #lines_out >= MAX_ADBLOCK_RULES then
			truncated = true
		end
	end
	-- Heuristic threshold: treat the source as dnsmasq format when at least half of
	-- its lines are address= entries. A boundary source (roughly half address= and
	-- half other content) also lands here, but its non address= lines are simply
	-- dropped below, and the quality gate at the end still rejects any source whose
	-- valid rule count is too low, so a wrong guess stays harmless.
	if total_lines > 0 and dnsmasq_lines * 2 >= total_lines then
		-- Already dnsmasq format. A single-domain rule carrying an IPv4 literal is
		-- rewritten to the address-less form, which answers NXDOMAIN for the whole
		-- domain and therefore blocks A and AAAA alike. Keeping the IPv4 literal
		-- would only block A: since dnsmasq 2.86 a query for another RR type is
		-- forwarded upstream, so on a dual-stack network the client receives the
		-- real IPv6 address and the block is defeated. Multi-domain rules and any
		-- target we do not recognise are kept verbatim.
		for line in raw:gmatch("[^\r\n]+") do
			if truncated then break end
			if line:find("^address=") == 1 then
				local domain, target = line:match("^address=/(.-)/(.*)$")
				if domain then
					domain = domain:lower()
					if target and target:match("^%d+%.%d+%.%d+%.%d+$") then
						add_line(string.format("address=/%s/", domain), domain)
					else
						add_line(line, domain)
					end
				end
			end
		end
	else
		-- Extract domains and generate address=/domain/ (NXDOMAIN), which covers
		-- both A and AAAA without needing a second line per domain.
		-- Skip comment lines, AdBlock exception rules and pure IP matches
		local seen = {}
		for line in raw:gmatch("[^\r\n]+") do
			if truncated then break end
			-- Known limit: only whole-line comments are skipped, so a trailing comment
			-- can still yield junk tokens; the quality gate below rejects such sources.
			if not line:match("^[!\\[@#]") and line:find("^@@") ~= 1 then
				for domain in line:gmatch("([%w%-%_]+%.[%w%.%-%_]+)") do
					if truncated then break end
					domain = domain:lower()
					if not domain:match("^%d+%.%d+%.%d+%.%d+$") and not seen[domain] then
						seen[domain] = true
						add_line(string.format("address=/%s/", domain), domain)
					end
				end
			end
		end
	end
	-- Source quality check: an empty result, too many junk tokens, or a payload
	-- whose lines do not look like rules at all (HTML/JSON error page).
	-- The lower bound is 2 rather than a "sane list size": a user may point this
	-- at a small hand-written list, and the ratio checks below already reject
	-- payloads that are not rule lists.
	if total_out < 2 or valid_out * 2 < total_out or rule_lines * 2 < cand_lines then
		os.remove(tmp)
		os.remove(new_conf)
		log(1, api.i18n.translate("The adblock rule source may be invalid, please modify it and try again."))
		return
	end
	if truncated then
		log(1, api.i18n.translatef("The adblock rules were truncated to %s entries.", MAX_ADBLOCK_RULES))
	end
	local out = io.open(new_conf, "w")
	if not out then
		os.remove(tmp)
		os.remove(new_conf)
		log(1, api.i18n.translate("Failed to update the adblock rules, please try again later or change the URL."))
		return
	end
	out:write(table.concat(lines_out, "\n") .. "\n")
	out:close()
	os.remove(tmp)
	-- Compare with existing rules to avoid unnecessary restarts
	if fs.access(ADBLOCK_CONF) and sys.call(string.format("cmp -s %s %s", new_conf, ADBLOCK_CONF)) == 0 then
		os.remove(new_conf)
		-- Content is identical, but the recorded URL may be missing (e.g. after a
		-- firmware upgrade), so refresh it to keep the rules usable.
		save_adblock_url(url)
		log(1, api.i18n.translate("The adblock rules are already up to date, no update needed."))
		return
	end
	local mv_ret = sys.call(string.format("mv -f %s %s", new_conf, ADBLOCK_CONF))
	if mv_ret ~= 0 then
		os.remove(new_conf)
		log(1, api.i18n.translate("Failed to update the adblock rules, please try again later or change the URL."))
		return
	end
	-- Record the source URL so detect_adblock() can tell whether the rule file
	-- still matches the configured source. Only flag a restart when the file
	-- really is usable.
	if not save_adblock_url(url) then
		return
	end
	reboot = 1
	log(1, api.i18n.translate("The adblock rules have been updated successfully."))
end

if arg2 then
	string.gsub(arg2, '[^' .. "," .. ']+', function(w)
		if w == "geoip" then
			geoip_update = "1"
		end
		if w == "geosite" then
			geosite_update = "1"
		end
		if w == "adblock" then
			adblock_update = "1"
		end
	end)
else
	geoip_update = uci_get("@global_rules[0]", "geoip_update") or "1"
	geosite_update = uci_get("@global_rules[0]", "geosite_update") or "1"
	adblock_update = uci_get("@global_rules[0]", "adblock_update") or "1"
end
if geoip_update == "0" and geosite_update == "0" and adblock_update == "0" then
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

-- Nothing to fetch while no rule source is selected; without this guard the
-- daily cron run would log "No adblock rule URL configured" every time.
if adblock_update == "1" and get_adblock_url() then
	log(1, api.i18n.translatef("%s Start updating...", "adblock"))
	safe_call(fetch_adblock, api.i18n.translatef("%s update error!", "adblock"))
end

-- Only the scheduled run may record the auto update switches. A manual update
-- passes the ticked boxes in arg2, and writing those back would disable the
-- switches of the boxes that were left unticked.
if not arg2 then
	uci_set("@global_rules[0]", "geoip_update", geoip_update)
	uci_set("@global_rules[0]", "geosite_update", geosite_update)
	uci_set("@global_rules[0]", "adblock_update", adblock_update)
end

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
