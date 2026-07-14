module("luci.passwall2.util_xray", package.seeall)
local api = require "luci.passwall2.api"
local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local appname = api.appname
local fs = api.fs
local CACHE_PATH = api.CACHE_PATH

local GLOBAL = {
	DNS_SERVER = {},
	DNS_HOSTNAME = {}
}

local xray_version = api.get_app_version("xray")

local xray_min_version = "26.3.27"

local function get_domain_excluded()
	local path = string.format("/usr/share/%s/domains_excluded", appname)
	local content = fs.readfile(path)
	if not content then return nil end
	local hosts = {}
	string.gsub(content, '[^' .. "\n" .. ']+', function(w)
		local s = api.trim(w)
		if s == "" then return end
		if s:find("#") and s:find("#") == 1 then return end
		if not s:find("#") or s:find("#") ~= 1 then table.insert(hosts, s) end
	end)
	if #hosts == 0 then hosts = nil end
	return hosts
end

function parseDNS(str)
	local result_dns_server
	-- [proto]://[ip]
	-- [proto]://[ip]:[port]
	-- https://[ip]/[path]
	-- https://[ip]:[port]/[path]
	local _a = api.parseURL(str)
	if _a then
		if _a.protocol == "tcp" or _a.protocol == "udp" or _a.protocol == "https" then
			result_dns_server = {
				address = str
			}
			if _a.protocol == "udp" then
				result_dns_server.address = _a.hostname
			end
			if _a.port then
				result_dns_server.port = _a.port
			else
				if _a.protocol == "https" then
					result_dns_server.port = 443
				else
					result_dns_server.port = 53
				end
			end
		end
	end
	return result_dns_server
end

function gen_outbound(flag, node, tag, proxy_table)
	local result = nil
	if node then
		local node_id = node[".name"]
		if tag == nil then
			tag = node_id
		end
		local remarks = node.remarks

		local proxy_tag = nil
		local fragment = nil
		local noise = nil
		local run_socks_instance = true
		if proxy_table ~= nil and type(proxy_table) == "table" then
			proxy_tag = proxy_table.tag or nil
			fragment = (proxy_table.fragment and not node.hysteria2_realms) and true or nil
			noise = (proxy_table.noise and not node.hysteria2_realms) and true or nil
			run_socks_instance = proxy_table.run_socks_instance
		end

		if node.type ~= "Xray" then
			local relay_port = node.port
			local new_port = api.get_new_port()
			local config_file = string.format("%s_%s_%s.json", flag, tag, new_port)
			if tag and node_id and not tag:find(node_id) then
				config_file = string.format("%s_%s_%s_%s.json", flag, tag, node_id, new_port)
			end
			if run_socks_instance then
				sys.call(string.format('/usr/share/%s/app.sh run_socks "%s"> /dev/null',
					appname,
					string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
						new_port, --flag
						node_id, --node
						"127.0.0.1", --bind
						new_port, --socks port
						config_file, --config file
						(proxy_tag and relay_port) and tostring(relay_port) or "" --relay port
						)
					)
				)
			end
			node = {}
			node.protocol = "socks"
			node.transport = "tcp"
			node.address = "127.0.0.1"
			node.port = new_port
			node.stream_security = "none"
			proxy_tag = "socks <- " .. node_id
		else
			if proxy_tag then
				node.proxySettings = {
					tag = proxy_tag,
					transportLayer = true
				}
			end
		end
		
		if node.type == "Xray" then
			if node.tls and node.tls == "1" then
				node.stream_security = "tls"
				if node.reality and node.reality == "1" then
					node.stream_security = "reality"
				end
			end
		end

		if node.protocol == "wireguard" and node.wireguard_reserved then
			local bytes = {}
			if not node.wireguard_reserved:match("[^%d,]+") then
				node.wireguard_reserved:gsub("%d+", function(b)
					bytes[#bytes + 1] = tonumber(b)
				end)
			else
				local result = api.base64Decode(node.wireguard_reserved)
				for i = 1, #result do
					bytes[i] = result:byte(i)
				end
			end
			node.wireguard_reserved = #bytes > 0 and bytes or nil
		end

		if node.protocol == "hysteria2" then
			node.protocol = "hysteria"
			node.transport = "hysteria"
			node.stream_security = "tls"
		end

		if remarks then
			tag = tag .. ":" .. remarks
		end

		node.address = (node.address or ""):lower()

		result = {
			_id = node_id,
			_flag = flag,
			_flag_proxy_tag = proxy_tag,
			tag = tag,
			proxySettings = node.proxySettings or nil,
			protocol = node.protocol,
			mux = {
				enabled = (node.mux == "1") and true or false,
				concurrency = (node.mux == "1" and ((node.mux_concurrency) and tonumber(node.mux_concurrency) or -1)) or nil,
				xudpConcurrency = (node.mux == "1" and ((node.xudp_concurrency) and tonumber(node.xudp_concurrency) or 8)) or nil
			} or nil,
			streamSettings = (node.streamSettings or node.protocol == "vmess" or node.protocol == "vless" or node.protocol == "socks" or node.protocol == "shadowsocks" or node.protocol == "trojan" or node.protocol == "hysteria") and {
				sockopt = {
					mark = 255,
					domainStrategy = node.domain_strategy or "UseIP",
					tcpFastOpen = (node.tcp_fast_open == "1") and true or nil,
					tcpMptcp = (node.tcpMptcp == "1") and true or nil
				},
				network = node.transport,
				security = node.stream_security,
				tlsSettings = (node.stream_security == "tls") and {
					serverName = node.tls_serverName,
					allowInsecure = (function()
								if node.tls_pinSHA256 and node.tls_pinSHA256 ~= "" then return nil end
								if api.compare_versions(os.date("%Y.%m.%d"), "<", "2026.6.1") and node.tls_allowInsecure == "1" then return true end
							end)(),
					fingerprint = (node.type == "Xray" and node.utls == "1" and node.fingerprint and node.fingerprint ~= "") and node.fingerprint or nil,
					pinnedPeerCertSha256 = (function()
								if api.compare_versions(xray_version, "<", "26.1.31") then return nil end
								if not node.tls_pinSHA256 then return "" end
								return node.tls_pinSHA256
							end)(),
					verifyPeerCertByName = (function()
								if api.compare_versions(xray_version, "<", "26.1.31") then return nil end
								if not node.tls_CertByName then return "" end
								return node.tls_CertByName
							end)(),
					echConfigList = (node.ech == "1") and node.ech_config or nil,
					certificates = (node.tls_certificate == "1" and node.tls_certificate_pem ~= "") and {
						certificate = api.split(node.tls_certificate_pem, "\n"),
						usage = "verify"
					} or nil
				} or nil,
				realitySettings = (node.stream_security == "reality") and {
					serverName = node.tls_serverName,
					publicKey = node.reality_publicKey,
					shortId = node.reality_shortId or "",
					spiderX = node.reality_spiderX or "/",
					fingerprint = (node.type == "Xray" and node.fingerprint and node.fingerprint ~= "") and node.fingerprint or "chrome",
					mldsa65Verify = (node.use_mldsa65Verify == "1") and node.reality_mldsa65Verify or nil
				} or nil,
				rawSettings = ((node.transport == "raw" or node.transport == "tcp") and node.protocol ~= "socks" and (node.tcp_guise and node.tcp_guise ~= "none")) and {
					header = {
						type = node.tcp_guise,
						request = (node.tcp_guise == "http") and {
							path = node.tcp_guise_http_path and (function()
									local t, r = node.tcp_guise_http_path, {}
									for _, v in ipairs(t) do
										r[#r + 1] = (v == "" and "/" or v)
									end
									return r
								end)() or {"/"},
							headers = (node.tcp_guise_http_host or node.user_agent) and {
								Host = node.tcp_guise_http_host,
								["User-Agent"] = node.user_agent and {node.user_agent} or nil
							} or nil
						} or nil
					}
				} or nil,
				kcpSettings = (node.transport == "mkcp") and {
					mtu = (node.mkcp_mtu and node.mkcp_mtu ~= "") and tonumber(node.mkcp_mtu) or 1350,
					tti = 50,
					uplinkCapacity = 12,
					downlinkCapacity = 100,
					CwndMultiplier = 1,
					MaxSendingWindow = 2 * 1024 * 1024
				} or nil,
				wsSettings = (node.transport == "ws") and {
					path = node.ws_path or "/",
					host = node.ws_host,
					headers = node.user_agent and {
						["User-Agent"] = node.user_agent
					} or nil,
					maxEarlyData = tonumber(node.ws_maxEarlyData) or nil,
					earlyDataHeaderName = (node.ws_earlyDataHeaderName) and node.ws_earlyDataHeaderName or nil,
					heartbeatPeriod = tonumber(node.ws_heartbeatPeriod) or nil
				} or nil,
				grpcSettings = (node.transport == "grpc") and {
					serviceName = node.grpc_serviceName,
					multiMode = (node.grpc_mode == "multi") and true or false,
					idle_timeout = node.grpc_idle_timeout and (tonumber(node.grpc_idle_timeout) < 10 and 10 or tonumber(node.grpc_idle_timeout)) or nil,
					health_check_timeout = tonumber(node.grpc_health_check_timeout) or nil,
					permit_without_stream = (node.grpc_permit_without_stream == "1") and true or false,
					initial_windows_size = node.grpc_initial_windows_size and tonumber(node.grpc_initial_windows_size) or 0,
					user_agent = node.user_agent
				} or nil,
				httpupgradeSettings = (node.transport == "httpupgrade") and {
					path = node.httpupgrade_path or "/",
					host = node.httpupgrade_host,
					headers =  node.user_agent and {
						["User-Agent"] = node.user_agent
					} or nil
				} or nil,
				xhttpSettings = (node.transport == "xhttp") and {
					mode = node.xhttp_mode or "auto",
					path = node.xhttp_path or "/",
					host = node.xhttp_host,
					extra = (function()
						local extra = {}
						if node.xhttp_extra then
							local ok, parsed = pcall(jsonc.parse, api.base64Decode(node.xhttp_extra))
							if ok and type(parsed) == "table" then
								extra = parsed.extra or parsed
							end
						end
						-- Handling User-Agent
						if node.user_agent and node.user_agent ~= "" then
							extra.headers = extra.headers or {}
							if not extra.headers["User-Agent"] and not extra.headers["user-agent"] then
								extra.headers["User-Agent"] = node.user_agent
							end
						end
						return api.cleanEmptyTables(extra)
					end)()
				} or nil,
				hysteriaSettings = (node.transport == "hysteria") and {
					version = 2,
					auth = node.hysteria2_auth_password
				} or nil,
				finalmask = (function()
					local finalmask = {}
					local TP = node.transport
					if TP == "mkcp" then
						local map = {none = "none", srtp = "srtp", utp = "utp", ["wechat-video"] = "wechat",
							dtls = "dtls", wireguard = "wireguard", dns = "dns"}
						local udp = {}
						if node.mkcp_guise and node.mkcp_guise ~= "none" then
							local g = { type = "mkcp-legacy" }
							g.settings = { header = map[node.mkcp_guise] }
							if node.mkcp_guise == "dns" and node.mkcp_domain and node.mkcp_domain ~= "" then
								g.settings.value = node.mkcp_domain
							end
							udp[#udp+1] = g
						end
						local s = { type = "mkcp-legacy" }
						if node.mkcp_seed and node.mkcp_seed ~= "" then
							s.settings = { value = node.mkcp_seed }
						end
						udp[#udp+1] = s
						finalmask.udp = udp
					elseif TP == "hysteria" then
						local udp = {}
						if node.hysteria2_obfs_type and node.hysteria2_obfs_type ~= "" then
							local o = {
								type = "salamander",
								settings = node.hysteria2_obfs_password and {
									password = node.hysteria2_obfs_password
								} or nil
							}
							if node.hysteria2_obfs_type == "gecko" then
								local min = tonumber(node.hysteria2_obfs_MinPacketSize) or 512
								local max = tonumber(node.hysteria2_obfs_MaxPacketSize) or 1200
								if min <= 0 or min > max or max > 2048 then
									min = 512
									max = 1200
								end
								o.settings.packetSize = min .. "-" .. max
							end
							udp[#udp+1] = o
						end
						if node.hysteria2_realms then
							local realm = api.parse_realm_uri(node.hysteria2_realm_url)
							local url, stun
							if realm then
								url = realm.scheme .. "://" .. realm.token .. "@" .. realm.server_url .. "/" .. realm.realm_id
								stun = realm.stun_servers or node.hysteria2_realm_stun
							end
							local r = {
								type = "realm",
								settings = {
									url = url,
									stunServers = stun
								}
							}
							udp[#udp+1] = r
						end
						finalmask.udp = udp
						local up = tonumber(node.hysteria2_up_mbps) or 0
						local down = tonumber(node.hysteria2_down_mbps) or 0
						finalmask.quicParams = {
							congestion = (up <= 0 and down <= 0) and "bbr" or "brutal",
							brutalUp = up > 0 and (up .. "mbps") or nil,
							brutalDown = down > 0 and (down .. "mbps") or nil,
							udpHop = (node.hysteria2_hop) and {
								ports = string.gsub(node.hysteria2_hop, ":", "-"),
								interval = (function(v)
									if not v then return 30 end
									if v:find("-", 1, true) then
										local min, max = v:match("^(%d+)%-(%d+)$")
										min = tonumber(min)
										max = tonumber(max)
										if min and max then
											min = (min >= 5) and min or 5
											max = (max >= min) and max or min
											return min .. "-" .. max
										end
										return 30
									end
									v = tonumber((v or "30"):match("^%d+"))
									return (v and v >= 5) and v or 30
								end)(node.hysteria2_hop_interval)
							} or nil,
							maxIdleTimeout = (function(t)
								t = tonumber(tostring(t or "30"):match("^%d+"))
								return (t and t >= 4 and t <= 120) and t or 30
							end)(node.hysteria2_idle_timeout),
							keepAlivePeriod = (function(t)
								t = tonumber(tostring(t or "0"):match("^%d+"))
								return (t and t >= 2 and t <= 60) and t or nil
							end)(node.hysteria2_keep_alive_period),
							disablePathMTUDiscovery = tonumber(node.hysteria2_disable_mtu_discovery) == 1
						}
					end
					if fragment and fragment_table and ({raw=1, ws=1, httpupgrade=1, grpc=1, xhttp=1})[TP] then
						finalmask.tcp = finalmask.tcp or {}
						finalmask.tcp[#finalmask.tcp+1] = api.clone(fragment_table)
					end
					if noise and noise_table and (TP == "mkcp" or (TP == "xhttp" and node.alpn == "h3")) then
						finalmask.udp = finalmask.udp or {}
						finalmask.udp[#finalmask.udp+1] = api.clone(noise_table)
					end
					if node.finalmask and node.finalmask ~= "" then
						local ok, fm = pcall(jsonc.parse, api.base64Decode(node.finalmask))
						if ok and type(fm) == "table" then
							finalmask = fm
						end
					end
					return api.cleanEmptyTables(finalmask)
				end)()
			} or nil,
			settings = {
				address = (node.protocol == "wireguard") and node.wireguard_local_address or node.address,
				port = tonumber(node.port),
				id = (node.protocol == "vmess" or node.protocol == "vless") and node.uuid or nil,
				encryption = (node.protocol == "vless") and ((node.encryption and node.encryption ~= "") and node.encryption or "none") or nil,
				flow = (node.protocol == "vless" and (node.tls == "1" or (node.encryption and node.encryption ~= "" and node.encryption ~= "none"))
					and node.flow and node.flow ~= "") and node.flow or nil,
				security = (node.protocol == "vmess") and node.security or nil,
				user = (node.protocol == "socks" or node.protocol == "http") and node.username or nil,
				pass = (node.protocol == "socks" or node.protocol == "http") and node.password or nil,
				password = (node.protocol == "shadowsocks" or node.protocol == "trojan") and node.password or nil,
				method = (node.protocol == "shadowsocks") and ((node.method == "chacha20-ietf-poly1305" and "chacha20-poly1305") or
					(node.method == "xchacha20-ietf-poly1305" and "xchacha20-poly1305") or (node.method ~= "" and node.method) or nil) or nil,
				secretKey = (node.protocol == "wireguard") and node.wireguard_secret_key or nil,
				peers = (node.protocol == "wireguard") and {
					{
						publicKey = node.wireguard_public_key,
						endpoint = node.address .. ":" .. node.port,
						preSharedKey = node.wireguard_preSharedKey,
						keepAlive = node.wireguard_keepAlive and tonumber(node.wireguard_keepAlive) or nil
					}
				} or nil,
				mtu = (node.protocol == "wireguard" and node.wireguard_mtu) and tonumber(node.wireguard_mtu) or nil,
				reserved = (node.protocol == "wireguard" and node.wireguard_reserved) and node.wireguard_reserved or nil,
				version = (node.protocol == "hysteria") and 2 or nil,
				level = 0
			}
		}

		if node.protocol == "hysteria" and node.hysteria2_realms then
			local realm = api.parse_realm_uri(node.hysteria2_realm_url)
			if realm then
				result.settings.address = realm.address
				result.settings.port = realm.port
			end
		end

		if node.protocol == "wireguard" then
			result.settings.noKernelTun = true
			if node.finalmask and node.finalmask ~= "" then
				local ok, fm = pcall(jsonc.parse, api.base64Decode(node.finalmask))
				if ok and type(fm) == "table" then
					result.streamSettings = result.streamSettings or {}
					result.streamSettings.finalmask = fm
				end
			end
		end

		local alpn = {}
		if node.alpn and node.alpn ~= "default" then
			string.gsub(node.alpn, '[^' .. "," .. ']+', function(w)
				table.insert(alpn, w)
			end)
		end
		if alpn and #alpn > 0 then
			if result.streamSettings.tlsSettings then
				result.streamSettings.tlsSettings.alpn = alpn
			end
		end

		if api.datatypes.hostname(node.address) and node.domain_resolver and (node.domain_resolver_dns or node.domain_resolver_dns_https) then
			local dns_tag = node_id .. "_dns"
			local dns_proto = node.domain_resolver
			local config_address
			local config_port
			if dns_proto == "https" then
				local _a = api.parseURL(node.domain_resolver_dns_https)
				if _a then
					config_address = node.domain_resolver_dns_https
					if _a.port then
						config_port = _a.port
					else
						config_port = 443
					end
					if _a.hostname then
						if api.datatypes.hostname(_a.hostname) then
							GLOBAL.DNS_HOSTNAME[_a.hostname] = true
						end
					end
				end
			else
				local server_address = node.domain_resolver_dns
				local config_port = 53
				local split = api.split(server_address, ":")
				if #split > 1 then
					server_address = split[1]
					config_port = tonumber(split[#split])
				end
				config_address = server_address
				if dns_proto == "tcp" then
					config_address = dns_proto .. "://" .. server_address .. ":" .. config_port
				end
			end
			GLOBAL.DNS_SERVER[node_id] = {
				tag = dns_tag,
				queryStrategy = node.domain_strategy or "UseIP",
				address = config_address,
				port = config_port,
				domains = {"full:" .. node.address},
				finalQuery = true,
				disableCache = false,
				serveStale = true,
			}
		end

	end
	return result
end

function gen_config_server(node)
	local settings = nil
	local routing = nil
	local outbounds = {
		{ protocol = "freedom", tag = "direct", settings = { finalRules = {{ action = "allow" }}}}, { protocol = "blackhole", tag = "blocked" }
	}

	if node.protocol == "vmess" or node.protocol == "vless" then
		if node.uuid then
			local users = {}
			for i = 1, #node.uuid do
				users[i] = {
					id = node.uuid[i],
					flow = (node.protocol == "vless"
					and (node.tls == "1" or (node.decryption and node.decryption ~= "" and node.decryption ~= "none")) 
					and node.flow and node.flow ~= "") and node.flow or nil
				}
			end
			settings = {
				users = users,
				decryption = (node.protocol == "vless") and ((node.decryption and node.decryption ~= "") and node.decryption or "none") or nil
			}
		end
	elseif node.protocol == "socks" then
		settings = {
			udp = ("1" == node.udp_forward) and true or false,
			auth = ("1" == node.auth) and "password" or "noauth",
			users = ("1" == node.auth) and {
				{
					user = node.username,
					pass = node.password
				}
			} or nil
		}
	elseif node.protocol == "http" then
		settings = {
			allowTransparent = false,
			users = ("1" == node.auth) and {
				{
					user = node.username,
					pass = node.password
				}
			} or nil
		}
		node.transport = "tcp"
		node.tcp_guise = "none"
	elseif node.protocol == "shadowsocks" then
		settings = {
			method = node.method,
			password = node.password,
			network = node.ss_network or "TCP,UDP"
		}
	elseif node.protocol == "trojan" then
		if node.uuid then
			local users = {}
			for i = 1, #node.uuid do
				users[i] = {
					password = node.uuid[i],
				}
			end
			settings = {
				users = users
			}
		end
	elseif node.protocol == "hysteria2" then
		settings = {
			version = 2,
			users = node.hysteria2_auth_password and {
				{ auth = node.hysteria2_auth_password }
			}
		}
	elseif node.protocol == "dokodemo-door" then
		settings = {
			network = node.d_protocol,
			address = node.d_address,
			port = tonumber(node.d_port)
		}
	end

	if node.fallback and node.fallback == "1" then
		local fallbacks = {}
		for i = 1, #node.fallback_list do
			local fallbackStr = node.fallback_list[i]
			if fallbackStr then
				local tmp = {}
				string.gsub(fallbackStr, '[^,]+', function(w)
					table.insert(tmp, w)
				end)
				local dest = tmp[1] or ""
				local path = tmp[2]
				local xver = tonumber(tmp[3])
				if not dest:find("%.") then
					dest = tonumber(dest)
				end
				fallbacks[i] = {
					path = path,
					dest = dest,
					xver = xver
				}
			end
		end
		settings.fallbacks = fallbacks
	end

	routing = {
		domainStrategy = "IPOnDemand",
		rules = {
			{
				ip = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				outboundTag = (node.accept_lan == nil or node.accept_lan == "0") and "blocked" or "direct"
			}
		}
	}

	if node.outbound_node then
		local outbound = nil
		if node.outbound_node == "_iface" and node.outbound_node_iface then
			outbound = {
				protocol = "freedom",
				tag = "outbound",
				streamSettings = {
					sockopt = {
						mark = 255,
						interface = node.outbound_node_iface
					}
				},
				settings = {
					finalRules = {{ action = "allow" }}
				}
			}
			sys.call(string.format("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.outbound_node_iface))
		else
			local outbound_node_t = uci:get_all("passwall2", node.outbound_node)
			if node.outbound_node == "_socks" or node.outbound_node == "_http" then
				outbound_node_t = {
					type = node.type,
					protocol = node.outbound_node:gsub("_", ""),
					transport = "tcp",
					address = node.outbound_node_address,
					port = node.outbound_node_port,
					username = (node.outbound_node_username and node.outbound_node_username ~= "") and node.outbound_node_username or nil,
					password = (node.outbound_node_password and node.outbound_node_password ~= "") and node.outbound_node_password or nil,
				}
			end
			outbound = require("luci.passwall2.util_xray").gen_outbound(nil, outbound_node_t, "outbound")
		end
		if outbound then
			table.insert(outbounds, 1, outbound)
		end
	end

	if node.protocol == "hysteria2" then
		node.protocol = "hysteria"
		node.transport = "hysteria"
		node.tls = "1"
	end

	local config = {
		log = {
			loglevel = ("1" == node.log) and node.loglevel or "none"
		},
		inbounds = {
			{
				listen = (node.bind_local == "1") and "127.0.0.1" or nil,
				port = tonumber(node.port),
				protocol = node.protocol,
				settings = settings,
				streamSettings = {
					network = node.transport,
					security = "none",
					tlsSettings = ("1" == node.tls) and {
						disableSystemRoot = false,
						certificates = {
							{
								certificateFile = node.tls_certificateFile,
								keyFile = node.tls_keyFile
							}
						},
						echServerKeys = (node.ech == "1") and node.ech_key or nil
					} or nil,
					rawSettings = (node.transport == "raw" or node.transport == "tcp") and {
						header = {
							type = node.tcp_guise,
							request = (node.tcp_guise == "http") and {
								path = node.tcp_guise_http_path and (function()
										local t, r = node.tcp_guise_http_path, {}
										for _, v in ipairs(t) do
											r[#r + 1] = (v == "" and "/" or v)
										end
										return r
									end)() or {"/"},
								headers = {
									Host = node.tcp_guise_http_host or {}
								}
							} or nil
						}
					} or nil,
					kcpSettings = (node.transport == "mkcp") and {
						mtu = (node.mkcp_mtu and node.mkcp_mtu ~= "") and tonumber(node.mkcp_mtu) or 1350,
						tti = 50,
						uplinkCapacity = 12,
						downlinkCapacity = 100,
						CwndMultiplier = 1,
						MaxSendingWindow = 2 * 1024 * 1024
					} or nil,
					wsSettings = (node.transport == "ws") and {
						host = node.ws_host or nil,
						path = node.ws_path
					} or nil,
					grpcSettings = (node.transport == "grpc" and node.grpc_serviceName) and {
						serviceName = node.grpc_serviceName
					} or nil,
					httpupgradeSettings = (node.transport == "httpupgrade") and {
						path = node.httpupgrade_path or "/",
						host = node.httpupgrade_host
					} or nil,
					xhttpSettings = (node.transport == "xhttp") and {
						path = node.xhttp_path or "/",
						host = node.xhttp_host,
						maxUploadSize = node.xhttp_maxuploadsize,
						maxConcurrentUploads = node.xhttp_maxconcurrentuploads
					} or nil,
					hysteriaSettings = (node.transport == "hysteria") and {
						version = 2
					} or nil,
					finalmask = (function()
						local finalmask = {}
						if node.transport == "mkcp" then
							local map = {none = "none", srtp = "srtp", utp = "utp", ["wechat-video"] = "wechat",
								dtls = "dtls", wireguard = "wireguard", dns = "dns"}
							local udp = {}
							if node.mkcp_guise and node.mkcp_guise ~= "none" then
								local g = { type = "mkcp-legacy" }
								g.settings = { header = map[node.mkcp_guise] }
								if node.mkcp_guise == "dns" and node.mkcp_domain and node.mkcp_domain ~= "" then
									g.settings.value = node.mkcp_domain
								end
								udp[#udp+1] = g
							end
							local s = { type = "mkcp-legacy" }
							if node.mkcp_seed and node.mkcp_seed ~= "" then
								s.settings = { value = node.mkcp_seed }
							end
							udp[#udp+1] = s
							finalmask.udp = udp
						elseif node.transport == "hysteria" then
							local udp = {}
							if node.hysteria2_obfs_type and node.hysteria2_obfs_type ~= "" then
								local o = {
									type = "salamander",
									settings = node.hysteria2_obfs_password and {
										password = node.hysteria2_obfs_password
									} or nil
								}
								if node.hysteria2_obfs_type == "gecko" then
									local min = tonumber(node.hysteria2_obfs_MinPacketSize) or 512
									local max = tonumber(node.hysteria2_obfs_MaxPacketSize) or 1200
									if min <= 0 or min > max or max > 2048 then
										min = 512
										max = 1200
									end
									o.settings.packetSize = min .. "-" .. max
								end
								udp[#udp+1] = o
							end
							if node.hysteria2_realms then
								local realm = api.parse_realm_uri(node.hysteria2_realm_url)
								local url, stun
								if realm then
									url = realm.scheme .. "://" .. realm.token .. "@" .. realm.server_url .. "/" .. realm.realm_id
									stun = realm.stun_servers or node.hysteria2_realm_stun
								end
								local r = {
									type = "realm",
									settings = {
										url = url,
										stunServers = stun
									}
								}
								udp[#udp+1] = r
							end
							finalmask.udp = udp
							local ignore = tonumber(node.hysteria2_ignore_client_bandwidth) == 1
							local up = (not ignore) and tonumber(node.hysteria2_up_mbps) or 0
							local down = (not ignore) and tonumber(node.hysteria2_down_mbps) or 0
							finalmask.quicParams = {
								congestion = (up <= 0 and down <= 0) and "bbr" or "brutal",
								brutalUp = up > 0 and (up .. "mbps") or nil,
								brutalDown = down > 0 and (down .. "mbps") or nil
							}
						end
						if node.finalmask and node.finalmask ~= "" then
							local ok, fm = pcall(jsonc.parse, api.base64Decode(node.finalmask))
							if ok and type(fm) == "table" then
								finalmask = fm
							end
						end
						return api.cleanEmptyTables(finalmask)
					end)(),
					sockopt = {
						tcpFastOpen = (node.tcp_fast_open == "1") and true or nil,
						acceptProxyProtocol = (node.acceptProxyProtocol and node.acceptProxyProtocol == "1") and true or false
					}
				}
			}
		},
		outbounds = outbounds,
		routing = routing,
		version = {
			min = xray_min_version
		}
	}

	local alpn = {}
	if node.alpn and node.alpn ~= "default" then
		string.gsub(node.alpn, '[^' .. "," .. ']+', function(w)
			table.insert(alpn, w)
		end)
	end
	if alpn and #alpn > 0 then
		if config.inbounds[1].streamSettings.tlsSettings then
			config.inbounds[1].streamSettings.tlsSettings.alpn = alpn
		end
	end

	if "1" == node.tls then
		config.inbounds[1].streamSettings.security = "tls"
		if "1" == node.reality then
			config.inbounds[1].streamSettings.tlsSettings = nil
			config.inbounds[1].streamSettings.security = "reality"
			config.inbounds[1].streamSettings.realitySettings = {
				show = false,
				dest = node.reality_dest,
				serverNames = node.reality_serverNames or {},
				privateKey = node.reality_private_key,
				shortIds = node.reality_shortId or "",
				mldsa65Seed = (node.use_mldsa65Seed == "1") and node.reality_mldsa65Seed or nil
			} or nil
		end
	end

	for index, value in ipairs(config.outbounds) do
		for k, v in pairs(config.outbounds[index]) do
			if k:find("_") == 1 then
				config.outbounds[index][k] = nil
			end
		end
		if value.protocol == "freedom" and api.compare_versions(xray_version, "<", "26.5.3") then -- Todo is to remove it
			value.settings = nil
		end
	end

	return config
end

function gen_config(var)
	local flag = var["flag"]
	local loglevel = var["loglevel"] or "warning"
	local node_id = var["node"]
	local server_host = var["server_host"]
	local server_port = var["server_port"]
	local tcp_proxy_way = var["tcp_proxy_way"]
	local redir_port = var["redir_port"]
	local local_socks_address = var["local_socks_address"] or "0.0.0.0"
	local local_socks_port = var["local_socks_port"]
	local local_socks_username = var["local_socks_username"]
	local local_socks_password = var["local_socks_password"]
	local local_http_address = var["local_http_address"] or "0.0.0.0"
	local local_http_port = var["local_http_port"]
	local local_http_username = var["local_http_username"]
	local local_http_password = var["local_http_password"]
	local dns_listen_port = var["dns_listen_port"]
	local direct_dns_udp_server = var["direct_dns_udp_server"]
	local direct_dns_udp_port = var["direct_dns_udp_port"]
	local direct_dns_query_strategy = var["direct_dns_query_strategy"]
	local direct_ipset = var["direct_ipset"]
	local direct_nftset = var["direct_nftset"]
	local remote_dns_udp_server = var["remote_dns_udp_server"]
	local remote_dns_udp_port = var["remote_dns_udp_port"]
	local remote_dns_tcp_server = var["remote_dns_tcp_server"]
	local remote_dns_tcp_port = var["remote_dns_tcp_port"]
	local remote_dns_doh_url = var["remote_dns_doh_url"]
	local remote_dns_doh_host = var["remote_dns_doh_host"]
	local remote_dns_doh_ip = var["remote_dns_doh_ip"]
	local remote_dns_doh_port = var["remote_dns_doh_port"]
	local remote_dns_fake = var["remote_dns_fake"]
	local remote_dns_query_strategy = var["remote_dns_query_strategy"]
	local remote_dns_detour = var["remote_dns_detour"]
	local dns_cache = var["dns_cache"]
	local no_run = var["no_run"]

	local dns_domain_rules = {}
	local dns = {}
	local fakedns = nil
	local inbounds = {}
	local outbounds = {}
	local routing = nil
	local observatory = nil
	local burstObservatory = nil
 	local strategy = nil
	local COMMON = {}

	local CACHE_TEXT_FILE = CACHE_PATH .. "/cache_" .. flag .. ".txt"

	local xray_settings = uci:get_all(appname, "@global_xray[0]") or {}

	if xray_settings.fragment == "1" then
		local lengths, delays = {}, {}
		api.trim(xray_settings.fragment_lengths):gsub("[^,]+", function(w)
		    w = w:gsub("%s+", "")
		    if w ~= "" then lengths[#lengths+1] = w end
		end)
		api.trim(xray_settings.fragment_delays):gsub("[^,]+", function(w)
		    w = w:gsub("%s+", "")
		    if w ~= "" then delays[#delays+1] = w end
		end)
		fragment_table = {
			type = "fragment",
			settings = {
				packets = xray_settings.fragment_packets or "tlshello",
				lengths = #lengths > 0 and lengths or {"3-5","6-8","10-20"},
				delays = #delays > 0 and delays or {"10-20"},
				maxSplit = xray_settings.fragment_maxSplit or "3-6"
			}
		}
	end

	if xray_settings.noise == "1" then
		local noises = {}
		uci:foreach(appname, "xray_noise_packets", function(n)
			if n.enabled == "1" then
				local noise = {
					rand = (n.type == "rand" and n.packet) and (n.packet:find("-", 1, true) and n.packet or tonumber(n.packet)) or nil,
					type = (n.type ~= "rand") and n.type or nil,
					packet = (n.type ~= "rand") and n.packet or nil,
					delay = n.delay and (n.delay:find("-", 1, true) and n.delay or tonumber(n.delay)) or nil
				}
				table.insert(noises, noise)
			end
		end)
		noise_table = #noises > 0 and {
			type = "noise",
			settings = { reset = 0, noise = noises }
		} or nil
	end

	local node = node_id and uci:get_all(appname, node_id) or nil
	local balancers = {}
	local rules = {}

	if local_socks_port then
		local inbound = {
			tag = "socks-in",
			listen = local_socks_address,
			port = tonumber(local_socks_port),
			protocol = "socks",
			settings = {auth = "noauth", udp = true},
			sniffing = {
				enabled = xray_settings.sniffing_override_dest == "1" or node.protocol == "_shunt"
			}
		}
		if inbound.sniffing.enabled == true then
			inbound.sniffing.destOverride = {"http", "tls", "quic"}
			inbound.sniffing.routeOnly = xray_settings.sniffing_override_dest ~= "1" or nil
			inbound.sniffing.domainsExcluded = xray_settings.sniffing_override_dest == "1" and get_domain_excluded() or nil
		end
		if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
			inbound.settings.auth = "password"
			inbound.settings.users = {
				{
					user = local_socks_username,
					pass = local_socks_password
				}
			}
		end
		table.insert(inbounds, inbound)
	end

	if local_http_port then
		local inbound = {
			listen = local_http_address,
			port = tonumber(local_http_port),
			protocol = "http",
			settings = {allowTransparent = false}
		}
		if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
			inbound.settings.users = {
				{
					user = local_http_username,
					pass = local_http_password
				}
			}
		end
		table.insert(inbounds, inbound)
	end

	function gen_socks_config_node(node_id, socks_id, remarks)
		if node_id then
			socks_id = node_id:sub(1 + #"Socks_")
		end
		local result
		local socks_node = uci:get_all(appname, socks_id) or nil
		if socks_node then
			if not remarks then
				remarks = socks_node.port
			end
			result = {
				[".name"] = "Socksid_" .. socks_id,
				remarks = remarks,
				type = "Xray",
				protocol = "socks",
				address = "127.0.0.1",
				port = socks_node.port,
				transport = "tcp",
				stream_security = "none"
			}
		end
		return result
	end

	function get_node_by_id(node_id)
		if not node_id or node_id == "" or node_id == "nil" then return nil end
		if node_id:find("Socks_") then
			return gen_socks_config_node(node_id)
		else
			return uci:get_all(appname, node_id)
		end
	end

	local nodes_list = {}
	function get_balancer_batch_nodes(_node)
		if #nodes_list == 0 then
			for k, e in ipairs(api.get_valid_nodes()) do
				if e.node_type == "normal" and (not e.chain_proxy or e.chain_proxy == "") then
					nodes_list[#nodes_list + 1] = {
						id = e[".name"],
						remarks = e["remarks"],
						group = e["group"]
					}
				end
			end
		end
		if not _node.node_group or _node.node_group == "" then return {} end
		local nodes = {}
		for g in _node.node_group:gmatch("%S+") do
			g = api.UrlDecode(g)
			for k, v in pairs(nodes_list) do
				local gn = (v.group and v.group ~= "") and v.group or "default"
				if gn:lower() == g:lower() and api.match_node_rule(v.remarks, _node.node_match_rule) then
					nodes[#nodes + 1] = v.id
				end
			end
		end
		return nodes
	end

	function gen_loopback(outbound_tag, loopback_dst)
		if not outbound_tag or outbound_tag == "" then return nil end
		local inbound_tag = loopback_dst and "lo-to-" .. loopback_dst or outbound_tag .. "-lo"
		local loopback_outbound = {
			protocol = "loopback",
			tag = outbound_tag,
			settings = { inboundTag = inbound_tag }
		}
		local insert_index = #outbounds + 1
		if outbound_tag == "default" then
			insert_index = 1
		end
		table.insert(outbounds, insert_index, loopback_outbound)
		return loopback_outbound
	end

	function gen_balancer(_node, loopback_tag)
		local balancer_id = _node[".name"]
		local balancer_tag = "balancer-" .. balancer_id
		local loopback_dst = balancer_id -- route destination for the loopback outbound
		if not loopback_tag or loopback_tag == "" then loopback_tag = balancer_id end
		-- existing balancer
		for _, v in ipairs(balancers) do
			if v.tag == balancer_tag then
				local loopback_outbound = gen_loopback(loopback_tag, loopback_dst)
				return balancer_tag, loopback_outbound
			end
		end
		-- new balancer
		local blc_nodes
		if _node.node_add_mode and _node.node_add_mode == "batch" then
			blc_nodes = get_balancer_batch_nodes(_node)
		else
			blc_nodes = _node.balancing_node
		end
		local valid_nodes = {}
		for i = 1, #(blc_nodes or {}) do
			local blc_node_id = blc_nodes[i]
			local blc_node_tag = "blc-" .. blc_node_id
			local is_new_blc_node = true
			for _, outbound in ipairs(outbounds) do
				if string.sub(outbound.tag, 1, #blc_node_tag) == blc_node_tag then
					is_new_blc_node = false
					valid_nodes[#valid_nodes + 1] = outbound.tag
					break
				end
			end
			if is_new_blc_node then
				local outboundTag = gen_outbound_get_tag(flag, blc_node_id, blc_node_tag, { fragment = xray_settings.fragment == "1" or nil, noise = xray_settings.noise == "1" or nil, run_socks_instance = not no_run })
				if outboundTag then
					valid_nodes[#valid_nodes + 1] = outboundTag
				end
			end
		end
		if #valid_nodes == 0 then return nil end

		-- fallback node
		local fallback_node_id = _node.fallback_node
		fallback_node_id = (fallback_node_id and fallback_node_id ~= "") and fallback_node_id or nil
		local fallback_node_tag = (fallback_node_id == "_direct") and "direct" or "blackhole"
		if fallback_node_id and fallback_node_id ~= "_direct" then
			local is_new_node = true
			for _, outbound in ipairs(outbounds) do
				if string.sub(outbound.tag, 1, #fallback_node_id) == fallback_node_id then
					is_new_node = false
					fallback_node_tag = outbound.tag
					break
				end
			end
			if is_new_node then
				local fallback_node = get_node_by_id(fallback_node_id)
				if fallback_node then
					if fallback_node.protocol ~= "_balancing" then
						local outboundTag = gen_outbound_get_tag(flag, fallback_node, fallback_node_id, { fragment = xray_settings.fragment == "1" or nil, noise = xray_settings.noise == "1" or nil, run_socks_instance = not no_run })
						if outboundTag then
							fallback_node_tag = outboundTag
						end
					else
						if gen_balancer(fallback_node) then
							fallback_node_tag = fallback_node_id
						end
					end
				end
			end
		end
		if _node.balancingStrategy == "leastLoad" then
			strategy = {
				type = _node.balancingStrategy,
				settings = {
					expected = _node.expected and tonumber(_node.expected) and tonumber(_node.expected) or 2,
					maxRTT = "1s",
					tolerance = (function(t)
						t = tonumber(t) or 0
						if t < 1 then return nil end
						if t > 100 then t = 100 end
						return t / 100
					end)(_node.tolerance)
				}
			}
		else
			strategy = { type = _node.balancingStrategy or "random" }
		end
		table.insert(balancers, {
			tag = balancer_tag,
			selector = api.clone(valid_nodes),
			fallbackTag = fallback_node_tag,
			strategy = strategy
		})
		if _node.balancingStrategy == "leastPing" or _node.balancingStrategy == "leastLoad" or fallback_node_tag then
			local t = api.format_go_time(_node.probeInterval)
			if t == "0s" then
				t = "60s"
			elseif not t:find("[hm]") and tonumber(t:match("%d+")) < 10 then
				t = "10s"
			end
			if _node.balancingStrategy == "leastLoad" then
				burstObservatory = burstObservatory or {
					subjectSelector = { "blc-" },
					pingConfig = {
						destination = _node.useCustomProbeUrl and _node.probeUrl or nil,
						interval = t,
						sampling = 3,
						timeout = "5s"
					}
				}
			else
				observatory = observatory or {
					subjectSelector = { "blc-" },
					probeUrl = _node.useCustomProbeUrl and _node.probeUrl or nil,
					probeInterval = t,
					enableConcurrency = true
				}
			end
		end
		local loopback_outbound = gen_loopback(loopback_tag, loopback_dst)
		local inbound_tag = loopback_outbound.settings.inboundTag
		table.insert(rules, { inboundTag = { inbound_tag }, balancerTag = balancer_tag })
		return balancer_tag, loopback_outbound
	end
	
	function set_outbound_detour(node, outbound, outbounds_table)
		if not node or not outbound or not outbounds_table then return nil end
		local default_outTag = outbound.tag
		local last_insert_outbound

		if node.chain_proxy == "1" and node.preproxy_node then
			if outbound["_flag_proxy_tag"] then
				--Ignore
			else
				local preproxy_node = get_node_by_id(node.preproxy_node)
				if preproxy_node then
					local preproxy_outbound, exist
					if preproxy_node.protocol == "_balancing" then
						local balancer_tag, loopback_outbound = gen_balancer(preproxy_node)
						if loopback_outbound then
							preproxy_outbound = loopback_outbound
							exist = true
						end
					else
						preproxy_outbound = gen_outbound(node[".name"], preproxy_node)
					end
					if preproxy_outbound then
						outbound.tag = preproxy_outbound.tag .. " -> " .. outbound.tag
						outbound.proxySettings = {
							tag = preproxy_outbound.tag,
							transportLayer = true
						}
						if not exist then
							last_insert_outbound = preproxy_outbound
						end
						default_outTag = outbound.tag
					end
				end
			end
		end
		if node.chain_proxy == "2" and node.to_node then
			local to_node = get_node_by_id(node.to_node)
			if to_node then
				-- Landing Node not support use special node.
				if to_node.protocol and to_node.protocol:find("^_") then
					to_node = nil
				end
			end
			if to_node then
				local to_outbound
				if to_node.type ~= "Xray" then
					local in_tag = "inbound_" .. to_node[".name"] .. "_" .. tostring(outbound.tag)
					local new_port = api.get_new_port()
					table.insert(inbounds, {
						tag = in_tag,
						listen = "127.0.0.1",
						port = new_port,
						protocol = "dokodemo-door",
						settings = {network = "tcp,udp", address = to_node.address, port = tonumber(to_node.port)}
					})
					if to_node.tls_serverName == nil then
						to_node.tls_serverName = to_node.address
					end
					to_node.address = "127.0.0.1"
					to_node.port = new_port
					table.insert(rules, 1, {
						inboundTag = {in_tag},
						outboundTag = outbound.tag
					})
					to_outbound = gen_outbound(node[".name"], to_node, to_node[".name"], {
						tag = to_node[".name"],
						run_socks_instance = not no_run
					})
				else
					to_outbound = gen_outbound(node[".name"], to_node)
				end
				if to_outbound then
					to_outbound.tag = outbound.tag .. " -> " .. to_outbound.tag
					if to_node.type == "Xray" then
						to_outbound.proxySettings = {
							tag = outbound.tag,
							transportLayer = true
						}
					end
					table.insert(outbounds_table, to_outbound)
					default_outTag = to_outbound.tag
				end
			end
		end
		if node.chain_proxy == "3" and node.outbound_iface then
			if outbound.streamSettings and outbound.streamSettings.sockopt then
				outbound.streamSettings.sockopt.interface = node.outbound_iface
			end
		end
		return default_outTag, last_insert_outbound
	end

	function gen_outbound_get_tag(flag, node_id, tag, proxy_table)
		if not node_id or node_id == "" or node_id == "nil" then return nil end
		local node
		if type(node_id) == "string" then
			node = get_node_by_id(node_id)
		elseif type(node_id) == "table" then
			node = node_id
		end
		if not tag then tag = node[".name"] end
		if node then
			if proxy_table.chain_proxy == "1" or proxy_table.chain_proxy == "2" then
				node.chain_proxy = proxy_table.chain_proxy
				node.preproxy_node = proxy_table.chain_proxy == "1" and proxy_table.preproxy_node
				node.to_node = proxy_table.chain_proxy == "2" and proxy_table.to_node
				proxy_table.chain_proxy = nil
				proxy_table.preproxy_node = nil
				proxy_table.to_node = nil
			end
			if tag == "default" then
				if default_node_address and default_node_port then
					node.address = default_node_address
					node.port = default_node_port
				end
			end
			local outbound, has_add_outbound
			for _, _outbound in ipairs(outbounds) do
				-- Avoid generating duplicate nested processes
				if _outbound["_flag_proxy_tag"] and _outbound["_flag_proxy_tag"]:find("socks <- " .. node[".name"], 1, true) then
					outbound = api.clone(_outbound)
					outbound.tag = tag
					break
				end
			end
			if node.protocol == "_balancing" then
				local balancer_tag, loopback_outbound = gen_balancer(node, tag)
				if loopback_outbound then
					outbound = loopback_outbound
					node[".name"] = outbound.tag
					has_add_outbound = true
				end
			elseif node.protocol == "_iface" then
				if node.iface then
					outbound = {
						tag = tag,
						protocol = "freedom",
						streamSettings = {
							sockopt = {
								mark = 255,
								interface = node.iface
							}
						},
						settings = (api.compare_versions(xray_version, ">", "26.4.25")) and {  -- Todo: Remove version check
							finalRules = {{ action = "allow" }}
						} or nil
					}
					sys.call(string.format("mkdir -p %s && touch %s/%s", api.TMP_IFACE_PATH, api.TMP_IFACE_PATH, node.iface))
				end
			end
			if not outbound then
				outbound = gen_outbound(flag, node, tag, proxy_table)
			end
			if outbound then
				local default_outbound_tag, last_insert_outbound = set_outbound_detour(node, outbound, outbounds)
				if not has_add_outbound then
					local insert_index = #outbounds + 1
					if tag == "default" then
						insert_index = 1
					end
					table.insert(outbounds, insert_index, outbound)
				end
				if last_insert_outbound then
					table.insert(outbounds, last_insert_outbound)
				end
				return default_outbound_tag
			end
		end
	end

	if node then
		if node.protocol ~= "_shunt" then
			-- create shunt logic
			local tmp_node = {
				remarks = node.remarks,
				type = "Xray",
				protocol = "_shunt",
				default_node = node[".name"],
			}
			tmp_node.fakedns = remote_dns_fake
			tmp_node.default_fakedns = remote_dns_fake
			node = tmp_node
		end

		if server_host and server_port then
			default_node_address = server_host
			default_node_port = server_port
		end

		if node.protocol == "_shunt" then
			inner_fakedns = node.fakedns or "0"

			local function gen_shunt_node(rule_name, _node_id)
				if not rule_name then return nil end
				if not _node_id then _node_id = node[rule_name] end
				if _node_id == "_direct" then
					return "direct"
				elseif _node_id == "_blackhole" then
					return "blackhole"
				elseif _node_id == "_default" and rule_name ~= "default" then
					return "default"
				elseif _node_id then
					local proxy_table = {
						fragment = xray_settings.fragment == "1",
						noise = xray_settings.noise == "1",
						run_socks_instance = not no_run,
					}
					local preproxy_node_id = node[rule_name .. "_proxy_tag"]
					if preproxy_node_id == _node_id then preproxy_node_id = nil end
					if preproxy_node_id then
						proxy_table.chain_proxy = "2"
						proxy_table.to_node = _node_id
						return gen_outbound_get_tag(flag, preproxy_node_id, rule_name, proxy_table)
					else
						return gen_outbound_get_tag(flag, _node_id, rule_name, proxy_table)
					end
				end
				return nil
			end

			--default_node
			local default_node_id = node.default_node or "_direct"
			local default_outboundTag = gen_shunt_node("default", default_node_id)
			COMMON.default_outbound_tag = default_outboundTag

			if inner_fakedns == "1" and node["default_fakedns"] == "1" then
				remote_dns_fake = true
			end

			--shunt rule
			uci:foreach(appname, "shunt_rules", function(e)
				local outboundTag = gen_shunt_node(e[".name"])
				if outboundTag and e.remarks then
					if outboundTag == "default" then
						outboundTag = default_outboundTag
					end
					local protocols = nil
					if e["protocol"] and e["protocol"] ~= "" then
						protocols = {}
						string.gsub(e["protocol"], '[^' .. " " .. ']+', function(w)
							table.insert(protocols, w)
						end)
					end
					local inboundTag = nil
					if e["inbound"] and e["inbound"] ~= "" then
						inboundTag = {}
						if e["inbound"]:find("tproxy") then
							if redir_port then
								table.insert(inboundTag, "tcp_redir")
								table.insert(inboundTag, "udp_redir")
							end
						end
						if e["inbound"]:find("socks") then
							if local_socks_port then
								table.insert(inboundTag, "socks-in")
							end
						end
					end
					local domains = nil
					if e.domain_list then
						local domain_table = {
							shunt_rule_name = e[".name"],
							outboundTag = outboundTag,
							domain = {},
							fakedns = nil,
						}
						domains = {}
						string.gsub(e.domain_list, '[^' .. "\r\n" .. ']+', function(w)
							if w:find("#") == 1 then return end
							if w:find("rule-set:", 1, true) == 1 or w:find("rs:") == 1 then return end
							table.insert(domains, w)
							table.insert(domain_table.domain, w)
						end)
						if inner_fakedns == "1" and node[e[".name"] .. "_fakedns"] == "1" and #domains > 0 then
							domain_table.fakedns = true
						end
						if outboundTag then
							table.insert(dns_domain_rules, api.clone(domain_table))
						end
						if #domains == 0 then
							domains = nil
						end
					end
					local ip = nil
					if e.ip_list then
						ip = {}
						string.gsub(e.ip_list, '[^' .. "\r\n" .. ']+', function(w)
							if w:find("#") == 1 then return end
							if w:find("rule-set:", 1, true) == 1 or w:find("rs:") == 1 then return end
							table.insert(ip, w)
						end)
						if #ip == 0 then ip = nil end
					end
					local source = nil
					if e.source then
						source = {}
						string.gsub(e.source, '[^' .. " " .. ']+', function(w)
							table.insert(source, w)
						end)
					end
					local rule = {
						ruleTag = e.remarks,
						inboundTag = inboundTag,
						outboundTag = outboundTag,
						network = e["network"] or "tcp,udp",
						source = source,
						--sourcePort = e["sourcePort"] ~= "" and e["sourcePort"] or nil,
						port = e["port"] ~= "" and e["port"] or nil,
						protocol = protocols
					}
					if domains then
						local _rule = api.clone(rule)
						_rule.ruleTag = _rule.ruleTag .. " Domains"
						_rule.domains = domains
						table.insert(rules, _rule)
					end
					if ip then
						local _rule = api.clone(rule)
						_rule.ruleTag = _rule.ruleTag .. " IP"
						_rule.ip = ip
						table.insert(rules, _rule)
					end
					if not domains and not ip then
						table.insert(rules, rule)
					end
				end
			end)

			if default_outboundTag then
				local rule = {
					ruleTag = "default",
					outboundTag = default_outboundTag,
				}
				if node.domainStrategy == "IPIfNonMatch" then
					rule.port = "1-65535"
				else
					rule.network = "tcp,udp"
				end
				table.insert(rules, rule)
			end

			routing = {
				domainStrategy = node.domainStrategy or "AsIs",
				domainMatcher = node.domainMatcher or "hybrid",
				balancers = #balancers > 0 and balancers or nil,
				rules = rules
			}
		end
	end

	local dns_servers = {}
	local direct_dns_tag = "dns-in-direct"
	local remote_dns_tag = "dns-in-remote"
	local remote_fakedns_tag = "dns-in-remote-fakedns"
	local default_dns_tag = "dns-in-default"

	dns = {
		tag = "dns-global",
		hosts = {},
		disableCache = (dns_cache and dns_cache == "0") and true or false,
		disableFallback = true,
		disableFallbackIfMatch = true,
		servers = {},
		queryStrategy = "UseIP"
	}

	for i, v in pairs(GLOBAL.DNS_SERVER) do
		table.insert(dns_servers, {
			server = v,
			outboundTag = "direct"
		})
	end

	local _direct_dns = nil
	if direct_dns_udp_server then
		_direct_dns = {
			tag = direct_dns_tag,
			address = direct_dns_udp_server,
			port = tonumber(direct_dns_udp_port) or 53,
			queryStrategy = (direct_dns_query_strategy and direct_dns_query_strategy ~= "") and direct_dns_query_strategy or "UseIP"
		}

		if _direct_dns.address then
			table.insert(dns_servers, {
				outboundTag = "direct",
				server = _direct_dns
			})
		end
	end

	if next(GLOBAL.DNS_HOSTNAME) then
		local hostname = {}
		for line, _ in pairs(GLOBAL.DNS_HOSTNAME) do
			table.insert(hostname, line)
		end
		local new_dns_server
		if _direct_dns then
			new_dns_server = api.clone(_direct_dns)
		else
			new_dns_server = {
				address = "localhost"
			}
		end
		new_dns_server.tag = "dns-in-bootstrap"
		new_dns_server.domains = hostname
		table.insert(dns_servers, #dns_servers - 1, {
			outboundTag = "direct",
			server = new_dns_server
		})
	end

	if dns_listen_port then
		local _remote_dns_proto = "tcp"

		if not routing then
			routing = {
				domainStrategy = "IPOnDemand",
				rules = {}
			}
		end
	
		local dns_host = ""
		if flag == "global" then
			dns_host = uci:get(appname, "@global[0]", "dns_hosts") or ""
		else
			flag = flag:gsub("acl_", "")
			local dns_hosts_mode = uci:get(appname, flag, "dns_hosts_mode") or "default"
			if dns_hosts_mode == "default" then
				dns_host = uci:get(appname, "@global[0]", "dns_hosts") or ""
			elseif dns_hosts_mode == "disable" then
				dns_host = ""
			elseif dns_hosts_mode == "custom" then
				dns_host = uci:get(appname, flag, "dns_hosts") or ""
			end
		end
		if #dns_host > 0 then
			string.gsub(dns_host, '[^' .. "\r\n" .. ']+', function(w)
				local host = sys.exec(string.format("echo -n $(echo %s | awk -F ' ' '{print $1}')", w))
				local key = sys.exec(string.format("echo -n $(echo %s | awk -F ' ' '{print $2}')", w))
				if host ~= "" and key ~= "" then
					dns.hosts[host] = key
				end
			end)
		end

		local _remote_dns_ip = nil
	
		local _remote_dns = {
			tag = remote_dns_tag,
			queryStrategy = (remote_dns_query_strategy and remote_dns_query_strategy ~= "") and remote_dns_query_strategy or "UseIPv4"
		}

		if remote_dns_udp_server then
			_remote_dns.address = remote_dns_udp_server
			_remote_dns.port = tonumber(remote_dns_udp_port) or 53
			_remote_dns_proto = "udp"
			_remote_dns_ip = remote_dns_udp_server
		end

		if remote_dns_tcp_server then
			_remote_dns.address = "tcp://" .. remote_dns_tcp_server .. ":" .. tonumber(remote_dns_tcp_port) or 53
			_remote_dns.port = tonumber(remote_dns_tcp_port) or 53
			_remote_dns_proto = "tcp"
			_remote_dns_ip = remote_dns_tcp_server
		end

		if remote_dns_doh_url and remote_dns_doh_host then
			if remote_dns_doh_ip and remote_dns_doh_host ~= remote_dns_doh_ip and not api.is_ip(remote_dns_doh_host) then
				dns.hosts[remote_dns_doh_host] = remote_dns_doh_ip
			end
			_remote_dns.address = remote_dns_doh_url
			_remote_dns.port = tonumber(remote_dns_doh_port) or 443
			_remote_dns_ip = remote_dns_doh_ip
		end

		if _remote_dns.address then
			table.insert(dns_servers, {
				outboundTag = remote_dns_detour == "direct" and "direct" or nil,
				server = _remote_dns
			})
		end

		local _remote_fakedns = nil
		if remote_dns_fake or inner_fakedns == "1" then
			fakedns = {}
			local fakedns4 = {
				ipPool = "198.18.0.0/16",
				poolSize = 65535
			}
			local fakedns6 = {
				ipPool = "fc00::/18",
				poolSize = 65535
			}
			if remote_dns_query_strategy == "UseIP" then
				table.insert(fakedns, fakedns4)
				table.insert(fakedns, fakedns6)
			elseif remote_dns_query_strategy == "UseIPv4" then
				table.insert(fakedns, fakedns4)
			elseif remote_dns_query_strategy == "UseIPv6" then
				table.insert(fakedns, fakedns6)
			end
			_remote_fakedns = {
				tag = remote_fakedns_tag,
				address = "fakedns",
			}
			table.insert(dns_servers, {
				server = _remote_fakedns
			})
		end

		if direct_dns_udp_server then
			local domain = {}
			local nodes_domain_text = sys.exec('uci show passwall2 | grep ".address=" | cut -d "\'" -f 2 | grep "[a-zA-Z]$" | sort -u')
			string.gsub(nodes_domain_text, '[^' .. "\r\n" .. ']+', function(w)
				w = (w or ""):lower()
				table.insert(domain, "full:" .. w)
			end)
			if #domain > 0 then
				table.insert(dns.servers, 1, {
					tag = "dns-in-vpslist",
					address = "localhost",
					domains = domain,
					finalQuery = true,
					disableCache = false,
					serveStale = true,
				})
			end
		end

		local dns_outbound
		if dns_listen_port then
			table.insert(inbounds, {
				listen = "127.0.0.1",
				port = tonumber(dns_listen_port),
				protocol = "dokodemo-door",
				tag = "dns-in",
				settings = {
					address = "0.0.0.0",
					network = "tcp,udp"
				}
			})
			local direct_type_dns = {
				settings = {
					address = direct_dns_udp_server,
					port = tonumber(direct_dns_udp_port) or 53,
					network = "udp",
					nonIPQuery = (api.compare_versions(xray_version, "<", "26.4.25")) and "skip" or nil, -- Todo is to remove it
					blockTypes = (api.compare_versions(xray_version, "<", "26.4.25")) and { 65 } or nil,  -- Todo is to remove it
					rules = (api.compare_versions(xray_version, ">", "26.4.17")) and {
						{
							qType = "1,28",
							action = "hijack"
						},
						{
							qType = 65,
							action = "return",
							rCode = 0
						},
						{
							action = "direct"
						}
					} or nil
				},
				proxySettings = {
					tag = "direct"
				}
			}
			local remote_type_dns = {
				settings = {
					address = remote_dns_udp_server,
					port = tonumber(remote_dns_udp_port) or 53,
					network = _remote_dns_proto or "tcp",
					nonIPQuery = (api.compare_versions(xray_version, "<", "26.4.25")) and "reject" or nil, -- Todo is to remove it
					rules = (api.compare_versions(xray_version, ">", "26.4.17")) and {
						{
							qType = "1,28",
							action = "hijack"
						},
						{
							action = "return",
							rCode = 0
						}
					} or nil
				}
			}
			local type_dns = direct_type_dns
			dns_outbound = {
				tag = "dns-out",
				protocol = "dns",
				proxySettings = type_dns.proxySettings,
				settings = type_dns.settings
			}
			table.insert(outbounds, dns_outbound)
			table.insert(routing.rules, 1, {
				inboundTag = {
					"dns-in"
				},
				outboundTag = "dns-out"
			})
		end
	
		local default_dns_tag_name = remote_dns_tag
		if not COMMON.default_outbound_tag or COMMON.default_outbound_tag == "direct" then
			default_dns_tag_name = direct_dns_tag
		end
	
		if dns_servers and #dns_servers > 0 then
			-- Default DNS logic
			local default_dns_server = nil
			for index, value in ipairs(dns_servers) do
				if not default_dns_server and value.server.tag == default_dns_tag_name then
					default_dns_server = api.clone(value)
					default_dns_server.server.tag = default_dns_tag
					if value.server.tag == remote_dns_tag then
						if remote_dns_fake then
							default_dns_server.server = api.clone(_remote_fakedns)
							default_dns_server.server.tag = default_dns_tag
						else
							default_dns_server.outboundTag = value.outboundTag or COMMON.default_outbound_tag
						end
					end
					table.insert(dns_servers, 1, default_dns_server)
					break
				end
			end

			-- Shunt rule DNS logic
			local dns_out_rules = {}
			if dns_domain_rules and #dns_domain_rules > 0 then
				for index, value in ipairs(dns_domain_rules) do
					if value.domain and value.outboundTag then
						local dns_server = nil
						local dns_outboundTag = value.outboundTag
						if value.dns_server then
							dns_server = api.clone(value.dns_server)
						elseif value.outboundTag == "direct" then
							dns_server = api.clone(_direct_dns)
						else
							if value.fakedns then
								dns_server = api.clone(_remote_fakedns)
							else
								dns_server = api.clone(_remote_dns)
								if remote_dns_detour == "direct" then
									dns_outboundTag = "direct"
								end
							end
						end
						if dns_outboundTag == "blackhole" then
							table.insert(dns_out_rules, {
								action = "return",
								rCode = 0,
								domain = api.clone(value.domain)
							})
							dns_server = nil
						else
							table.insert(dns_out_rules, {
								action = "hijack",
								qType = "1,28",
								domain = api.clone(value.domain)
							})
						end
						if dns_server then
							dns_server.finalQuery = true
							dns_server.domains = value.domain
							if value.shunt_rule_name then
								dns_server.tag = "dns-in-" .. value.shunt_rule_name
							end
							table.insert(dns_servers, {
								outboundTag = dns_outboundTag,
								server = dns_server
							})
						end
					end
				end
				if dns_outbound and dns_outbound.settings.rules and #dns_out_rules > 0 then
					for i = #dns_out_rules, 1, -1 do
						table.insert(dns_outbound.settings.rules, 1, dns_out_rules[i])
					end
				end
			end
		end

		local default_rule_index = nil
		for index, value in ipairs(routing.rules) do
			if value.ruleTag == "default" then
				default_rule_index = index
				break
			end
		end
		if default_rule_index then
			local default_rule = api.clone(routing.rules[default_rule_index])
			table.remove(routing.rules, default_rule_index)
			table.insert(routing.rules, default_rule)
		end

		local content = flag .. node_id .. jsonc.stringify(routing.rules)
		if api.cacheFileCompareToLogic(CACHE_TEXT_FILE, content) == false then
			--clear ipset/nftset
			if direct_ipset then
				string.gsub(direct_ipset, '[^' .. "," .. ']+', function(w)
					sys.call("ipset -q -F " .. w)
				end)
				local ipset_prefix_name = "psw2_" .. node_id .. "_"
				local ipset_list = sys.exec("ipset list | grep 'Name: ' | grep '" .. ipset_prefix_name .. "' | awk '{print $2}'")
				string.gsub(ipset_list, '[^' .. "\r\n" .. ']+', function(w)
					sys.call("ipset -q -F " .. w)
				end)
			end
			if direct_nftset then
				string.gsub(direct_nftset, '[^' .. "," .. ']+', function(w)
					local split = api.split(w, "#")
					if #split > 3 then
						local ip_type = split[1]
						local family = split[2]
						local table_name = split[3]
						local set_name = split[4]
						sys.call(string.format("nft flush set %s %s %s 2>/dev/null", family, table_name, set_name))
					end
				end)
				local family = "inet"
				local table_name = "passwall2"
				local nftset_prefix_name = "psw2_" .. node_id .. "_"
				local nftset_list = sys.exec("nft -a list sets | grep -E '" .. nftset_prefix_name .. "' | awk -F 'set ' '{print $2}' | awk '{print $1}'")
				string.gsub(nftset_list, '[^' .. "\r\n" .. ']+', function(w)
					sys.call(string.format("nft flush set %s %s %s 2>/dev/null", family, table_name, w))
				end)
			end
		end
	end

	if not next(dns.hosts) then
		dns.hosts = nil
	end

	for i = #dns_servers, 1, -1 do
		local value = dns_servers[i]
		if value.server.tag ~= direct_dns_tag and value.server.tag ~= remote_dns_tag then
			-- DNS rule must be at the front, prevents being matched by rules.
			if value.outboundTag and value.server.address ~= "fakedns" then
				table.insert(routing.rules, 1, {
					inboundTag = {
						value.server.tag
					},
					outboundTag = value.outboundTag,
				})
			end
			if (value.server.domains and #value.server.domains > 0) or value.server.tag == default_dns_tag then
				-- Only keep default DNS server or has domains DNS server.
				table.insert(dns.servers, 1, value.server)
			end
		end
	end

	local has_default_dns_server = "0"
	for index, value in ipairs(dns.servers) do
		if value.domains == nil then
			has_default_dns_server = "1"
			break
		end
	end

	if #dns.servers == 0 or not has_default_server == "0" then
		table.insert(dns.servers, 1, {
			tag = "local",
			address = "localhost"
		})
	end

	if redir_port then
		local inbound = {
			port = tonumber(redir_port),
			protocol = "dokodemo-door",
			settings = {network = "tcp,udp", followRedirect = true},
			streamSettings = {sockopt = {tproxy = "tproxy"}},
			sniffing = {
				enabled = xray_settings.sniffing_override_dest == "1" or node.protocol == "_shunt"
			}
		}
		if inbound.sniffing.enabled == true then
			inbound.sniffing.destOverride = {"http", "tls", "quic"}
			inbound.sniffing.metadataOnly = false
			inbound.sniffing.routeOnly = xray_settings.sniffing_override_dest ~= "1" or nil
			inbound.sniffing.domainsExcluded = xray_settings.sniffing_override_dest == "1" and get_domain_excluded() or nil
		end
		if remote_dns_fake or inner_fakedns == "1" then
			inbound.sniffing.enabled = true
			if not inbound.sniffing.destOverride then
				inbound.sniffing.destOverride = {"fakedns"}
				inbound.sniffing.metadataOnly = true
			else
				table.insert(inbound.sniffing.destOverride, "fakedns")
				inbound.sniffing.metadataOnly = false
			end
		end

		local tcp_inbound = api.clone(inbound)
		tcp_inbound.tag = "tcp_redir"
		tcp_inbound.settings.network = "tcp"
		tcp_inbound.streamSettings.sockopt.tproxy = tcp_proxy_way
		table.insert(inbounds, tcp_inbound)

		local udp_inbound = api.clone(inbound)
		udp_inbound.tag = "udp_redir"
		udp_inbound.settings.network = "udp"
		table.insert(inbounds, udp_inbound)
	end
	
	if inbounds or outbounds then
		local config = {
			env = (function()
				local asset_location = uci:get(appname, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
				return { XRAY_LOCATION_ASSET = asset_location }
			end)(),
			log = {
				--access = string.format("/tmp/etc/%s/%s_access.log", appname, "global"),
				--error = string.format("/tmp/etc/%s/%s_error.log", appname, "global"),
				--dnsLog = true,
				loglevel = loglevel
			},
			dns = dns,
			fakedns = fakedns,
			inbounds = inbounds,
			outbounds = outbounds,
			observatory = (not burstObservatory) and observatory or nil,
			burstObservatory = burstObservatory,
			routing = routing,
			policy = {
				levels = {
					[0] = {
						-- handshake = 4,
						-- connIdle = 300,
						-- uplinkOnly = 2,
						-- downlinkOnly = 5,
						bufferSize = xray_settings.buffer_size and tonumber(xray_settings.buffer_size) or nil,
						statsUserUplink = false,
						statsUserDownlink = false
					}
				},
				-- system = {
				--     statsInboundUplink = false,
				--     statsInboundDownlink = false
				-- }
			},
			version = {
				min = xray_min_version
			}
		}

		local direct_outbound = {
			protocol = "freedom",
			tag = "direct",
			settings = {
				domainStrategy = (direct_dns_query_strategy and direct_dns_query_strategy ~= "") and direct_dns_query_strategy or "UseIP",
				finalRules = {{ action = "allow" }}
			},
			streamSettings = {
				sockopt = {
					mark = 255
				}
			}
		}
		if COMMON.default_outbound_tag == "direct" then
			table.insert(outbounds, 1, direct_outbound)
		else
			table.insert(outbounds, direct_outbound)
		end

		local blackhole_outbound = {
			protocol = "blackhole",
			tag = "blackhole"
		}
		if COMMON.default_outbound_tag == "blackhole" then
			table.insert(outbounds, 1, blackhole_outbound)
		else
			table.insert(outbounds, blackhole_outbound)
		end

		for index, value in ipairs(config.outbounds) do
			local s = value.settings
			if not value["_flag_proxy_tag"] and value["_id"] and s and not no_run and
			((s.vnext and s.vnext[1] and s.vnext[1].address and s.vnext[1].port) or 
			(s.servers and s.servers[1] and s.servers[1].address and s.servers[1].port) or
			(s.peers and s.peers[1] and s.peers[1].endpoint) or
			(s.address and s.port)) then
				sys.call(string.format("echo '%s' >> %s", value["_id"], api.TMP_PATH .. "/direct_node_list"))
			end
			for k, v in pairs(config.outbounds[index]) do
				if k:find("_") == 1 then
					config.outbounds[index][k] = nil
				end
			end
		end
		return jsonc.stringify(config, 1)
	end
end

function gen_proto_config(var)
	local local_socks_address = var["local_socks_address"] or "0.0.0.0"
	local local_socks_port = var["local_socks_port"]
	local local_socks_username = var["local_socks_username"]
	local local_socks_password = var["local_socks_password"]
	local local_http_address = var["local_http_address"] or "0.0.0.0"
	local local_http_port = var["local_http_port"]
	local local_http_username = var["local_http_username"]
	local local_http_password = var["local_http_password"]
	local server_proto = var["server_proto"]
	local server_address = var["server_address"]
	local server_port = var["server_port"]
	local server_username = var["server_username"]
	local server_password = var["server_password"]
	
	local inbounds = {}
	local outbounds = {}
	local routing = nil

	if local_socks_address and local_socks_port then
		local inbound = {
			listen = local_socks_address,
			port = tonumber(local_socks_port),
			protocol = "socks",
			settings = {
				udp = true,
				auth = "noauth"
			}
		}
		if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
			inbound.settings.auth = "password"
			inbound.settings.users = {
				{
					user = local_socks_username,
					pass = local_socks_password
				}
			}
		end
		table.insert(inbounds, inbound)
	end
	
	if local_http_address and local_http_port then
		local inbound = {
			listen = local_http_address,
			port = tonumber(local_http_port),
			protocol = "http",
			settings = {
				allowTransparent = false
			}
		}
		if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
			inbound.settings.users = {
				{
					user = local_http_username,
					pass = local_http_password
				}
			}
		end
		table.insert(inbounds, inbound)
	end
	
	if server_proto ~= "nil" and server_address ~= "nil" and server_port ~= "nil" then
		local outbound = {
			protocol = server_proto,
			streamSettings = {
				network = "tcp",
				security = "none"
			},
			settings = {
				servers = {
					{
						address = server_address,
						port = tonumber(server_port),
						users = (server_username and server_password) and {
							{
								user = server_username,
								pass = server_password
							}
						} or nil
					}
				}
			}
		}
		if outbound then table.insert(outbounds, outbound) end
	end

	table.insert(outbounds, {
		protocol = "freedom",
		tag = "direct",
		settings = (api.compare_versions(xray_version, ">", "26.4.25")) and { -- Todo: Remove version check
			finalRules = {{ action = "allow" }}
		} or nil,
		sockopt = {mark = 255}
	})
	
	local config = {
		log = {
			loglevel = "warning"
		},
		inbounds = inbounds,
		outbounds = outbounds,
		routing = routing
	}
	return jsonc.stringify(config, 1)
end

function gen_front_dns_config(var)
	local dns_listen_port = var["dns_listen_port"]
	local direct_dns_udp_server = var["direct_dns_udp_server"]
	local direct_dns_udp_port = var["direct_dns_udp_port"]
	local default_dns_udp_server = var["default_dns_udp_server"]
	local default_dns_udp_port = var["default_dns_udp_port"]

	local queryStrategy = "UseIP"
	local dns = {
		tag = "dns-global-direct",
		disableCache = false,
		disableFallback = true,
		disableFallbackIfMatch = true,
		queryStrategy = queryStrategy,
		servers = {}
	}
	local inbounds = {}
	local outbounds = {}
	local routing = {
		rules = {}
	}

	table.insert(outbounds, {
		tag = "direct",
		protocol = "freedom",
		settings = {
			domainStrategy = queryStrategy
		},
		streamSettings = {
			sockopt = {
				mark = 255
			}
		}
	})

	if default_dns_udp_server then
		table.insert(dns.servers, {
			tag = "default",
			address = default_dns_udp_server,
			port = tonumber(default_dns_udp_port) or 53,
			queryStrategy = queryStrategy,
		})
	end

	local direct_dns_shunt = uci:get(appname, "@global[0]", "direct_dns_shunt") or ""
	if #direct_dns_shunt > 0 then
		local dns_server = {}
		string.gsub(direct_dns_shunt, '[^' .. "\r\n" .. ']+', function(w)
			if w:find("#") == 1 then return end
			local domain = sys.exec(string.format("echo -n $(echo %s | awk -F ' ' '{print $1}')", w))
			local dns = sys.exec(string.format("echo -n $(echo %s | awk -F ' ' '{print $2}')", w))
			if domain ~= "" and dns ~= "" then
				local new_dns_server = parseDNS(dns)
				if new_dns_server then
					if not dns_server[dns] then
						dns_server[dns] = {}
					end
					dns_server[dns].tag = dns
					dns_server[dns].queryStrategy = queryStrategy
					dns_server[dns].address = new_dns_server.address
					dns_server[dns].port = new_dns_server.port
					dns_server[dns].finalQuery = true
					if not dns_server[dns].domains then
						dns_server[dns].domains = {}
					end
					table.insert(dns_server[dns].domains, domain)
				end
			end
		end)
		for k, v in pairs(dns_server) do
			table.insert(dns.servers, v)
			table.insert(routing.rules, {
				inboundTag = {
					v.tag
				},
				outboundTag = "direct"
			})
		end
	end

	if direct_dns_udp_server then
		local node_domain = {}
		local nodes_domain_text = sys.exec('uci show passwall2 | grep ".address=" | cut -d "\'" -f 2 | grep "[a-zA-Z]$" | sort -u')
		string.gsub(nodes_domain_text, '[^' .. "\r\n" .. ']+', function(w)
			w = (w or ""):lower()
			table.insert(node_domain, "full:" .. w)
		end)
		if #node_domain > 0 then
			table.insert(dns.servers, {
				tag = "dns-in-vpslist",
				address = direct_dns_udp_server,
				port = tonumber(direct_dns_udp_port) or 53,
				queryStrategy = queryStrategy,
				domains = node_domain,
				finalQuery = true,
				disableCache = false,
				serveStale = true,
			})
		end
	end

	table.insert(inbounds, {
		tag = "dns-in",
		listen = "127.0.0.1",
		port = tonumber(dns_listen_port),
		protocol = "dokodemo-door",
		settings = {
			address = "0.0.0.0",
			network = "tcp,udp"
		}
	})

	table.insert(outbounds, {
		tag = "dns-out",
		protocol = "dns",
		proxySettings = {
			tag = "direct"
		},
		settings = {
			address = direct_dns_udp_server,
			port = tonumber(direct_dns_udp_port) or 53,
			network = "udp",
			nonIPQuery = "skip",
			blockTypes = {
				65
			}
		}
	})

	table.insert(routing.rules, {
		inboundTag = {
			"dns-in"
		},
		outboundTag = "dns-out"
	})

	local config = {
		log = {
			dnsLog = true,
			loglevel = "debug"
		},
		dns = dns,
		inbounds = inbounds,
		outbounds = outbounds,
		routing = routing
	}
	return jsonc.stringify(config, 1)
end

_G.gen_config = gen_config
_G.gen_front_dns_config = gen_front_dns_config
_G.gen_proto_config = gen_proto_config

if arg[1] then
	local func =_G[arg[1]]
	if func then
		local var = nil
		if arg[2] then
			var = jsonc.parse(arg[2])
		end
		print(func(var))
	end
end
