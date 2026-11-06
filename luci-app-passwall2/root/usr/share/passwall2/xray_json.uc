import { readfile, writefile, popen, unlink, rmdir, chmod } from 'fs';

function shellquote(value) {
	return "'" + replace(value, /'/g, "'\\''") + "'";
}

function validate(profile) {
	if (type(profile) != 'object' || type(profile.outbounds) != 'array' || !length(profile.outbounds) || type(profile.inbounds) != 'array')
		die('Expected a complete Xray client configuration');
	if (profile.api || profile.metrics || profile.reverse || profile.services)
		die('Server and control listeners are not supported in client profiles');
	let socks = 0;
	let http = 0;
	for (let inbound in profile.inbounds) {
		if (inbound.protocol != 'socks' && inbound.protocol != 'http')
			die('Client profiles must use SOCKS or HTTP inbounds');
		if (inbound.protocol == 'socks')
			socks++;
		else
			http++;
	}
	if (socks != 1)
		die('Expected exactly one SOCKS inbound');
	if (http > 1)
		die('At most one HTTP inbound is supported');
}

function generate(profile, args) {
	validate(profile);
	let port = int(args.local_socks_port);
	if (port < 1 || port > 65535)
		die('A valid local SOCKS port is required');
	let inbounds = [];
	let socks_tag;
	let http = false;
	for (let inbound in profile.inbounds) {
		if (inbound.protocol == 'socks') {
			socks_tag = inbound.tag;
			inbound.listen = args.local_socks_address || '127.0.0.1';
			inbound.port = port;
			inbound.settings = { auth: 'noauth', udp: true };
			if (args.local_socks_username && args.local_socks_password) {
				inbound.settings.auth = 'password';
				inbound.settings.accounts = [{ user: args.local_socks_username, pass: args.local_socks_password }];
			}
			push(inbounds, inbound);
		}
		else if (args.local_http_port) {
			http = true;
			let http_port = int(args.local_http_port);
			if (http_port < 1 || http_port > 65535 || http_port == port)
				die('A valid distinct HTTP port is required');
			inbound.listen = args.local_http_address || '127.0.0.1';
			inbound.port = http_port;
			inbound.settings = {};
			if (args.local_http_username && args.local_http_password)
				inbound.settings.accounts = [{ user: args.local_http_username, pass: args.local_http_password }];
			push(inbounds, inbound);
		}
	}
	if (args.local_http_port && !http) {
		let http_port = int(args.local_http_port);
		if (http_port < 1 || http_port > 65535 || http_port == port)
			die('A valid distinct HTTP port is required');
		let tag = (socks_tag || 'passwall2') + '-http';
		let inbound = { tag, protocol: 'http', listen: args.local_http_address || '127.0.0.1', port: http_port, settings: {} };
		if (args.local_http_username && args.local_http_password)
			inbound.settings.accounts = [{ user: args.local_http_username, pass: args.local_http_password }];
		push(inbounds, inbound);
		for (let rule in profile.routing?.rules || []) {
			if (socks_tag && type(rule.inboundTag) == 'array' && index(rule.inboundTag, socks_tag) >= 0)
				push(rule.inboundTag, tag);
		}
	}
	profile.inbounds = inbounds;
	profile.log = { loglevel: args.loglevel == 'warn' ? 'warning' : (args.loglevel || 'warning') };
	profile.env = { XRAY_LOCATION_ASSET: args.asset_location || '/usr/share/v2ray/' };
	for (let outbound in profile.outbounds) {
		if (!outbound.streamSettings)
			outbound.streamSettings = {};
		if (!outbound.streamSettings.sockopt)
			outbound.streamSettings.sockopt = {};
		outbound.streamSettings.sockopt.mark = (outbound.streamSettings.sockopt.mark || 0) | 255;
	}
	return profile;
}

let temporary;
let temporary_dir;
let phase = 'reading input';
try {
	let raw = readfile(ARGV[1]);
	if (!raw || length(raw) > 2097152)
		die('Configuration is empty or exceeds 2 MiB');
	let source = json(raw);
	if (ARGV[0] == 'generate') {
		print(sprintf('%J', generate(source, json(ARGV[2]))));
	}
	else if (ARGV[0] == 'parse') {
		phase = 'validating the profile list';
		let profiles = type(source) == 'array' ? source : [source];
		if (!length(profiles) || length(profiles) > 100)
			die('Expected between 1 and 100 client profiles');
		let names = {};
		let nodes = [];
		phase = 'creating the private validation file';
		let process = popen('mktemp -d /tmp/passwall2-json-check.XXXXXX', 'r');
		let directory = trim(process.read('all'));
		process.close();
		if (!match(directory, /^\/tmp\/passwall2-json-check\.[A-Za-z0-9]+$/))
			die('Unable to create a private validation file');
		temporary_dir = directory;
		temporary = directory + '/config.json';
		for (let profile in profiles) {
			phase = 'validating profile ' + length(nodes);
			validate(profile);
			let name = profile.remarks || profile.name;
			if (type(name) != 'string' || !length(trim(name)) || names[name])
				die('Each profile must have a unique, nonempty name');
			names[name] = true;
			let preserved = sprintf('%J', profile);
			phase = 'generating profile ' + length(nodes);
			let candidate = generate(json(preserved), { local_socks_port: 10808, asset_location: ARGV[2] });
			if (!writefile(temporary, sprintf('%J', candidate)))
				die('Unable to write the private validation file');
			chmod(temporary, 384);
			phase = 'checking profile ' + length(nodes);
			let assets = ARGV[2] || '/usr/share/v2ray/';
			let core = ARGV[3] || '/usr/bin/xray';
			if (system('XRAY_LOCATION_ASSET=' + shellquote(assets) + ' ' + shellquote(core) + ' run -test -format json -config ' + shellquote(temporary) + ' >/dev/null 2>&1') != 0)
				die('Xray rejected a profile; the subscription was not imported');
			push(nodes, { type: 'Xray', protocol: '_custom', remarks: name, custom_config: preserved });
		}
		unlink(temporary);
		temporary = null;
		rmdir(temporary_dir);
		temporary_dir = null;
		print(sprintf('%J', nodes));
	}
	else {
		die('Unknown Xray JSON operation');
	}
}
catch (error) {
	if (temporary)
		unlink(temporary);
	if (temporary_dir)
		rmdir(temporary_dir);
	warn('Invalid Xray JSON client configuration while ' + phase + '\n');
	exit(1);
}
