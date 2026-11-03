/*
 * Click-to-sort headers and a per-group filter bar for the node list.
 *
 * Sort reorders rows inside one group table and calls set_order(), the same
 * path as drag-and-drop and To Top. Nothing is written until Save & Apply.
 *
 * A filter only toggles the pw-row-hidden class. Rows stay in the form, so
 * Save & Apply still posts every node and the full group.order value.
 *
 * Translated strings are read from #pw2-nodesort-i18n (the node list template).
 * The template calls init() once, then enhanceAll() after loadNodeList()
 * has built the group tables.
 *
 * auto_detection_time is a top-level let in the template, not a window
 * property. It is read by name so rows are not moved while automatic Ping
 * or TCPing is still writing results by row position.
 */
(function () {
	'use strict';

	var COLUMNS = {
		'pw-remark': 'name',
		'pw-ping': 'ping',
		'pw-tcping': 'tcping',
		'pw-urltest': 'urltest'
	};
	/* sub controls drawn inside the Remarks header: [sort key, label key or symbol, title key] */
	var NAME_EXTRA = [
		['type', 'type', 'typeHint'],
		['addr', 'addr', 'addrHint'],
		['orig', '\u21BA', 'origHint']
	];

	var state = {
		app: 'passwall2',
		root: null,
		text: {},
		bound: false
	};
	var searchTimer = null;

	function T(key) {
		var value = state.text[key];
		return (value == null || value === '') ? key : value;
	}

	function readText(box) {
		var text = {};
		var spans = box.querySelectorAll('[data-k]');
		for (var i = 0; i < spans.length; i++)
			text[spans[i].getAttribute('data-k')] = spans[i].textContent;
		return text;
	}

	var collator = null;
	function prepareCollator() {
		var lang = document.documentElement.lang || (navigator.language || '');
		try {
			collator = (window.Intl && Intl.Collator) ? new Intl.Collator(lang || undefined, { numeric: true, sensitivity: 'base' }) : null;
		} catch (e) {
			collator = null;
		}
	}

	function cmpText(a, b) {
		if (collator)
			return collator.compare(a, b);
		return a < b ? -1 : (a > b ? 1 : 0);
	}

	/* "123 ms", "12.5 ms", "1.2 s" -> milliseconds. Timeout, Error, ---, Test stay null. */
	function parseLatency(text) {
		var t = String(text || '').replace(/\s+/g, ' ').trim();
		var m = /^(\d+(?:[.,]\d+)?)\s*(ms|s)?$/i.exec(t);
		if (!m)
			return null;
		var v = parseFloat(m[1].replace(',', '.'));
		if (isNaN(v))
			return null;
		if (m[2] && /^s$/i.test(m[2]))
			v *= 1000;
		return v;
	}

	function hiddenVal(id, opt) {
		var el = document.getElementById('cbid.' + state.app + '.' + id + '.' + opt);
		return el && el.value != null ? String(el.value).trim() : '';
	}

	function cellsOf(tr) {
		var out = [];
		for (var i = 0; i < tr.children.length; i++) {
			var tag = tr.children[i].tagName;
			if (tag === 'TD' || tag === 'TH')
				out.push(tr.children[i]);
		}
		return out;
	}

	var wordSplit;
	try {
		wordSplit = new RegExp('[^\\p{L}\\p{N}]+', 'u');
	} catch (e) {
		wordSplit = /[\s.,;:!?|\/\\()\[\]{}<>"'`~@#$%^&*=+_-]+/;
	}

	function wordsOf(text) {
		var seen = {};
		var out = [];
		var parts = String(text || '').split(wordSplit);
		for (var i = 0; i < parts.length; i++) {
			var w = parts[i];
			if (w.length < 2 || /^\d+$/.test(w))
				continue;
			var k = w.toLowerCase();
			if (!seen[k]) {
				seen[k] = 1;
				out.push(w);
			}
		}
		return out;
	}

	function infoOf(table) {
		var prefix = 'cbi-' + state.app + '-nodes-';
		var id = table && table.id ? table.id : '';
		if (id.indexOf(prefix) !== 0 || id.slice(-6) !== '-table')
			return null;
		return { group: id.slice(prefix.length, -6) };
	}

	function rowId(tr) {
		var prefix = 'cbi-' + state.app + '-';
		return tr.id.indexOf(prefix) === 0 ? tr.id.substring(prefix.length) : tr.id;
	}

	function bodyOf(table) {
		return table.querySelector('tbody') || table;
	}

	function dataRows(table) {
		var body = bodyOf(table);
		var out = [];
		for (var i = 0; i < body.children.length; i++) {
			var tr = body.children[i];
			if (tr.tagName === 'TR' && tr.classList.contains('cbi-section-table-row') && !tr.classList.contains('placeholder'))
				out.push(tr);
		}
		return out;
	}

	function colIndexMap(table) {
		var rows = dataRows(table);
		var map = {};
		if (!rows.length)
			return map;
		var cells = cellsOf(rows[0]);
		for (var i = 0; i < cells.length; i++) {
			for (var cls in COLUMNS) {
				if (cells[i].classList.contains(cls))
					map[COLUMNS[cls]] = i;
			}
		}
		return map;
	}

	function typeOf(tr, cols) {
		var cell = cellsOf(tr)[cols.name];
		var text = cell ? cell.textContent.replace(/\s+/g, ' ').trim() : '';
		var i = text.indexOf('\uFF1A');
		if (i < 0)
			i = text.indexOf(':');
		return (i < 0 ? '' : text.slice(0, i)).replace(/\s+Realm$/, '').trim();
	}

	function sortKey(tr, key, cols) {
		var id = rowId(tr);
		var cell;
		if (key === 'name')
			return hiddenVal(id, 'remarks') || ((cellsOf(tr)[cols.name] || {}).textContent || '').trim();
		if (key === 'type')
			return typeOf(tr, cols) + '\u0000' + hiddenVal(id, 'remarks');
		if (key === 'addr') {
			var address = hiddenVal(id, 'address');
			if (!address)
				return null;
			return address + '\u0000' + ('00000' + hiddenVal(id, 'port')).slice(-5);
		}
		cell = cellsOf(tr)[cols[key]];
		return cell ? parseLatency(cell.textContent) : null;
	}

	function detectionMode() {
		try {
			if (typeof auto_detection_time === 'undefined')
				return null;
			return auto_detection_time;
		} catch (e) {
			return null;
		}
	}

	/* { inflight: requests still running, left: cells still waiting for a result } */
	function pingBusy() {
		var mode = detectionMode();
		var inflight = 0;
		var left = 0;
		if (mode !== 'icmp' && mode !== 'tcping')
			return { inflight: 0, left: 0 };
		var list = window.ajax && window.ajax.list;
		if (list && list.length) {
			for (var i = 0; i < list.length; i++) {
				if (list[i].readyState > 0 && list[i].readyState < 4)
					inflight++;
			}
		}
		if (!state.root)
			return { inflight: inflight, left: 0 };
		var spans = state.root.getElementsByClassName(mode === 'tcping' ? 'tcping_value' : 'ping_value');
		for (var s = 0; s < spans.length; s++) {
			var id = spans[s].getAttribute('cbiid');
			if (!id || spans[s].textContent.trim() !== '---')
				continue;
			var full = null;
			if (typeof window.get_address_full === 'function')
				full = window.get_address_full(id);
			if (!full)
				full = { address: hiddenVal(id, 'address'), port: hiddenVal(id, 'port') };
			if (full.address && (mode === 'icmp' || full.port))
				left++;
		}
		return { inflight: inflight, left: left };
	}

	function note(table, text) {
		var id = 'pw-note-' + table.id;
		var el = document.getElementById(id);
		if (!text) {
			if (el && el.parentNode)
				el.parentNode.removeChild(el);
			return;
		}
		if (!el) {
			el = document.createElement('div');
			el.id = id;
			el.className = 'pw-sort-note';
			table.parentNode.insertBefore(el, table);
		}
		el.textContent = text;
	}

	function setIndicator(table, th, sub, key, dir) {
		var arrows = table.querySelectorAll('.pw-sort-arrow');
		var subs = table.querySelectorAll('.pw-sort-sub');
		var headers = table.querySelectorAll('th[data-pw-sort]');
		var i;
		for (i = 0; i < arrows.length; i++)
			arrows[i].textContent = '';
		for (i = 0; i < subs.length; i++)
			subs[i].classList.remove('pw-sort-active');
		for (i = 0; i < headers.length; i++) {
			if (headers[i] !== th) {
				delete headers[i].dataset.pwDir;
				delete headers[i].dataset.pwKey;
			}
		}
		var arrow = th.querySelector('.pw-sort-arrow');
		if (arrow && key !== 'orig' && !sub)
			arrow.textContent = dir === 'desc' ? '\u25BC' : '\u25B2';
		if (sub && key !== 'orig')
			sub.classList.add('pw-sort-active');
	}

	function applyOrder(table, info, rows) {
		var body = bodyOf(table);
		var frag = document.createDocumentFragment();
		for (var i = 0; i < rows.length; i++) {
			rows[i].classList.remove('cbi-rowstyle-1', 'cbi-rowstyle-2');
			rows[i].classList.add('cbi-rowstyle-' + (i % 2 + 1));
			frag.appendChild(rows[i]);
		}
		body.appendChild(frag);
		if (typeof window.set_order === 'function')
			window.set_order(info.group);
	}

	function doSort(table, th, sub, key) {
		var info = infoOf(table);
		var rows = dataRows(table);
		var dir = 'asc';
		if (!info || rows.length < 2)
			return;
		if (key === 'orig') {
			var pos = {};
			var orig = table.__pwOrig || [];
			for (var n = 0; n < orig.length; n++)
				pos[orig[n]] = n;
			rows.sort(function (a, b) {
				var pa = pos[rowId(a)];
				var pb = pos[rowId(b)];
				return (pa == null ? 1e9 : pa) - (pb == null ? 1e9 : pb);
			});
			delete th.dataset.pwDir;
			delete th.dataset.pwKey;
		} else {
			dir = (th.dataset.pwKey === key && th.dataset.pwDir === 'asc') ? 'desc' : 'asc';
			th.dataset.pwKey = key;
			th.dataset.pwDir = dir;
			var cols = colIndexMap(table);
			var sign = dir === 'desc' ? -1 : 1;
			var list = [];
			for (var i = 0; i < rows.length; i++)
				list.push({ tr: rows[i], i: i, k: sortKey(rows[i], key, cols) });
			list.sort(function (a, b) {
				var emptyA = (a.k === null || a.k === '');
				var emptyB = (b.k === null || b.k === '');
				if (emptyA || emptyB)
					return emptyA === emptyB ? a.i - b.i : (emptyA ? 1 : -1);
				var cmp = (typeof a.k === 'number' && typeof b.k === 'number') ? a.k - b.k : cmpText(String(a.k), String(b.k));
				return cmp !== 0 ? sign * cmp : a.i - b.i;
			});
			rows = [];
			for (var j = 0; j < list.length; j++)
				rows.push(list[j].tr);
		}
		applyOrder(table, info, rows);
		refreshFilter(table);
		setIndicator(table, th, sub, key, dir);
		note(table, key === 'orig' ? T('restored') : T('changed'));
	}

	function requestSort(table, th, sub, key) {
		if (table.__pwWait) {
			clearInterval(table.__pwWait);
			table.__pwWait = null;
		}
		var st = pingBusy();
		if (!st.inflight && !st.left) {
			doSort(table, th, sub, key);
			return;
		}
		var started = Date.now();
		var idle = 0;
		note(table, T('wait').replace('%d', st.left || st.inflight));
		table.__pwWait = setInterval(function () {
			st = pingBusy();
			idle = st.inflight ? 0 : idle + 1;
			if ((!st.inflight && !st.left) || idle >= 6) {
				clearInterval(table.__pwWait);
				table.__pwWait = null;
				if (document.body.contains(table))
					doSort(table, th, sub, key);
				return;
			}
			if (Date.now() - started > 120000) {
				clearInterval(table.__pwWait);
				table.__pwWait = null;
				note(table, T('waitFail'));
				return;
			}
			note(table, T('wait').replace('%d', st.left || st.inflight));
		}, 500);
	}

	function enhance(table) {
		var info = infoOf(table);
		if (!info || table.__pwReady)
			return;
		var titles = table.querySelector('tr.cbi-section-table-titles');
		var rows = dataRows(table);
		if (!titles || !rows.length)
			return;
		var cols = colIndexMap(table);
		var headers = cellsOf(titles);
		table.__pwReady = true;
		table.__pwOrig = [];
		for (var r = 0; r < rows.length; r++)
			table.__pwOrig.push(rowId(rows[r]));
		for (var key in cols) {
			if (!Object.prototype.hasOwnProperty.call(cols, key))
				continue;
			var th = headers[cols[key]];
			if (!th || th.classList.contains('cbi-section-actions'))
				continue;
			th.setAttribute('data-pw-sort', key);
			th.title = T('hint');
			var arrow = document.createElement('span');
			arrow.className = 'pw-sort-arrow';
			th.appendChild(arrow);
			if (key !== 'name')
				continue;
			for (var s = 0; s < NAME_EXTRA.length; s++) {
				var spec = NAME_EXTRA[s];
				var sp = document.createElement('span');
				sp.className = 'pw-sort-sub';
				sp.setAttribute('data-pw-sort', spec[0]);
				sp.textContent = T(spec[1]);
				sp.title = T(spec[2]);
				th.appendChild(sp);
			}
		}
	}

	function rowVisible(el) {
		var row = el && el.closest ? el.closest('tr') : null;
		return !row || !row.classList.contains('pw-row-hidden');
	}

	function filterDefs(rows, cols) {
		return [
			{
				key: 'type',
				label: T('type'),
				multi: false,
				get: function (tr) { return typeOf(tr, cols); }
			},
			{
				key: 'word',
				label: T('fWord'),
				multi: true,
				minCount: 2,
				max: 40,
				get: function (tr) { return wordsOf(hiddenVal(rowId(tr), 'remarks')); }
			}
		];
	}

	function searchText(tr, cols) {
		var id = rowId(tr);
		return [
			typeOf(tr, cols),
			hiddenVal(id, 'remarks'),
			hiddenVal(id, 'address') + ':' + hiddenVal(id, 'port')
		].join(' ');
	}

	function collect(table) {
		var rows = dataRows(table);
		var cols = colIndexMap(table);
		var defs = rows.length >= 2 ? filterDefs(rows, cols) : [];
		var shown = [];
		for (var d = 0; d < defs.length; d++) {
			var def = defs[d];
			var counts = {};
			var labels = {};
			var vals = [];
			for (var r = 0; r < rows.length; r++) {
				var raw = def.get(rows[r]);
				var list = def.multi ? (raw || []) : [raw == null ? '' : String(raw)];
				var keys = [];
				for (var n = 0; n < list.length; n++) {
					var item = list[n];
					var k = def.multi ? String(item).toLowerCase() : String(item);
					counts[k] = (counts[k] || 0) + 1;
					if (!labels[k])
						labels[k] = {};
					labels[k][item] = (labels[k][item] || 0) + 1;
					keys.push(k);
				}
				vals.push(keys);
			}
			var opts = [];
			for (var k in counts) {
				if (!Object.prototype.hasOwnProperty.call(counts, k))
					continue;
				if (def.multi && (counts[k] < (def.minCount || 1) || counts[k] >= rows.length))
					continue;
				var best = '';
				var bestN = -1;
				for (var label in labels[k]) {
					if (labels[k][label] > bestN) {
						bestN = labels[k][label];
						best = label;
					}
				}
				opts.push({ v: k, label: best === '' ? T('empty') : best, n: counts[k] });
			}
			opts.sort(function (a, b) {
				if (def.multi && a.n !== b.n)
					return b.n - a.n;
				return cmpText(a.label, b.label);
			});
			if (def.max && opts.length > def.max)
				opts = opts.slice(0, def.max);
			var enough = def.multi ? opts.length >= 1 : opts.length >= 2;
			if (!enough)
				continue;
			def.vals = vals;
			def.opts = opts;
			shown.push(def);
		}
		var search = rows.length >= 2;
		var sig = String(rows.length) + (search ? 's' : '');
		for (var i = 0; i < shown.length; i++) {
			sig += '|' + shown[i].key + '=';
			for (var o = 0; o < shown[i].opts.length; o++)
				sig += shown[i].opts[o].v + ':' + shown[i].opts[o].n + ',';
		}
		return { rows: rows, cols: cols, defs: shown, search: search, sig: sig };
	}

	function barId(table) {
		return 'pw-filter-' + table.id;
	}

	function buildBar(table, collected) {
		var st = table.__pwF || (table.__pwF = { sel: {}, q: '' });
		var id = barId(table);
		var bar = document.getElementById(id);
		if (!bar) {
			bar = document.createElement('div');
			bar.id = id;
			bar.className = 'pw-filter';
			bar.title = T('filterHint');
			table.parentNode.insertBefore(bar, table);
			bar.__pwTable = table;
		}
		while (bar.firstChild)
			bar.removeChild(bar.firstChild);
		var head = document.createElement('span');
		head.textContent = T('filter');
		bar.appendChild(head);
		var keep = {};
		for (var d = 0; d < collected.defs.length; d++) {
			var def = collected.defs[d];
			var lab = document.createElement('label');
			var sel = document.createElement('select');
			lab.appendChild(document.createTextNode(def.label));
			sel.className = 'cbi-input-select';
			sel.setAttribute('data-pw-filter', def.key);
			var all = document.createElement('option');
			all.value = '';
			all.textContent = T('all') + ' (' + collected.rows.length + ')';
			sel.appendChild(all);
			for (var o = 0; o < def.opts.length; o++) {
				var op = document.createElement('option');
				op.value = 'v:' + def.opts[o].v;
				op.textContent = def.opts[o].label + ' (' + def.opts[o].n + ')';
				sel.appendChild(op);
			}
			var cur = st.sel[def.key] || '';
			var known = false;
			if (cur) {
				for (var c = 0; c < def.opts.length; c++) {
					if (('v:' + def.opts[c].v) === cur) {
						known = true;
						break;
					}
				}
			}
			if (!known)
				cur = '';
			sel.value = cur;
			if (cur)
				keep[def.key] = cur;
			lab.appendChild(sel);
			bar.appendChild(lab);
		}
		st.sel = keep;
		if (collected.search) {
			var input = document.createElement('input');
			input.type = 'search';
			input.className = 'cbi-input-text';
			input.placeholder = T('search');
			input.title = T('searchHint');
			input.autocomplete = 'off';
			input.setAttribute('data-pw-search', '1');
			input.value = st.q;
			bar.appendChild(input);
		} else {
			st.q = '';
		}
		var count = document.createElement('span');
		count.className = 'pw-filter-count';
		bar.appendChild(count);
		var reset = document.createElement('button');
		reset.type = 'button';
		reset.className = 'btn cbi-button';
		reset.setAttribute('data-pw-reset', '1');
		reset.textContent = T('reset');
		reset.title = T('resetHint');
		bar.appendChild(reset);
		return bar;
	}

	function listHas(list, value) {
		for (var i = 0; i < list.length; i++) {
			if (list[i] === value)
				return true;
		}
		return false;
	}

	function applyFilter(table, collected, bar) {
		var st = table.__pwF || { sel: {}, q: '' };
		var q = String(st.q || '').toLowerCase().trim();
		var active = !!q;
		var shown = 0;
		var unchecked = false;
		var d;
		for (d = 0; d < collected.defs.length; d++) {
			if (st.sel[collected.defs[d].key])
				active = true;
		}
		for (var i = 0; i < collected.rows.length; i++) {
			var tr = collected.rows[i];
			var ok = true;
			for (d = 0; d < collected.defs.length; d++) {
				var sel = st.sel[collected.defs[d].key];
				if (ok && sel && !listHas(collected.defs[d].vals[i], sel.slice(2)))
					ok = false;
			}
			if (ok && q && searchText(tr, collected.cols).toLowerCase().indexOf(q) < 0)
				ok = false;
			if (ok !== !tr.classList.contains('pw-row-hidden'))
				tr.classList.toggle('pw-row-hidden', !ok);
			if (ok) {
				shown++;
				var want = 'cbi-rowstyle-' + ((shown - 1) % 2 + 1);
				var other = want === 'cbi-rowstyle-1' ? 'cbi-rowstyle-2' : 'cbi-rowstyle-1';
				if (!tr.classList.contains(want))
					tr.classList.add(want);
				if (tr.classList.contains(other))
					tr.classList.remove(other);
			} else {
				var cb = tr.querySelector('input.nodes_select');
				if (cb && cb.checked) {
					cb.checked = false;
					unchecked = true;
				}
			}
		}
		if (unchecked && typeof window.update_select_state === 'function')
			window.update_select_state();
		var count = bar.querySelector('.pw-filter-count');
		var txt = T('shown').replace('%s', shown).replace('%t', collected.rows.length);
		if (count && count.textContent !== txt)
			count.textContent = txt;
		if (bar.classList.contains('pw-filter-on') !== active)
			bar.classList.toggle('pw-filter-on', active);
	}

	function removeBar(table) {
		var bar = document.getElementById(barId(table));
		if (bar && bar.parentNode)
			bar.parentNode.removeChild(bar);
		var rows = dataRows(table);
		for (var i = 0; i < rows.length; i++) {
			if (rows[i].classList.contains('pw-row-hidden'))
				rows[i].classList.remove('pw-row-hidden');
		}
		table.__pwSig = null;
	}

	function refreshFilter(table) {
		if (!infoOf(table))
			return;
		var collected = collect(table);
		if (!collected.defs.length && !collected.search) {
			if (table.__pwSig)
				removeBar(table);
			return;
		}
		var bar = document.getElementById(barId(table));
		if (!bar || collected.sig !== table.__pwSig) {
			bar = buildBar(table, collected);
			table.__pwSig = collected.sig;
		}
		applyFilter(table, collected, bar);
	}

	function barTable(el) {
		var bar = el && el.closest ? el.closest('.pw-filter') : null;
		return bar && bar.__pwTable ? bar.__pwTable : null;
	}

	function eventTarget(ev) {
		var t = ev.target;
		if (t && t.nodeType !== 1)
			t = t.parentNode;
		return t;
	}

	function bind(root) {
		root.addEventListener('click', function (ev) {
			var t = eventTarget(ev);
			if (t && t.getAttribute && t.getAttribute('data-pw-reset')) {
				var resetTable = barTable(t);
				if (!resetTable)
					return;
				ev.preventDefault();
				resetTable.__pwF = { sel: {}, q: '' };
				resetTable.__pwSig = null;
				refreshFilter(resetTable);
				return;
			}
			var el = t && t.closest ? t.closest('[data-pw-sort]') : null;
			if (!el || !root.contains(el))
				return;
			if (t.closest && t.closest('input, a, button, select'))
				return;
			var th = el.closest('th');
			var table = el.closest('table');
			if (!th || !table || !infoOf(table))
				return;
			ev.preventDefault();
			ev.stopPropagation();
			requestSort(table, th, el === th ? null : el, el.getAttribute('data-pw-sort'));
		});
		root.addEventListener('change', function (ev) {
			var t = eventTarget(ev);
			if (!t || !t.getAttribute || !t.getAttribute('data-pw-filter'))
				return;
			var table = barTable(t);
			if (!table)
				return;
			(table.__pwF = table.__pwF || { sel: {}, q: '' }).sel[t.getAttribute('data-pw-filter')] = t.value;
			refreshFilter(table);
		});
		root.addEventListener('input', function (ev) {
			var t = eventTarget(ev);
			if (!t || !t.getAttribute || !t.getAttribute('data-pw-search'))
				return;
			var table = barTable(t);
			if (!table)
				return;
			clearTimeout(searchTimer);
			searchTimer = setTimeout(function () {
				(table.__pwF = table.__pwF || { sel: {}, q: '' }).q = t.value;
				refreshFilter(table);
			}, 150);
		});
		root.addEventListener('keydown', function (ev) {
			var t = eventTarget(ev);
			if (ev.key === 'Enter' && t && t.getAttribute && t.getAttribute('data-pw-search'))
				ev.preventDefault();
		});
	}

	function init() {
		var box = document.getElementById('pw2-nodesort-i18n');
		var root = document.getElementById('node_list');
		if (!box || !root)
			return;
		state.app = box.getAttribute('data-app') || 'passwall2';
		state.text = readText(box);
		state.root = root;
		prepareCollator();
		if (!state.bound) {
			bind(root);
			state.bound = true;
		}
	}

	function enhanceAll() {
		if (!state.root)
			return;
		var tables = state.root.querySelectorAll('table.cbi-section-table');
		for (var i = 0; i < tables.length; i++) {
			try {
				enhance(tables[i]);
				refreshFilter(tables[i]);
			} catch (e) {
				if (window.console)
					console.warn('passwall2 node list sort:', e);
			}
		}
	}

	window.pw2NodeSort = {
		init: init,
		enhanceAll: enhanceAll,
		rowVisible: rowVisible
	};
})();
