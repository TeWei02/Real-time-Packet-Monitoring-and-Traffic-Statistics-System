/* ---------------------------------------------------------------------------
 * Traffic console – client-side capture dissection and statistics.
 *
 * This is a static build of the Real-time Packet Monitoring project.  It reads
 * a classic libpcap file (or a seeded synthetic stream), dissects Ethernet /
 * IPv4 / TCP / UDP / ICMP / DNS / HTTP, and aggregates the same statistics the
 * Python pipeline produces.  Nothing leaves the browser: capture bytes are
 * never uploaded anywhere.
 *
 * The parsing and aggregation rules below mirror src/parser.py and
 * src/analyzer.py field for field, so the bundled capture can be used to
 * cross-check the two implementations (see docs/data/reference.json).
 * ------------------------------------------------------------------------- */

'use strict';

const RPM = (function () {
  /* ------------------------------------------------------------------ *
   * Constants
   * ------------------------------------------------------------------ */

  const LINKTYPE_ETHERNET = 1;
  const LINKTYPE_RAW = 101;

  // Mirrors PORT_SERVICE_MAP in src/utils.py.
  const PORT_SERVICES = {
    20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL',
    6379: 'Redis', 8080: 'HTTP-alt'
  };

  // Mirrors HTTP_METHODS in src/parser.py.
  const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/'];

  const PROTO_COLOURS = {
    TCP: '#4cc2ff',
    UDP: '#a78bfa',
    DNS: '#4ade80',
    HTTP: '#fbbf24',
    ICMP: '#f472b6',
    OTHER: '#93a4c0'
  };

  /* ------------------------------------------------------------------ *
   * Small helpers
   * ------------------------------------------------------------------ */

  function round2(value) {
    return Math.round((value + Number.EPSILON) * 100) / 100;
  }

  function humanBytes(n) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = n;
    for (let i = 0; i < units.length; i += 1) {
      if (v < 1024) return v.toFixed(1) + ' ' + units[i];
      v /= 1024;
    }
    return v.toFixed(1) + ' PB';
  }

  function localStamp(epochSeconds) {
    const d = new Date(epochSeconds * 1000);
    const p = (x) => String(x).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function mac(frame, off) {
    const parts = [];
    for (let i = 0; i < 6; i += 1) parts.push(frame[off + i].toString(16).padStart(2, '0'));
    return parts.join(':');
  }

  function ipv4(frame, off) {
    return frame[off] + '.' + frame[off + 1] + '.' + frame[off + 2] + '.' + frame[off + 3];
  }

  function u16(frame, off) {
    return ((frame[off] << 8) | frame[off + 1]) >>> 0;
  }

  function portService(port) {
    if (port === null || port === undefined) return '-';
    return Object.prototype.hasOwnProperty.call(PORT_SERVICES, port)
      ? PORT_SERVICES[port] : String(port);
  }

  /* ------------------------------------------------------------------ *
   * pcap reader (classic libpcap; pcapng is out of scope)
   * ------------------------------------------------------------------ */

  function readPcap(buffer) {
    if (buffer.byteLength < 24) throw new Error('file is shorter than a pcap header');
    const dv = new DataView(buffer);
    const magic = dv.getUint32(0, false);
    let little;
    let nanos = false;
    if (magic === 0xa1b2c3d4) little = false;
    else if (magic === 0xd4c3b2a1) little = true;
    else if (magic === 0xa1b23c4d) { little = false; nanos = true; }
    else if (magic === 0x4d3cb2a1) { little = true; nanos = true; }
    else throw new Error('unsupported file magic 0x' + magic.toString(16) +
      ' (classic .pcap is expected; pcapng is not supported)');

    const linktype = dv.getUint32(20, little);
    const packets = [];
    let off = 24;
    let truncated = 0;

    while (off + 16 <= buffer.byteLength) {
      const tsSec = dv.getUint32(off, little);
      const tsFrac = dv.getUint32(off + 4, little);
      const inclLen = dv.getUint32(off + 8, little);
      const origLen = dv.getUint32(off + 12, little);
      off += 16;
      if (inclLen > buffer.byteLength - off) { truncated += 1; break; }
      const frame = new Uint8Array(buffer, off, inclLen);
      off += inclLen;
      packets.push({
        time: tsSec + (nanos ? tsFrac / 1e9 : tsFrac / 1e6),
        frame: frame,
        origLen: origLen
      });
    }

    return { linktype: linktype, packets: packets, truncated: truncated };
  }

  /* ------------------------------------------------------------------ *
   * Dissection
   * ------------------------------------------------------------------ */

  function detectHttp(payloadBytes) {
    for (let i = 0; i < HTTP_METHODS.length; i += 1) {
      const token = HTTP_METHODS[i];
      if (payloadBytes.length < token.length) continue;
      let hit = true;
      for (let j = 0; j < token.length; j += 1) {
        if (payloadBytes[j] !== token.charCodeAt(j)) { hit = false; break; }
      }
      if (!hit) continue;
      let end = 0;
      while (end < payloadBytes.length && end < 200) {
        if (payloadBytes[end] === 13 && payloadBytes[end + 1] === 10) break;
        end += 1;
      }
      let line = '';
      for (let k = 0; k < end && k < 80; k += 1) {
        const c = payloadBytes[k];
        line += (c >= 32 && c < 127) ? String.fromCharCode(c) : '?';
      }
      return line;
    }
    return null;
  }

  function dnsQuestionName(frame, off) {
    if (frame.length < off + 12) return null;
    const qdcount = u16(frame, off + 4);
    if (qdcount < 1) return null;
    let p = off + 12;
    const labels = [];
    let guard = 0;
    while (p < frame.length && guard < 128) {
      guard += 1;
      const len = frame[p];
      if (len === 0) break;
      if ((len & 0xc0) === 0xc0) break;            // compression pointer
      if (len > 63 || p + 1 + len > frame.length) return null;
      let label = '';
      for (let i = 0; i < len; i += 1) {
        const c = frame[p + 1 + i];
        label += (c >= 32 && c < 127) ? String.fromCharCode(c) : '\ufffd';
      }
      labels.push(label);
      p += 1 + len;
    }
    if (!labels.length) return null;
    return labels.join('.').replace(/\.$/, '');
  }

  function tcpFlags(value) {
    let out = '';
    if (value & 0x02) out += 'S';
    if (value & 0x10) out += 'A';
    if (value & 0x01) out += 'F';
    if (value & 0x04) out += 'R';
    if (value & 0x08) out += 'P';
    if (value & 0x20) out += 'U';
    return out;
  }

  function dissect(frame, linktype) {
    const pkt = {
      timestamp: 0,
      length: frame.length,
      src_ip: null, dst_ip: null, ttl: null,
      protocol: 'OTHER', src_port: null, dst_port: null,
      info: '', eth_src: null, eth_dst: null,
      flags: null, dns_query: null, http_method: null
    };

    let off = 0;
    let etherType = 0;

    if (linktype === LINKTYPE_ETHERNET) {
      if (frame.length < 14) return null;
      pkt.eth_dst = mac(frame, 0);
      pkt.eth_src = mac(frame, 6);
      etherType = (frame[12] << 8) | frame[13];
      off = 14;
      let guard = 0;
      while ((etherType === 0x8100 || etherType === 0x88a8) && guard < 4) {
        guard += 1;
        if (frame.length < off + 4) return null;
        etherType = (frame[off + 2] << 8) | frame[off + 3];
        off += 4;
      }
    } else if (linktype === LINKTYPE_RAW) {
      etherType = 0x0800;
    } else {
      return null;
    }

    const isIpv4 = etherType === 0x0800;
    let l4 = -1;

    if (isIpv4 && frame.length >= off + 20) {
      const ihl = (frame[off] & 0x0f) * 4;
      if (ihl >= 20 && frame.length >= off + ihl) {
        const proto = frame[off + 9];
        pkt.ttl = frame[off + 8];
        pkt.src_ip = ipv4(frame, off + 12);
        pkt.dst_ip = ipv4(frame, off + 16);
        l4 = off + ihl;

        if (proto === 6 && frame.length >= l4 + 20) {
          pkt.protocol = 'TCP';
          pkt.src_port = u16(frame, l4);
          pkt.dst_port = u16(frame, l4 + 2);
          pkt.flags = tcpFlags(frame[l4 + 13]);
          const dataOffset = ((frame[l4 + 12] >> 4) & 0x0f) * 4;
          const payloadAt = l4 + Math.max(dataOffset, 20);
          if (payloadAt <= frame.length) {
            const http = detectHttp(frame.subarray(payloadAt, Math.min(frame.length, payloadAt + 96)));
            if (http) {
              pkt.http_method = http;
              pkt.protocol = 'HTTP';
            }
          }
        } else if (proto === 17 && frame.length >= l4 + 8) {
          pkt.protocol = 'UDP';
          pkt.src_port = u16(frame, l4);
          pkt.dst_port = u16(frame, l4 + 2);
          // A port-53 datagram is only labelled DNS when it actually carries a
          // DNS message. Scapy (the Python side) binds the DNS layer only for a
          // non-empty payload, so datagrams whose UDP payload is shorter than the
          // 12-byte DNS header stay labelled UDP in both implementations.
          const payloadLen = Math.max(0, Math.min(u16(frame, l4 + 4) - 8, frame.length - (l4 + 8)));
          if ((pkt.src_port === 53 || pkt.dst_port === 53) && payloadLen >= 12) {
            pkt.protocol = 'DNS';
            pkt.dns_query = dnsQuestionName(frame, l4 + 8);
          }
        } else if (proto === 1) {
          pkt.protocol = 'ICMP';
        }
      }
    }

    // Summary line, following src/parser.py.
    if (pkt.protocol === 'DNS' && pkt.dns_query) {
      pkt.info = 'DNS Query: ' + pkt.dns_query;
    } else if (pkt.protocol === 'HTTP' && pkt.http_method) {
      pkt.info = 'HTTP: ' + pkt.http_method;
    } else if (pkt.protocol === 'TCP' || pkt.protocol === 'UDP') {
      pkt.info = pkt.protocol + ' ' + pkt.src_ip + ':' + pkt.src_port +
        ' \u2192 ' + pkt.dst_ip + ':' + pkt.dst_port;
    } else if (pkt.protocol === 'ICMP') {
      pkt.info = 'ICMP ' + pkt.src_ip + ' \u2192 ' + pkt.dst_ip;
    } else {
      pkt.info = pkt.protocol + ' len=' + pkt.length;
    }

    return pkt;
  }

  function dissectCapture(parsed) {
    const records = [];
    let unparsed = 0;
    for (let i = 0; i < parsed.packets.length; i += 1) {
      const raw = parsed.packets[i];
      const pkt = dissect(raw.frame, parsed.linktype);
      if (!pkt) { unparsed += 1; continue; }
      pkt.timestamp = raw.time;
      records.push(pkt);
    }
    return { records: records, unparsed: unparsed };
  }

  /* ------------------------------------------------------------------ *
   * Aggregation (mirrors src/analyzer.py)
   * ------------------------------------------------------------------ */

  function valueCounts(values, head) {
    const counts = new Map();
    const firstSeen = new Map();
    values.forEach(function (v, i) {
      if (v === null || v === undefined || v === '') return;
      counts.set(v, (counts.get(v) || 0) + 1);
      if (!firstSeen.has(v)) firstSeen.set(v, i);
    });
    const list = Array.from(counts.entries());
    list.sort(function (a, b) {
      if (b[1] !== a[1]) return b[1] - a[1];
      // Equal counts keep first-appearance order, matching pandas value_counts.
      return firstSeen.get(a[0]) - firstSeen.get(b[0]);
    });
    return head ? list.slice(0, head) : list;
  }

  function analyze(records) {
    if (!records.length) {
      return {
        total_packets: 0, total_bytes: 0, total_bytes_human: '0 B', avg_pkt_size: 0,
        duration_sec: 0, pps: 0, peak_pps: 0, peak_time: 'N/A',
        proto_counts: {}, top_src_ips: [], top_dst_ips: [],
        top_src_ports: [], top_dst_ports: [], top_dns: [], time_series: []
      };
    }

    let totalBytes = 0;
    let tMin = Infinity;
    let tMax = -Infinity;
    const proto = new Map();
    const perSecond = new Map();

    records.forEach(function (p) {
      totalBytes += p.length;
      if (p.timestamp < tMin) tMin = p.timestamp;
      if (p.timestamp > tMax) tMax = p.timestamp;
      proto.set(p.protocol, (proto.get(p.protocol) || 0) + 1);
      const bucket = Math.floor(p.timestamp);
      perSecond.set(bucket, (perSecond.get(bucket) || 0) + 1);
    });

    const duration = Math.max(tMax - tMin, 1.0);
    let peakBucket = null;
    let peakCount = 0;
    Array.from(perSecond.keys()).sort(function (a, b) { return a - b; }).forEach(function (k) {
      if (perSecond.get(k) > peakCount) { peakCount = perSecond.get(k); peakBucket = k; }
    });

    const timeSeries = Array.from(perSecond.keys())
      .sort(function (a, b) { return a - b; })
      .map(function (k) { return { second: k, count: perSecond.get(k) }; });

    const protoCounts = {};
    Array.from(proto.keys()).sort(function (a, b) {
      if (proto.get(b) !== proto.get(a)) return proto.get(b) - proto.get(a);
      return a < b ? -1 : 1;
    }).forEach(function (k) { protoCounts[k] = proto.get(k); });

    const srcPorts = records.map(function (p) { return p.src_port; });
    const dstPorts = records.map(function (p) { return p.dst_port; });

    return {
      total_packets: records.length,
      total_bytes: totalBytes,
      total_bytes_human: humanBytes(totalBytes),
      avg_pkt_size: round2(totalBytes / records.length),
      duration_sec: round2(duration),
      pps: round2(records.length / duration),
      peak_pps: peakCount,
      peak_time: peakBucket === null ? 'N/A' : localStamp(peakBucket),
      peak_epoch: peakBucket,
      proto_counts: protoCounts,
      top_src_ips: valueCounts(records.map(function (p) { return p.src_ip; }), 10),
      top_dst_ips: valueCounts(records.map(function (p) { return p.dst_ip; }), 10),
      top_src_ports: valueCounts(srcPorts.filter(function (p) { return p !== null; }), 10),
      top_dst_ports: valueCounts(dstPorts.filter(function (p) { return p !== null; }), 10),
      top_dns: valueCounts(records.map(function (p) { return p.dns_query; }), 5),
      time_series: timeSeries
    };
  }

  /* ------------------------------------------------------------------ *
   * Seeded synthetic stream (mirrors the demo generator in main.py)
   * ------------------------------------------------------------------ */

  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function simulate(count, seed) {
    const rnd = mulberry32(seed);
    const pick = function (arr) { return arr[Math.floor(rnd() * arr.length)]; };
    const between = function (a, b) { return a + Math.floor(rnd() * (b - a + 1)); };
    const ips = [
      ['192.168.1.10', '8.8.8.8'],
      ['192.168.1.20', '1.1.1.1'],
      ['10.0.0.5', '172.217.0.1'],
      ['192.168.1.10', '192.168.1.20'],
      ['10.0.0.5', '8.8.8.8']
    ];
    const tcpPorts = [80, 443, 22, 8080];
    const udpPorts = [53, 123, 5353];
    const domains = ['example.com', 'cloudflare.com', 'github.com', 'wireshark.org'];
    const base = Math.floor(Date.now() / 1000) - 60;
    const records = [];

    for (let i = 0; i < count; i += 1) {
      const pair = pick(ips);
      const roll = rnd() * 100;
      const ts = base + i * 0.3 + rnd() * 0.2;
      let pkt;

      if (roll < 40) {
        const sport = between(1024, 65535);
        const dport = pick(tcpPorts);
        pkt = {
          timestamp: ts, length: 54 + between(0, 60), src_ip: pair[0], dst_ip: pair[1], ttl: between(32, 128),
          protocol: 'TCP', src_port: sport, dst_port: dport, flags: 'S',
          info: 'TCP ' + pair[0] + ':' + sport + ' \u2192 ' + pair[1] + ':' + dport
        };
      } else if (roll < 70) {
        const sport = between(1024, 65535);
        const dport = pick(udpPorts);
        pkt = {
          timestamp: ts, length: 62 + between(0, 40), src_ip: pair[0], dst_ip: pair[1], ttl: between(32, 128),
          protocol: 'UDP', src_port: sport, dst_port: dport, flags: null,
          info: 'UDP ' + pair[0] + ':' + sport + ' \u2192 ' + pair[1] + ':' + dport
        };
      } else if (roll < 85) {
        pkt = {
          timestamp: ts, length: 74, src_ip: pair[0], dst_ip: pair[1], ttl: 64,
          protocol: 'ICMP', src_port: null, dst_port: null, flags: null,
          info: 'ICMP ' + pair[0] + ' \u2192 ' + pair[1]
        };
      } else {
        const sport = between(1024, 65535);
        const qname = pick(domains);
        pkt = {
          timestamp: ts, length: 78, src_ip: pair[0], dst_ip: '8.8.8.8', ttl: 64,
          protocol: 'DNS', src_port: sport, dst_port: 53, flags: null,
          dns_query: qname, info: 'DNS Query: ' + qname
        };
      }
      records.push(pkt);
    }
    return records;
  }

  /* ------------------------------------------------------------------ *
   * Report rendering
   * ------------------------------------------------------------------ */

  function pad(text, width) {
    const s = String(text);
    return s.length >= width ? s : s + ' '.repeat(width - s.length);
  }

  function padLeft(text, width) {
    const s = String(text);
    return s.length >= width ? s : ' '.repeat(width - s.length) + s;
  }

  function renderTextReport(stats) {
    const out = [];
    const total = stats.total_packets || 1;

    out.push('\u2500'.repeat(3) + ' Real-time Packet Monitoring & Traffic Statistics ' + '\u2500'.repeat(3));
    out.push('');
    out.push('Traffic Summary');
    out.push('  Total Packets   :  ' + stats.total_packets);
    out.push('  Total Bytes     :  ' + stats.total_bytes_human);
    out.push('  Avg Packet Size :  ' + stats.avg_pkt_size.toFixed(2) + ' bytes');
    out.push('  Duration        :  ' + stats.duration_sec.toFixed(2) + ' s');
    out.push('  Avg PPS         :  ' + stats.pps.toFixed(2) + ' pkt/s');
    out.push('  Peak PPS        :  ' + stats.peak_pps + ' pkt/s');
    out.push('  Peak Time       :  ' + stats.peak_time);
    out.push('');
    out.push('Protocol Distribution');
    out.push('  ' + pad('Protocol', 12) + padLeft('Packets', 9) + padLeft('Share', 9));
    Object.keys(stats.proto_counts).forEach(function (k) {
      const n = stats.proto_counts[k];
      out.push('  ' + pad(k, 12) + padLeft(n, 9) + padLeft((100 * n / total).toFixed(1) + '%', 9));
    });
    out.push('');

    const block = function (title, rows, keyLabel, extra) {
      const lines = [title];
      lines.push('  ' + pad(keyLabel, 22) + (extra ? pad('Service', 14) : '') + padLeft('Packets', 9));
      rows.slice(0, 5).forEach(function (row) {
        lines.push('  ' + pad(row[0], 22) + (extra ? pad(portService(Number(row[0])), 14) : '') + padLeft(row[1], 9));
      });
      if (!rows.length) lines.push('  (none)');
      return lines;
    };

    out.push('Top Source IPs');
    out.push.apply(out, block('', stats.top_src_ips, 'IP Address', false).slice(1));
    out.push('');
    out.push('Top Destination IPs');
    out.push.apply(out, block('', stats.top_dst_ips, 'IP Address', false).slice(1));
    out.push('');
    out.push('Top Source Ports');
    out.push.apply(out, block('', stats.top_src_ports, 'Port', true).slice(1));
    out.push('');
    out.push('Top Destination Ports');
    out.push.apply(out, block('', stats.top_dst_ports, 'Port', true).slice(1));
    out.push('');
    out.push('Top DNS Queries');
    out.push('  ' + pad('Query', 24) + padLeft('Count', 7));
    if (stats.top_dns.length) {
      stats.top_dns.forEach(function (row) { out.push('  ' + pad(row[0], 24) + padLeft(row[1], 7)); });
    } else {
      out.push('  (none)');
    }
    out.push('');
    out.push('\u2500'.repeat(3) + ' End of Report ' + '\u2500'.repeat(3));
    return out.join('\n');
  }

  function renderMetrics(stats, meta) {
    const el = document.getElementById('metrics');
    if (!el) return;
    const cells = [
      ['Packets', stats.total_packets, ''],
      ['Bytes', stats.total_bytes_human, ''],
      ['Avg packet', stats.avg_pkt_size.toFixed(2), ' bytes'],
      ['Duration', stats.duration_sec.toFixed(2), ' s'],
      ['Avg PPS', stats.pps.toFixed(2), ' pkt/s'],
      ['Peak PPS', stats.peak_pps, ' pkt/s'],
      ['Protocols', Object.keys(stats.proto_counts).length, ''],
      ['Source', meta.label, '']
    ];
    el.innerHTML = cells.map(function (c) {
      return '<div class="metric"><div class="k">' + escapeHtml(c[0]) + '</div>' +
        '<div class="v">' + escapeHtml(String(c[1])) + '<small>' + escapeHtml(c[2]) + '</small></div></div>';
    }).join('');
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ------------------------------------------------------------------ *
   * Charts (inline SVG)
   * ------------------------------------------------------------------ */

  function donutSvg(stats) {
    const entries = Object.keys(stats.proto_counts).map(function (k) {
      return [k, stats.proto_counts[k]];
    });
    const total = entries.reduce(function (a, e) { return a + e[1]; }, 0) || 1;
    const r = 54;
    const c = 2 * Math.PI * r;
    let offset = 0;
    let arcs = '';
    entries.forEach(function (e) {
      const frac = e[1] / total;
      const colour = PROTO_COLOURS[e[0]] || PROTO_COLOURS.OTHER;
      arcs += '<circle cx="80" cy="80" r="' + r + '" fill="none" stroke="' + colour +
        '" stroke-width="26" stroke-dasharray="' + (frac * c).toFixed(2) + ' ' + c.toFixed(2) +
        '" stroke-dashoffset="' + (-offset * c).toFixed(2) + '" transform="rotate(-90 80 80)"></circle>';
      offset += frac;
    });
    const legend = entries.map(function (e) {
      const colour = PROTO_COLOURS[e[0]] || PROTO_COLOURS.OTHER;
      return '<span><i style="background:' + colour + '"></i>' + escapeHtml(e[0]) + ' ' +
        e[1] + ' (' + (100 * e[1] / total).toFixed(1) + '%)</span>';
    }).join('');
    return {
      svg: '<svg viewBox="0 0 160 160" width="160" height="160" role="img" aria-label="Protocol distribution">' +
        arcs + '<text x="80" y="76" text-anchor="middle" fill="#e7eef9" font-size="20" font-family="ui-monospace, monospace">' +
        total + '</text><text x="80" y="94" text-anchor="middle" fill="#93a4c0" font-size="10" ' +
        'font-family="ui-monospace, monospace">packets</text></svg>',
      legend: legend
    };
  }

  function barsSvg(stats) {
    const rows = stats.top_dst_ips.slice(0, 5);
    if (!rows.length) return { svg: '', legend: '' };
    const max = rows[0][1] || 1;
    const rowH = 30;
    const height = rows.length * rowH + 10;
    let body = '';
    rows.forEach(function (row, i) {
      const w = Math.max(2, (row[1] / max) * 300);
      const y = i * rowH + 6;
      body += '<rect x="0" y="' + y + '" width="' + w.toFixed(1) + '" height="18" rx="4" fill="#2a9fd6" opacity="0.85"></rect>' +
        '<text x="' + (w + 8).toFixed(1) + '" y="' + (y + 13) + '" fill="#93a4c0" font-size="11" ' +
        'font-family="ui-monospace, monospace">' + row[1] + '</text>' +
        '<text x="4" y="' + (y + 13) + '" fill="#0b1220" font-size="11" ' +
        'font-family="ui-monospace, monospace">' + escapeHtml(row[0]) + '</text>';
    });
    return {
      svg: '<svg viewBox="0 0 400 ' + height + '" width="400" height="' + height + '" role="img" aria-label="Top destination addresses">' + body + '</svg>',
      legend: ''
    };
  }

  function lineSvg(stats) {
    const series = stats.time_series;
    if (series.length < 2) return { svg: '', legend: '' };
    const w = 400;
    const h = 140;
    const pad2 = 24;
    const max = Math.max.apply(null, series.map(function (p) { return p.count; })) || 1;
    const step = (w - pad2 * 2) / (series.length - 1);
    const pts = series.map(function (p, i) {
      return [pad2 + i * step, h - pad2 - (p.count / max) * (h - pad2 * 2)];
    });
    const line = pts.map(function (p, i) {
      return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1);
    }).join(' ');
    const area = line + ' L' + pts[pts.length - 1][0].toFixed(1) + ' ' + (h - pad2) +
      ' L' + pts[0][0].toFixed(1) + ' ' + (h - pad2) + ' Z';
    let grid = '';
    for (let g = 0; g <= 2; g += 1) {
      const y = pad2 + (g * (h - pad2 * 2)) / 2;
      const val = Math.round(max * (1 - g / 2));
      grid += '<line x1="' + pad2 + '" y1="' + y + '" x2="' + (w - pad2) + '" y2="' + y +
        '" stroke="#22304a" stroke-width="1"></line>' +
        '<text x="4" y="' + (y + 4) + '" fill="#6f809b" font-size="10" font-family="ui-monospace, monospace">' + val + '</text>';
    }
    return {
      svg: '<svg viewBox="0 0 ' + w + ' ' + h + '" width="' + w + '" height="' + h + '" role="img" aria-label="Packets per second">' +
        grid + '<path d="' + area + '" fill="#4cc2ff" opacity="0.12"></path>' +
        '<path d="' + line + '" fill="none" stroke="#4cc2ff" stroke-width="2"></path>' + '</svg>',
      legend: '<span>peak ' + max + ' pkt/s</span><span>' + series.length + ' one-second buckets</span>'
    };
  }

  /* ------------------------------------------------------------------ *
   * Packet table
   * ------------------------------------------------------------------ */

  function renderTable(records, filter) {
    const body = document.getElementById('packet-body');
    if (!body) return 0;
    const needle = (filter || '').trim().toLowerCase();
    const rows = [];
    let shown = 0;
    for (let i = 0; i < records.length; i += 1) {
      const p = records[i];
      if (needle && p.info.toLowerCase().indexOf(needle) === -1 &&
        String(p.protocol).toLowerCase().indexOf(needle) === -1 &&
        String(p.src_ip || '').indexOf(needle) === -1) continue;
      shown += 1;
      if (rows.length >= 250) continue;
      rows.push('<tr><td>' + localStamp(p.timestamp) + '</td><td>' + escapeHtml(p.src_ip || '-') +
        '</td><td>' + escapeHtml(p.dst_ip || '-') + '</td><td>' + escapeHtml(p.protocol) +
        '</td><td class="num">' + p.length + '</td><td>' + escapeHtml(p.info) + '</td></tr>');
    }
    body.innerHTML = rows.join('');
    const count = document.getElementById('packet-count');
    if (count) {
      count.textContent = shown + ' matching packet' + (shown === 1 ? '' : 's') +
        (shown > 250 ? ' (first 250 shown)' : '');
    }
    return shown;
  }

  /* ------------------------------------------------------------------ *
   * Exports
   * ------------------------------------------------------------------ */

  const CSV_COLUMNS = ['timestamp', 'datetime', 'length', 'src_ip', 'dst_ip', 'protocol',
    'src_port', 'dst_port', 'info', 'eth_src', 'eth_dst', 'ttl', 'flags', 'dns_query', 'http_method'];

  function csvCell(value) {
    if (value === null || value === undefined) return '';
    const s = String(value);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function buildCsv(records) {
    const lines = [CSV_COLUMNS.join(',')];
    records.forEach(function (p) {
      lines.push([
        p.timestamp, localStamp(p.timestamp), p.length, p.src_ip || '', p.dst_ip || '', p.protocol,
        p.src_port === null ? '' : p.src_port, p.dst_port === null ? '' : p.dst_port,
        p.info, p.eth_src || '', p.eth_dst || '', p.ttl === null ? '' : p.ttl,
        p.flags || '', p.dns_query || '', p.http_method || ''
      ].map(csvCell).join(','));
    });
    return lines.join('\n') + '\n';
  }

  function buildMarkdown(stats, meta) {
    const lines = [];
    const total = stats.total_packets || 1;
    lines.push('# Traffic analysis report');
    lines.push('');
    lines.push('Source: ' + meta.label + '. Generated in the browser console; no capture bytes were uploaded.');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('| --- | --- |');
    lines.push('| Total packets | ' + stats.total_packets + ' |');
    lines.push('| Total bytes | ' + stats.total_bytes + ' (' + stats.total_bytes_human + ') |');
    lines.push('| Average packet size | ' + stats.avg_pkt_size.toFixed(2) + ' bytes |');
    lines.push('| Capture duration | ' + stats.duration_sec.toFixed(2) + ' s |');
    lines.push('| Average throughput | ' + stats.pps.toFixed(2) + ' pkt/s |');
    lines.push('| Peak second | ' + stats.peak_pps + ' pkt/s at ' + stats.peak_time + ' |');
    lines.push('');
    lines.push('## Protocol distribution');
    lines.push('');
    lines.push('| Protocol | Packets | Share |');
    lines.push('| --- | --- | --- |');
    Object.keys(stats.proto_counts).forEach(function (k) {
      lines.push('| ' + k + ' | ' + stats.proto_counts[k] + ' | ' +
        (100 * stats.proto_counts[k] / total).toFixed(1) + '% |');
    });
    lines.push('');
    const table = function (title, rows, keyHeader, withService) {
      lines.push('## ' + title);
      lines.push('');
      lines.push('| ' + keyHeader + ' | ' + (withService ? 'Service | ' : '') + 'Packets |');
      lines.push('| --- | ' + (withService ? '--- | ' : '') + '--- |');
      rows.slice(0, 5).forEach(function (r) {
        lines.push('| ' + r[0] + ' | ' + (withService ? portService(Number(r[0])) + ' | ' : '') + r[1] + ' |');
      });
      lines.push('');
    };
    table('Top source addresses', stats.top_src_ips, 'Address', false);
    table('Top destination addresses', stats.top_dst_ips, 'Address', false);
    table('Top source ports', stats.top_src_ports, 'Port', true);
    table('Top destination ports', stats.top_dst_ports, 'Port', true);
    lines.push('## Top DNS queries');
    lines.push('');
    lines.push('| Query | Count |');
    lines.push('| --- | --- |');
    if (stats.top_dns.length) {
      stats.top_dns.forEach(function (r) { lines.push('| ' + r[0] + ' | ' + r[1] + ' |'); });
    } else {
      lines.push('| (none) | 0 |');
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('Traffic statistics describe the analysed capture only; no inference about users,');
    lines.push('content or intent is made from packet headers.');
    return lines.join('\n') + '\n';
  }

  function download(filename, text, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  function downloadSvg(filename, svg) {
    download(filename, '<?xml version="1.0" encoding="UTF-8"?>\n' + svg, 'image/svg+xml');
  }

  /* ------------------------------------------------------------------ *
   * Cross-check against the Python reference
   * ------------------------------------------------------------------ */

  function sameMap(browserList, refList) {
    if (browserList.length !== refList.length) return false;
    const map = new Map();
    browserList.forEach(function (e) { map.set(String(e[0]), e[1]); });
    return refList.every(function (e) {
      return map.has(String(e[0])) && map.get(String(e[0])) === e[1];
    });
  }

  function close(a, b, tol) {
    return Math.abs(a - b) <= tol;
  }

  function runParity(stats, reference, sha, shaState) {
    const checks = [];
    const add = function (name, ok, browser, python, skipped) {
      checks.push({ name: name, ok: ok, browser: browser, python: python, skipped: !!skipped });
    };

    if (!reference) return checks;

    add('capture sha256', shaState === 'ok' ? sha === reference.capture_sha256 : null,
      shaState === 'ok' ? sha.slice(0, 16) + '…' : shaState, reference.capture_sha256.slice(0, 16) + '…',
      shaState !== 'ok');
    add('packets', stats.total_packets === reference.total_packets, stats.total_packets, reference.total_packets);
    add('bytes', stats.total_bytes === reference.total_bytes, stats.total_bytes, reference.total_bytes);
    add('average packet size', close(stats.avg_pkt_size, reference.avg_pkt_size, 0.02),
      stats.avg_pkt_size.toFixed(2), reference.avg_pkt_size.toFixed(2));
    add('duration (s)', close(stats.duration_sec, reference.duration_sec, 0.02),
      stats.duration_sec.toFixed(2), reference.duration_sec.toFixed(2));
    add('average pps', close(stats.pps, reference.pps, 0.02), stats.pps.toFixed(2), reference.pps.toFixed(2));
    add('peak pps', stats.peak_pps === reference.peak_pps, stats.peak_pps, reference.peak_pps);
    add('peak second', stats.peak_time === reference.peak_time, stats.peak_time, reference.peak_time);
    add('protocol counts', sameMap(Object.keys(stats.proto_counts).map(function (k) { return [k, stats.proto_counts[k]]; }),
      Object.keys(reference.proto_counts).map(function (k) { return [k, reference.proto_counts[k]]; })),
      JSON.stringify(stats.proto_counts), JSON.stringify(reference.proto_counts));
    add('top source addresses', sameMap(stats.top_src_ips, reference.top_src_ips),
      stats.top_src_ips.length, reference.top_src_ips.length);
    add('top destination addresses', sameMap(stats.top_dst_ips, reference.top_dst_ips),
      stats.top_dst_ips.length, reference.top_dst_ips.length);
    add('top source ports', sameMap(stats.top_src_ports, reference.top_src_ports),
      stats.top_src_ports.length, reference.top_src_ports.length);
    add('top destination ports', sameMap(stats.top_dst_ports, reference.top_dst_ports),
      stats.top_dst_ports.length, reference.top_dst_ports.length);
    add('top DNS queries', sameMap(stats.top_dns, reference.top_dns),
      stats.top_dns.length, reference.top_dns.length);
    add('per-second buckets', stats.time_series.length === reference.time_series.length,
      stats.time_series.length, reference.time_series.length);
    const refCounts = reference.time_series.map(function (p) { return p.count; });
    const browserCounts = stats.time_series.map(function (p) { return p.count; });
    add('per-second counts',
      refCounts.length === browserCounts.length &&
      refCounts.every(function (c, i) { return c === browserCounts[i]; }),
      browserCounts.join(','), refCounts.join(','));
    const refLabels = reference.time_series.map(function (p) { return p.second; });
    const browserLabels = stats.time_series.map(function (p) { return localStamp(p.second); });
    add('per-second labels (viewer local time)',
      refLabels.length === browserLabels.length &&
      refLabels.every(function (s, i) { return s === browserLabels[i]; }),
      browserLabels.slice(0, 2).join(' / ') + ' …', refLabels.slice(0, 2).join(' / ') + ' …');
    return checks;
  }

  function renderParity(checks, applicable, note) {
    const host = document.getElementById('parity-body');
    const pill = document.getElementById('parity-pill');
    const noteEl = document.getElementById('parity-note');
    if (noteEl) noteEl.textContent = note || '';
    if (!host) return;
    if (!applicable) {
      host.innerHTML = '<tr><td colspan="4" class="skip-mark">Reference comparison is available for the bundled capture only.</td></tr>';
      if (pill) { pill.className = 'pill'; pill.textContent = 'not applicable'; }
      return;
    }
    const scored = checks.filter(function (c) { return !c.skipped; });
    const passed = scored.filter(function (c) { return c.ok; }).length;
    host.innerHTML = checks.map(function (c) {
      const mark = c.skipped ? '<span class="skip-mark">skipped</span>'
        : (c.ok ? '<span class="ok-mark">pass</span>' : '<span class="bad-mark">fail</span>');
      return '<tr><td>' + escapeHtml(c.name) + '</td><td class="num">' + escapeHtml(String(c.browser)) +
        '</td><td class="num">' + escapeHtml(String(c.python)) + '</td><td>' + mark + '</td></tr>';
    }).join('');
    if (pill) {
      const allPass = passed === scored.length;
      pill.className = 'pill ' + (allPass ? 'ok' : 'bad');
      pill.textContent = passed + ' / ' + scored.length + ' checks passed';
    }
  }

  /* ------------------------------------------------------------------ *
   * State + wiring
   * ------------------------------------------------------------------ */

  const state = { records: [], stats: null, meta: { label: 'bundled capture' } };
  let reference = null;

  // Machine-readable result of the most recent run, so an external checker
  // (tools/check_demo.py) can assert on the page instead of scraping text.
  const runStatus = {
    status: 'pending',
    source: '',
    packets: 0,
    protocols: 0,
    proto_counts: {},
    dns: 0,
    records: 0,
    checks_passed: 0,
    checks_total: 0,
    mismatches: []
  };

  function paint(stats, records, meta, parityTarget) {
    state.records = records;
    state.stats = stats;
    state.meta = meta;

    const pre = document.getElementById('report-text');
    if (pre) pre.textContent = renderTextReport(stats);
    renderMetrics(stats, meta);

    const donut = donutSvg(stats);
    const bars = barsSvg(stats);
    const line = lineSvg(stats);
    const donutHost = document.getElementById('chart-protocol');
    const barHost = document.getElementById('chart-endpoints');
    const lineHost = document.getElementById('chart-rate');
    if (donutHost) { donutHost.innerHTML = donut.svg; }
    if (donut.legend) {
      const legendHost = document.getElementById('legend-protocol');
      if (legendHost) legendHost.innerHTML = donut.legend;
    }
    if (barHost) barHost.innerHTML = bars.svg;
    if (lineHost) { lineHost.innerHTML = line.svg; }
    const rateLegend = document.getElementById('legend-rate');
    if (rateLegend) rateLegend.innerHTML = line.legend;

    renderTable(records, document.getElementById('filter') ? document.getElementById('filter').value : '');

    const sourcePill = document.getElementById('source-pill');
    if (sourcePill) sourcePill.textContent = 'source: ' + meta.label;

    const inputNote = document.getElementById('input-note');
    if (inputNote) inputNote.textContent = meta.note || '';

    refreshParity(stats, parityTarget);
  }

  async function refreshParity(stats, parityTarget) {
    if (!parityTarget || !reference) {
      renderParity([], false, 'The cross-check applies to the bundled capture (data/demo.pcap) analysed from this page; local uploads and the synthetic stream have no Python reference here.');
      setSmoke(stats, null);
      return;
    }
    const hash = await sha256Hex(parityTarget.bytes);
    const checks = runParity(stats, reference, hash, hash === 'unavailable' ? 'unavailable' : 'ok');
    renderParity(checks, true, 'Left column: this browser build. Right column: the Python pipeline (Scapy) run on the same capture, committed as docs/data/reference.json.');
    setSmoke(stats, checks);
  }

  function setSmoke(stats, checks) {
    const el = document.getElementById('smoke');
    const scored = (checks || []).filter(function (c) { return !c.skipped; });
    const passed = scored.filter(function (c) { return c.ok; }).length;
    const failed = scored.filter(function (c) { return !c.ok; }).map(function (c) { return c.name; });

    runStatus.source = (state.meta && state.meta.label) || '';
    runStatus.packets = stats.total_packets;
    runStatus.protocols = Object.keys(stats.proto_counts).length;
    runStatus.proto_counts = stats.proto_counts;
    runStatus.dns = stats.top_dns.length;
    runStatus.records = state.records.length;
    runStatus.checks_passed = passed;
    runStatus.checks_total = scored.length;
    runStatus.mismatches = failed;
    // A run is only "ready" when every applicable parity check passed.
    runStatus.status = (scored.length && failed.length) ? 'parity_failed' : 'ready';

    const detail = 'packets=' + stats.total_packets + ' protos=' + Object.keys(stats.proto_counts).length +
      ' dns=' + stats.top_dns.length + ' checks=' + (scored.length ? passed + '/' + scored.length : 'n/a');
    if (el) el.textContent = ((scored.length && failed.length) ? 'UI_SMOKE_FAIL ' : 'UI_SMOKE_OK ') + detail;
  }

  function fail(message) {
    runStatus.status = 'failed';
    runStatus.mismatches = [message];
    const el = document.getElementById('smoke');
    if (el) el.textContent = 'UI_SMOKE_FAIL ' + message;
    const status = document.getElementById('status');
    if (status) { status.className = 'status bad'; status.textContent = message; }
  }

  function setStatus(text, kind) {
    const el = document.getElementById('status');
    if (!el) return;
    el.className = 'status ' + (kind || '');
    el.textContent = text;
  }

  async function sha256Hex(bytes) {
    try {
      if (!window.crypto || !window.crypto.subtle) return 'unavailable';
      const digest = await window.crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(digest)).map(function (b) {
        return b.toString(16).padStart(2, '0');
      }).join('');
    } catch (e) {
      return 'unavailable';
    }
  }

  function analyzeBytes(bytes) {
    const parsed = readPcap(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
    const result = dissectCapture(parsed);
    return { parsed: parsed, dissected: result, stats: analyze(result.records) };
  }

  async function loadBundled() {
    setStatus('loading bundled capture…', 'busy');
    try {
      const response = await fetch('data/demo.pcap', { cache: 'no-cache' });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const buffer = await response.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const out = analyzeBytes(bytes);
      paint(out.stats, out.dissected.records, {
        label: 'bundled capture (data/demo.pcap)',
        note: 'Bundled 200-packet capture, dissected locally in this browser (' + out.parsed.packets.length +
          ' frames read, ' + out.dissected.unparsed + ' skipped).'
      }, { bytes: bytes });
      setStatus('bundled capture analysed', 'ok');
    } catch (e) {
      fail('bundled capture could not be loaded: ' + e.message);
    }
  }

  function handleUpload(file) {
    setStatus('reading ' + file.name + '…', 'busy');
    const reader = new FileReader();
    reader.onload = function () {
      try {
        const bytes = new Uint8Array(reader.result);
        const out = analyzeBytes(bytes);
        if (!out.dissected.records.length) throw new Error('no dissectable frames found');
        paint(out.stats, out.dissected.records, {
          label: file.name + ' (local file, not uploaded)',
          note: 'Parsed locally with the browser reader: ' + out.parsed.packets.length + ' frames, ' +
            out.dissected.unparsed + ' skipped, link type ' + out.parsed.linktype + '.'
        }, null);
        setStatus('analysed ' + file.name, 'ok');
      } catch (e) {
        fail('could not read ' + file.name + ': ' + e.message);
      }
    };
    reader.onerror = function () { fail('the file could not be read'); };
    reader.readAsArrayBuffer(file);
  }

  function runSimulation() {
    const select = document.getElementById('sim-count');
    const count = select ? parseInt(select.value, 10) : 200;
    const records = simulate(count, 20260405);
    const stats = analyze(records);
    paint(stats, records, {
      label: 'synthetic stream (' + count + ' packets, simulated)',
      note: 'Simulated traffic generated in the browser with a fixed seed. These packets are synthetic; ' +
        'they are not a capture and no measurement was taken from a live network.'
    }, null);
    setStatus('simulated stream analysed', 'ok');
  }

  function init() {
    const sample = document.getElementById('btn-sample');
    if (sample) sample.addEventListener('click', loadBundled);

    const input = document.getElementById('file-input');
    if (input) input.addEventListener('change', function () {
      if (input.files && input.files[0]) handleUpload(input.files[0]);
    });

    const sim = document.getElementById('btn-sim');
    if (sim) sim.addEventListener('click', runSimulation);

    const filter = document.getElementById('filter');
    if (filter) filter.addEventListener('input', function () {
      renderTable(state.records, filter.value);
    });

    const csv = document.getElementById('btn-csv');
    if (csv) csv.addEventListener('click', function () {
      if (state.records.length) download('traffic_summary.csv', buildCsv(state.records), 'text/csv;charset=utf-8');
    });

    const md = document.getElementById('btn-md');
    if (md) md.addEventListener('click', function () {
      if (state.stats) download('report.md', buildMarkdown(state.stats, state.meta), 'text/markdown;charset=utf-8');
    });

    const svgProtocol = document.getElementById('svg-protocol');
    if (svgProtocol) svgProtocol.addEventListener('click', function () {
      downloadSvg('protocol_distribution.svg', document.getElementById('chart-protocol').innerHTML);
    });
    const svgEndpoints = document.getElementById('svg-endpoints');
    if (svgEndpoints) svgEndpoints.addEventListener('click', function () {
      downloadSvg('top_endpoints.svg', document.getElementById('chart-endpoints').innerHTML);
    });
    const svgRate = document.getElementById('svg-rate');
    if (svgRate) svgRate.addEventListener('click', function () {
      downloadSvg('packet_rate.svg', document.getElementById('chart-rate').innerHTML);
    });

    const dragZone = document.body;
    dragZone.addEventListener('dragover', function (e) { e.preventDefault(); });
    dragZone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        e.preventDefault();
        handleUpload(e.dataTransfer.files[0]);
      }
    });

    fetch('data/reference.json', { cache: 'no-cache' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (json) { reference = json; })
      .catch(function () { reference = null; })
      .then(loadBundled);

    if ('serviceWorker' in navigator) {
      window.addEventListener('load', function () {
        navigator.serviceWorker.register('sw.js').catch(function () { /* offline support is optional */ });
      });
    }
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
  }

  return {
    readPcap: readPcap,
    dissect: dissect,
    analyze: analyze,
    simulate: simulate,
    analyzeBytes: analyzeBytes,
    renderTextReport: renderTextReport,
    buildCsv: buildCsv,
    buildMarkdown: buildMarkdown,
    PORT_SERVICES: PORT_SERVICES,
    status: function () { return runStatus; },
    state: state
  };
})();

window.RPM = RPM;
