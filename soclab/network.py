"""Bounded offline packet investigation; observations are never incident verdicts."""

from collections import Counter, defaultdict
from bisect import bisect_left, bisect_right
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import statistics
import struct
from tempfile import TemporaryDirectory

MAX_CAPTURE = 32 * 1024 * 1024
MAX_PACKETS = 50_000
MAX_FLOWS = 2_000
MAX_STREAM = 128 * 1024
MAGIC = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
         b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read_document(path):
    with Path(path).open('rb') as stream: raw = stream.read(131_073)
    if len(raw) > 131_072: raise ValueError('context/scope document exceeds 128 KiB')
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate context/scope JSON key')
            result[key] = value
        return result
    try: return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs)
    except (UnicodeError, RecursionError) as exc: raise ValueError('invalid context/scope document') from exc


def require(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError('truncated protocol field')
    return data[offset:offset + length]


def dns_name(data, offset):
    labels, visited, end, octets = [], set(), None, 1
    for _ in range(128):
        if offset in visited:
            raise ValueError('DNS compression cycle')
        visited.add(offset)
        size = require(data, offset, 1)[0]
        if size & 0xC0 == 0xC0:
            pointer = struct.unpack('!H', require(data, offset, 2))[0] & 0x3FFF
            end = offset + 2 if end is None else end
            offset = pointer
            continue
        if size & 0xC0:
            raise ValueError('unsupported DNS label encoding')
        offset += 1
        if size == 0:
            return '.'.join(labels).lower(), offset if end is None else end
        octets += size + 1
        if octets > 255:
            raise ValueError('DNS name exceeds wire bound')
        labels.append(require(data, offset, size).decode('ascii', errors='backslashreplace'))
        offset += size
    raise ValueError('DNS pointer traversal bound exceeded')


def parse_dns(data):
    identifier, flags, questions, answers, authority, additional = struct.unpack('!6H', require(data, 0, 12))
    if questions > 32 or answers + authority + additional > 256:
        raise ValueError('DNS record bound exceeded')
    offset, qs, records = 12, [], []
    for _ in range(questions):
        name, offset = dns_name(data, offset)
        qtype, qclass = struct.unpack('!HH', require(data, offset, 4))
        qs.append({'name': name, 'type': qtype, 'class': qclass})
        offset += 4
    for index in range(answers + authority + additional):
        name, offset = dns_name(data, offset)
        rtype, rclass, ttl, size = struct.unpack('!HHIH', require(data, offset, 10))
        offset += 10
        raw = require(data, offset, size)
        value = None
        if rtype == 1 and size == 4 or rtype == 28 and size == 16:
            value = str(ipaddress.ip_address(raw))
        elif rtype in (2, 5, 12):
            value, name_end = dns_name(data, offset)
            if name_end > offset + size:
                raise ValueError('DNS RDATA name exceeds field')
        elif rtype == 16:
            parts, at = [], 0
            while at < size:
                length = raw[at]; at += 1
                parts.append(require(raw, at, length).decode('utf-8', errors='replace')); at += length
            value = parts
        records.append({'section': 'answer' if index < answers else 'authority' if index < answers + authority else 'additional',
                        'name': name, 'type': rtype, 'class': rclass, 'ttl': ttl, 'value': value, 'rdata_sha256': digest(raw)})
        offset += size
    return {'id': identifier, 'response': bool(flags & 0x8000), 'opcode': (flags >> 11) & 15,
            'rcode': flags & 15, 'truncated': bool(flags & 0x200), 'questions': qs, 'records': records}


def ipv4(frame, link):
    if link == 1:
        kind = struct.unpack('!H', require(frame, 12, 2))[0]; offset = 14
        for _ in range(2):
            if kind not in (0x8100, 0x88A8): break
            kind = struct.unpack('!H', require(frame, offset + 2, 2))[0]; offset += 4
        if kind != 0x0800: return None, 'non-IPv4 Ethernet frame'
    elif link == 113:
        kind = struct.unpack('!H', require(frame, 14, 2))[0]; offset = 16
        if kind != 0x0800: return None, 'non-IPv4 Linux cooked frame'
    else:
        offset = 0
    data = require(frame, offset, len(frame) - offset)
    require(data, 0, 20)
    if data[0] >> 4 != 4: return None, 'non-IPv4 raw packet'
    ihl, total, fragment = (data[0] & 15) * 4, struct.unpack_from('!H', data, 2)[0], struct.unpack_from('!H', data, 6)[0]
    if ihl < 20 or total < ihl: raise ValueError('invalid IPv4 lengths')
    require(data, 0, total)
    if fragment & 0x3FFF: return None, 'IPv4 fragmentation unsupported; no application inference'
    source, destination = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
    body, proto = data[ihl:total], data[9]
    result = {'source_ip': source, 'destination_ip': destination, 'ip_protocol': proto, 'ip_bytes': total}
    if proto == 17:
        sport, dport, size, _ = struct.unpack('!4H', require(body, 0, 8))
        if size < 8: raise ValueError('invalid UDP length')
        require(body, 0, size)
        result.update(protocol='UDP', source_port=sport, destination_port=dport, payload=body[8:size])
    elif proto == 6:
        require(body, 0, 20)
        sport, dport, seq = struct.unpack_from('!HHI', body)
        hlen = (body[12] >> 4) * 4
        if hlen < 20 or hlen > len(body): raise ValueError('invalid TCP header length')
        result.update(protocol='TCP', source_port=sport, destination_port=dport, sequence=seq,
                      flags=body[13], payload=body[hlen:])
    else:
        return None, 'unsupported IPv4 transport'
    return result, None


def reassemble(segments):
    if not segments: return b'', {'gaps': 0, 'conflicting_bytes': 0, 'retransmitted_bytes': 0}, []
    base = segments[0][0]
    adjusted = [(((seq - base + 2**31) % 2**32) - 2**31, payload, anchor) for seq, payload, anchor in segments]
    start = min(x[0] for x in adjusted); end = max(x[0] + len(x[1]) for x in adjusted)
    if end - start > MAX_STREAM: raise ValueError('TCP stream span bound exceeded')
    content, seen = bytearray(end - start), bytearray(end - start)
    conflicts, repeated = 0, 0
    for at, payload, _ in adjusted:
        for index, value in enumerate(payload, at - start):
            if seen[index]:
                repeated += 1; conflicts += content[index] != value
            else: content[index] = value; seen[index] = 1
    gaps = seen.count(0)
    return bytes(content) if not gaps and not conflicts else b'', {
        'gaps': gaps, 'conflicting_bytes': conflicts, 'retransmitted_bytes': repeated}, [s[2] for s in segments]


def parse_http(data):
    """Parse framed requests from the stream start, never regex-scan bodies for requests."""
    messages, offset = [], 0
    for _ in range(100):
        remaining = data[offset:]
        if not remaining: break
        first_end = remaining.find(b'\r\n')
        if first_end < 0: break
        first = remaining[:first_end].decode('ascii', errors='replace')
        match = re.fullmatch(r'(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) ([^\s]+) HTTP/1\.[01]', first)
        if not match: break
        boundary = remaining.find(b'\r\n\r\n')
        if boundary < 0 or boundary > 16_384:
            messages.append({'diagnostic': 'HTTP header incomplete or oversized'}); break
        headers = {}
        for line in remaining[first_end + 2:boundary].split(b'\r\n'):
            if not line or line[:1] in (b' ', b'\t') or b':' not in line:
                raise ValueError('unsupported or invalid HTTP header')
            key, value = line.split(b':', 1)
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                raise ValueError('invalid HTTP header name')
            if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
                raise ValueError('invalid HTTP header value')
            headers.setdefault(key.decode('ascii').lower(), []).append(value.strip().decode('latin1'))
        if any(len(headers.get(k, [])) > 1 for k in ('host', 'content-length', 'transfer-encoding')):
            raise ValueError('ambiguous HTTP framing headers')
        size_text = headers.get('content-length', ['0'])[0]
        if not re.fullmatch('[0-9]{1,12}', size_text): raise ValueError('invalid HTTP content length')
        size = int(size_text); body_at = offset + boundary + 4
        transfer = headers.get('transfer-encoding', [''])[0]
        if transfer and 'content-length' in headers: raise ValueError('conflicting HTTP framing')
        body_complete = not transfer and len(data) - body_at >= size
        body = data[body_at:body_at + size] if body_complete else b''
        messages.append({'method': match[1], 'target': match[2], 'host': headers.get('host', [''])[0],
                         'content_type': headers.get('content-type', [''])[0], 'declared_body_bytes': size,
                         'body_complete': body_complete, 'body_sha256': digest(body) if body_complete else None,
                         'transfer_encoding': transfer, 'stream_offset': offset,
                         'note': 'Declared length is not proof of server acceptance or exfiltration.'})
        if not body_complete: break
        offset = body_at + size
    return messages


def parse_tls(data):
    """A bounded first ClientHello/SNI inspection, without decryption or fingerprint claims."""
    if not data or data[0] != 22: return None
    require(data, 0, 5)
    if data[1] != 3: raise ValueError('unsupported TLS record version')
    size = struct.unpack_from('!H', data, 3)[0]
    hello = require(data, 5, size)
    if not hello or hello[0] != 1: return None
    hsize = int.from_bytes(require(hello, 1, 3), 'big')
    body = require(hello, 4, hsize); require(body, 0, 35)
    if body[34] > 32: raise ValueError('invalid TLS legacy session ID length')
    at = 35 + body[34]
    cipher_size = struct.unpack('!H', require(body, at, 2))[0]; at += 2 + cipher_size
    compression_size = require(body, at, 1)[0]; at += 1 + compression_size
    if at == len(body): return {'server_names': [], 'note': 'No SNI extension; no hostname inferred.'}
    extension_size = struct.unpack('!H', require(body, at, 2))[0]; at += 2
    end = at + extension_size; require(body, at, extension_size)
    names = []
    while at < end:
        kind, length = struct.unpack('!HH', require(body, at, 4)); at += 4
        extension = require(body, at, length)
        if at + length > end: raise ValueError('TLS extension exceeds section')
        if kind == 0:
            list_size = struct.unpack('!H', require(extension, 0, 2))[0]
            if list_size + 2 != len(extension): raise ValueError('invalid TLS SNI list length')
            pos = 2
            while pos < len(extension):
                name_type = require(extension, pos, 1)[0]
                name_size = struct.unpack('!H', require(extension, pos + 1, 2))[0]; pos += 3
                name = require(extension, pos, name_size); pos += name_size
                if name_type == 0: names.append(name.decode('ascii').lower())
        at += length
    return {'server_names': names, 'note': 'SNI is client-provided metadata. No certificate validation, decryption or remote reputation lookup.'}


def analyze_capture(path):
    path = Path(path)
    with path.open('rb') as stream: data = stream.read(MAX_CAPTURE + 1)
    if len(data) > MAX_CAPTURE: raise ValueError('capture exceeds 32 MiB input limit')
    if data[:4] not in MAGIC: raise ValueError('only classic PCAP is supported; PCAPNG needs explicit conversion')
    endian, multiplier = MAGIC[data[:4]]
    major, minor, _, _, snaplen, link = struct.unpack(endian + 'HHIIII', require(data, 4, 20))
    if (major, minor) != (2, 4) or not 1 <= snaplen <= MAX_CAPTURE or link not in (1, 101, 113):
        raise ValueError('unsupported PCAP header or link type')
    source = digest(data); packets, flows, dns, diagnostics = [], [], [], []
    sessions, segments = {}, defaultdict(lambda: defaultdict(list))
    offset = 24
    while offset < len(data):
        if len(packets) >= MAX_PACKETS: raise ValueError('packet bound exceeded')
        seconds, fraction, caplen, wirelen = struct.unpack(endian + 'IIII', require(data, offset, 16))
        if fraction >= 1_000_000_000 // multiplier or caplen > snaplen or caplen > wirelen:
            raise ValueError('invalid PCAP record lengths or timestamp')
        frame = require(data, offset + 16, caplen); index = len(packets) + 1
        timestamp_ns = seconds * 1_000_000_000 + fraction * multiplier
        anchor = {'packet_number': index, 'record_offset': offset, 'source_sha256': source,
                  'packet_uid': digest(f'{source}:{offset}'.encode()), 'frame_sha256': digest(frame)}
        packet = {**anchor, 'timestamp_ns': timestamp_ns,
                  'timestamp': datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{fraction * multiplier:09d}Z',
                  'captured_bytes': caplen, 'wire_bytes': wirelen}
        packets.append(packet); offset += 16 + caplen
        if caplen < wirelen:
            diagnostics.append({'packet_number': index, 'reason': 'snapshot truncation; application decoding skipped'}); continue
        try:
            parsed, reason = ipv4(frame, link)
        except (ValueError, struct.error, UnicodeError) as exc:
            diagnostics.append({'packet_number': index, 'reason': str(exc)}); continue
        if parsed is None:
            diagnostics.append({'packet_number': index, 'reason': reason}); continue
        payload = parsed.pop('payload'); packet.update(parsed, payload_bytes=len(payload))
        endpoints = sorted([(parsed['source_ip'], parsed['source_port']), (parsed['destination_ip'], parsed['destination_port'])])
        key = (parsed['protocol'], *endpoints)
        flags = parsed.get('flags', 0)
        flow = sessions.get(key)
        syn = parsed['protocol'] == 'TCP' and flags & 2 and not flags & 16
        if flow is None or syn and (flow['closed'] or parsed['sequence'] != flow['initial_sequence']):
            if len(flows) >= MAX_FLOWS: raise ValueError('flow bound exceeded')
            flow = {'id': digest(f'{source}:{index}:flow'.encode())[:24], 'protocol': parsed['protocol'],
                    'origin_ip': parsed['source_ip'], 'origin_port': parsed['source_port'],
                    'peer_ip': parsed['destination_ip'], 'peer_port': parsed['destination_port'],
                    'start_ns': timestamp_ns, 'end_ns': timestamp_ns, 'packets': [], 'captured_ip_bytes': 0,
                    'closed': False, 'initial_sequence': parsed.get('sequence'), 'syn_observed': bool(syn), 'http': [], 'tls': []}
            sessions[key] = flow; flows.append(flow)
        packet['flow_id'] = flow['id']; flow['packets'].append(index)
        flow['start_ns'] = min(flow['start_ns'], timestamp_ns); flow['end_ns'] = max(flow['end_ns'], timestamp_ns)
        flow['captured_ip_bytes'] += parsed['ip_bytes']
        flow['closed'] |= bool(flags & 5)
        if parsed['protocol'] == 'TCP' and payload:
            direction = (parsed['source_ip'], parsed['source_port'], parsed['destination_ip'], parsed['destination_port'])
            segments[flow['id']][direction].append(((parsed['sequence'] + bool(flags & 2)) % 2**32, payload, index))
        elif parsed['protocol'] == 'UDP' and 53 in (parsed['source_port'], parsed['destination_port']):
            try: dns.append({**parse_dns(payload), 'packet_number': index, 'flow_id': flow['id'], 'timestamp_ns': timestamp_ns,
                             'source_ip': parsed['source_ip'], 'destination_ip': parsed['destination_ip'],
                             'source_port': parsed['source_port'], 'destination_port': parsed['destination_port']})
            except (ValueError, struct.error, UnicodeError) as exc:
                diagnostics.append({'packet_number': index, 'reason': 'DNS: ' + str(exc)})
    for flow in flows:
        flow['streams'] = []
        for direction, parts in segments[flow['id']].items():
            try: payload, quality, numbers = reassemble(parts)
            except ValueError as exc:
                flow['streams'].append({'direction': list(direction), 'diagnostic': str(exc), 'packets': [p[2] for p in parts]})
                diagnostics.append({'flow_id': flow['id'], 'reason': str(exc)}); continue
            flow['streams'].append({'direction': list(direction), 'quality': quality, 'packets': numbers,
                                    'reassembled_bytes': len(payload), 'sha256': digest(payload) if payload else None})
            if not payload:
                diagnostics.append({'flow_id': flow['id'], 'reason': 'TCP gap or conflicting overlap; application parsing suppressed', 'quality': quality})
                continue
            try:
                for request in parse_http(payload):
                    flow['http'].append({**request, 'direction': list(direction), 'packets': numbers})
                    if request.get('diagnostic') or not request.get('body_complete', False):
                        diagnostics.append({'flow_id': flow['id'], 'reason': request.get('diagnostic', 'HTTP body incomplete or unsupported transfer encoding')})
                tls = parse_tls(payload)
                if tls: flow['tls'].append({**tls, 'direction': list(direction), 'packets': numbers})
                if 53 in (direction[1], direction[3]):
                    pos = 0
                    while pos < len(payload):
                        size = struct.unpack('!H', require(payload, pos, 2))[0]; pos += 2
                        message = parse_dns(require(payload, pos, size)); pos += size
                        dns.append({**message, 'packet_number': numbers[0], 'stream_packets': numbers, 'flow_id': flow['id'],
                                    'timestamp_ns': flow['start_ns'], 'source_ip': direction[0], 'destination_ip': direction[2],
                                    'source_port': direction[1], 'destination_port': direction[3]})
            except (ValueError, struct.error, UnicodeError) as exc:
                diagnostics.append({'flow_id': flow['id'], 'reason': 'application: ' + str(exc)})
    for number, message in enumerate(dns, 1): message['message_id'] = number
    transactions, query_index = [], defaultdict(list)
    def dns_key(message, reverse=False):
        endpoints = (message['destination_ip'], message['destination_port'], message['source_ip'], message['source_port']) if reverse else (message['source_ip'], message['source_port'], message['destination_ip'], message['destination_port'])
        return (message['id'], message['flow_id'], *endpoints, json.dumps(message['questions'], sort_keys=True))
    for query in (d for d in dns if not d['response']):
        query_index[dns_key(query)].append(query)
    for group in query_index.values(): group.sort(key=lambda q: q['timestamp_ns'])
    query_times = {key: [q['timestamp_ns'] for q in group] for key, group in query_index.items()}
    for response in (d for d in dns if d['response']):
        group = query_index[dns_key(response, reverse=True)]
        times = query_times.get(dns_key(response, reverse=True), [])
        left, right = bisect_left(times, response['timestamp_ns'] - 10_000_000_000), bisect_right(times, response['timestamp_ns'])
        count = right - left
        transactions.append({'response_packet': response['packet_number'], 'response_message_id': response['message_id'],
                             'candidate_query_packets': [q['packet_number'] for q in group[left:min(right, left + 100)]],
                             'candidate_query_message_ids': [q['message_id'] for q in group[left:min(right, left + 100)]],
                             'candidate_count': count, 'association': 'TCP tuple/question candidates; message timing approximate' if 'stream_packets' in response else 'unique observed question/tuple/time' if count == 1 else 'ambiguous' if count else 'query not observed'})
    dns_connections = []
    responses_by_id = {m['message_id']: m for m in dns if m['response']}
    queries_by_id = {m['message_id']: m for m in dns if not m['response']}
    for transaction in transactions:
        if transaction['candidate_count'] != 1: continue
        response = responses_by_id[transaction['response_message_id']]
        query = queries_by_id[transaction['candidate_query_message_ids'][0]]
        if 'stream_packets' in response or 'stream_packets' in query: continue
        if response['rcode'] or response['truncated']: continue
        names = {q['name'] for q in query['questions']}
        for _ in range(8):
            expanded = names | {r['value'] for r in response['records'] if r['section'] == 'answer' and r['type'] == 5 and r['class'] == 1 and r['name'] in names}
            if expanded == names: break
            names = expanded
        for answer in response['records']:
            if answer['section'] != 'answer' or answer['class'] != 1 or answer['type'] != 1 or answer['name'] not in names: continue
            for flow in flows:
                if flow['origin_ip'] == query['source_ip'] and flow['peer_ip'] == answer['value'] and 0 <= flow['start_ns'] - response['timestamp_ns'] <= min(answer['ttl'], 300) * 1_000_000_000:
                    dns_connections.append({'query_packet': query['packet_number'], 'answer_packet': response['packet_number'],
                                            'name': answer['name'], 'address': answer['value'], 'flow_id': flow['id'],
                                            'assessment': 'Same captured client and returned IPv4 address within TTL/300s. Shared addresses, cache and NAT prevent identity proof.'})
                    if len(dns_connections) > 2000: raise ValueError('DNS connection candidate bound exceeded')
    return {'format': 'soclab-network-v1', 'source': {'filename': path.name, 'sha256': source, 'bytes': len(data), 'link_type': link},
            'packets': packets, 'flows': flows, 'dns': dns, 'dns_transactions': transactions, 'diagnostics': diagnostics,
            'summary': {'packets': len(packets), 'flows': len(flows), 'dns_messages': len(dns),
                        'http_requests': sum(len(f['http']) for f in flows), 'tls_client_hellos': sum(len(f['tls']) for f in flows)},
            'dns_connection_candidates': dns_connections, 'leads': network_leads(flows, dns), 'limits': [
                'Offline IPv4 PCAP only; Ethernet (up to two VLAN tags), raw IPv4 and Linux cooked v1. No IPv6, IP fragment assembly or PCAPNG.',
                'No packet checksum validation, payload execution, DNS resolution or remote IOC lookup.',
                'TCP overlap conflicts/gaps suppress application parsing; 128 KiB stream span limit. Midstream starts and tuple reuse without SYN can be ambiguous.',
                'HTTP/1 request framing only; chunked bodies are not decoded. TLS only first unfragmented ClientHello handshake within one record, no decryption.',
                'Payloads may contain secrets. Original PCAP remains separate; summaries, URLs and DNS answers are also potentially sensitive.',
                'Network heuristics are review leads; no malware, C2, exfiltration or server acceptance verdict.'
            ]}


def network_leads(flows, messages):
    leads = []
    for message in messages:
        if message['response']: continue
        for q in message['questions']:
            label = max(q['name'].split('.'), key=len)
            entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in Counter(label).values()) if label else 0
            if len(label) >= 40 and entropy >= 3.5:
                leads.append({'id': 'NET-001', 'title': 'Long varied DNS label', 'packets': [message['packet_number']],
                              'flow_id': message['flow_id'], 'observable': q['name'], 'entropy': round(entropy, 3),
                              'alternatives': ['CDN/cache identifiers', 'Telemetry', 'Encoded data'], 'next_evidence': 'Endpoint process, resolver baseline and approved service context'})
    for flow in flows:
        for request in flow['http']:
            if request.get('method') in ('POST', 'PUT', 'PATCH') and request['declared_body_bytes'] >= 1024:
                leads.append({'id': 'NET-002', 'title': 'HTTP request declares an upload body', 'packets': request['packets'],
                              'flow_id': flow['id'], 'observable': request['host'] + request['target'],
                              'body_complete': request['body_complete'], 'declared_bytes': request['declared_body_bytes'],
                              'alternatives': ['Approved backup', 'Application upload', 'Unauthorized transfer'],
                              'next_evidence': 'Data classification, destination ownership, authorization and endpoint/file context'})
    groups = defaultdict(list)
    for flow in flows:
        if flow['protocol'] == 'TCP' and flow['syn_observed']:
            groups[(flow['origin_ip'], flow['peer_ip'], flow['peer_port'])].append(flow)
    for key, group in groups.items():
        times = sorted(f['start_ns'] / 1e9 for f in group)
        if len(times) < 6 or times[-1] - times[0] < 120: continue
        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(intervals)
        if mean > 0 and statistics.pstdev(intervals) / mean <= .1:
            leads.append({'id': 'NET-003', 'title': 'Regular repeated TCP SYN starts', 'flow_ids': [f['id'] for f in group],
                          'packets': [f['packets'][0] for f in group], 'observable': list(key), 'mean_interval_seconds': round(mean, 3),
                          'alternatives': ['Health checks', 'Scheduled agent', 'Beacon-like activity'],
                          'next_evidence': 'Completed handshake evidence, longer observation, agent inventory, jitter and process attribution'})
    if len(leads) > 2000: raise ValueError('review lead bound exceeded; narrow the capture')
    return leads


def extract_packet(capture, number, expected_source_sha256):
    if type(number) is not int or number < 1: raise ValueError('packet number must be positive')
    result = analyze_capture(capture)
    if result['source']['sha256'] != expected_source_sha256: raise ValueError('capture differs from approved source hash')
    if number > len(result['packets']): raise ValueError('packet number outside capture')
    packet = result['packets'][number - 1]
    if packet['captured_bytes'] > 1_048_576: raise ValueError('packet extraction exceeds one MiB')
    with Path(capture).open('rb') as stream:
        stream.seek(packet['record_offset'] + 16); raw = stream.read(packet['captured_bytes'])
    if digest(raw) != packet['frame_sha256']: raise ValueError('capture changed during extraction')
    return {'anchor': packet, 'frame_hex': raw.hex(), 'scope': 'Original captured frame bytes, not full wire bytes if snapshot-truncated.'}


def endpoint_pivots(result, db, scope):
    """Return tuple/time candidates under exact source approval; no process attribution claim."""
    from itertools import islice
    from .store import iter_events, sources
    actual = {s['sha256'] for s in sources(db)}
    if not isinstance(scope, dict) or scope.get('capture_sha256') != result['source']['sha256']:
        raise ValueError('scope must approve the exact capture and all endpoint source hashes')
    approved = scope.get('endpoint_source_sha256')
    if not isinstance(approved, list) or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in approved) or len(approved) != len(set(approved)) or set(approved) != actual:
        raise ValueError('scope must approve the exact capture and all endpoint source hashes')
    if not isinstance(scope.get('collection_reason'), str) or not scope['collection_reason'].strip() or len(scope['collection_reason']) > 2000:
        raise ValueError('explicit collection reason is required')
    index, event_count = defaultdict(list), 0
    for event in islice(iter_events(db), 100_001):
        event_count += 1
        if event_count > 100_000: raise ValueError('endpoint event bound exceeded')
        if event['event_id'] != 3 or event['provider'].lower() != 'microsoft-windows-sysmon' or event['channel'].lower() != 'microsoft-windows-sysmon/operational': continue
        d = event['event_data']
        key = (d.get('SourceIp'), d.get('SourcePort'), d.get('DestinationIp'), d.get('DestinationPort'), d.get('Protocol', '').upper())
        at = int(datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp() * 1e9)
        index[key].append((at, event))
    for group in index.values(): group.sort(key=lambda pair: pair[0])
    index_times = {key: [pair[0] for pair in group] for key, group in index.items()}
    pivots = []
    for flow in result['flows']:
        candidates = []
        key = (flow['origin_ip'], str(flow['origin_port']), flow['peer_ip'], str(flow['peer_port']), flow['protocol'])
        group, times = index[key], index_times.get(key, [])
        left, right = bisect_left(times, flow['start_ns'] - 2_000_000_000), bisect_right(times, flow['end_ns'] + 2_000_000_000)
        if right - left > 100: raise ValueError('too many endpoint candidates for one flow; narrow collection')
        for _, event in group[left:right]:
            d = event['event_data']
            candidates.append({'event_uid': event['event_uid'], 'source_sha256': event['source_sha256'], 'source_line': event['source_line'],
                               'host': event['host'], 'process_guid': d.get('ProcessGuid'), 'image': d.get('Image'), 'timestamp': event['timestamp']})
        if candidates: pivots.append({'flow_id': flow['id'], 'candidates': candidates, 'assessment': 'tuple/time candidate only; verify NAT, capture vantage, clock offset and GUID creation evidence'})
    return {'approved_scope': scope, 'pivots': pivots, 'note': 'Even one candidate is not authenticated attribution. Multiple candidates remain visible; independent historical samples must not be joined.'}


def write_bundle(capture, output, *, endpoint_db=None, scope_path=None, context_path=None):
    from .network_report import render_html, readiness
    output = Path(output)
    if output.exists(): raise ValueError('choose a fresh network bundle directory')
    result = analyze_capture(capture)
    if bool(endpoint_db) != bool(scope_path): raise ValueError('--endpoint-db and --scope must be supplied together')
    if endpoint_db: result['endpoint_pivots'] = endpoint_pivots(result, endpoint_db, read_document(scope_path))
    context = read_document(context_path) if context_path else None
    result['readiness'] = readiness(result, context)
    result['engine_sha256'] = digest(Path(__file__).read_bytes())
    result['context_sha256'] = digest(Path(context_path).read_bytes()) if context_path else None
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.soclab-network-', dir=output.parent) as temporary:
        staged = Path(temporary) / 'bundle'; staged.mkdir()
        (staged / 'network.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
        (staged / 'index.html').write_text(render_html(result), encoding='utf-8', newline='\n')
        files = {p.name: digest(p.read_bytes()) for p in staged.iterdir()}
        (staged / 'manifest.json').write_text(json.dumps({'source': result['source'], 'files': files, 'scope': 'Original PCAP must be retained separately. Relative integrity, no acquisition signature.'}, indent=2) + '\n', encoding='utf-8', newline='\n')
        if output.exists(): raise ValueError('output appeared during analysis')
        os.rename(staged, output)
    return result
