"""Reproduce packet evidence, ambiguous pivots and an optional independent dpkt check."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import socket
import struct
import sys
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.network_fixtures import build
from soclab import __version__
from soclab.network import analyze_capture, digest, extract_packet, write_bundle
from soclab.store import ingest


def approved_capture_url(spec, url):
    source = spec['url']
    parsed = urlparse(source)
    if (parsed.scheme != 'https' or parsed.netloc != 'wiki.wireshark.org'
            or not parsed.path.startswith('/uploads/') or parsed.query or parsed.fragment):
        raise ValueError('unexpected capture source')
    canonical = 'https://gitlab.com/wireshark/wireshark/-/wikis' + parsed.path
    if spec.get('redirect_url') != canonical:
        raise ValueError('catalog redirect does not match the official upload path')
    return url in (source, canonical)


class CatalogRedirect(HTTPRedirectHandler):
    def __init__(self, spec): self.spec = spec

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not approved_capture_url(self.spec, newurl):
            raise ValueError('unexpected capture redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(spec, folder=None):
    if not approved_capture_url(spec, spec['url']): raise ValueError('unexpected capture source')
    if Path(spec['filename']).name != spec['filename']: raise ValueError('invalid capture filename')
    folder = folder if folder is not None else ROOT / 'data/raw/network'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / spec['filename']
    if path.exists(): raw = path.read_bytes()
    else:
        with build_opener(CatalogRedirect(spec)).open(spec['url'], timeout=30) as response:
            if not approved_capture_url(spec, response.geturl()): raise ValueError('unexpected capture redirect')
            raw = response.read(spec['bytes'] + 1)
        if len(raw) != spec['bytes'] or digest(raw) != spec['sha256']: raise ValueError('downloaded capture differs from catalog')
        with path.open('xb') as stream: stream.write(raw)
    if len(raw) != spec['bytes'] or digest(raw) != spec['sha256']: raise ValueError('cached capture differs from catalog')
    return path


def independent(path, result):
    import dpkt
    rows, dns, requests, checksum_checks = [], [], [], []
    with path.open('rb') as stream:
        reader = dpkt.pcap.Reader(stream)
        if reader.datalink() != 1: raise ValueError('independent exercise expects Ethernet')
        for number, (timestamp, raw) in enumerate(reader, 1):
            eth = dpkt.ethernet.Ethernet(raw); ip = eth.data
            if not isinstance(ip, dpkt.ip.IP): continue
            transport = ip.data
            if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)): continue
            rows.append({'packet_number': number, 'source_ip': socket.inet_ntoa(ip.src), 'destination_ip': socket.inet_ntoa(ip.dst),
                         'source_port': transport.sport, 'destination_port': transport.dport,
                         'protocol': 'TCP' if isinstance(transport, dpkt.tcp.TCP) else 'UDP'})
            if isinstance(transport, dpkt.udp.UDP) and 53 in (transport.sport, transport.dport):
                message = dpkt.dns.DNS(transport.data)
                dns.append({'packet_number': number, 'response': bool(message.qr), 'rcode': message.rcode,
                            'questions': [{'name': q.name.lower(), 'type': q.type, 'class': q.cls} for q in message.qd]})
            if isinstance(transport, dpkt.tcp.TCP) and transport.data.startswith((b'GET ', b'POST ', b'PUT ', b'HEAD ')):
                try:
                    request = dpkt.http.Request(transport.data)
                    requests.append({'packet_number': number, 'method': request.method, 'target': request.uri, 'host': request.headers.get('host', '')})
                except (dpkt.UnpackError, ValueError): pass  # Segmented constructed request is checked separately.
            if path.name == 'constructed.pcap':
                # Fixture Ethernet has no VLAN tags. Validate the actually stored bytes, not reserialized dpkt objects.
                header_length = (raw[14] & 15) * 4
                header = raw[14:14 + header_length]; segment = raw[14 + header_length:14 + ip.len]
                pseudo = ip.src + ip.dst + struct.pack('!BBH', 0, ip.p, len(segment))
                assert dpkt.in_cksum(header) == 0
                assert dpkt.in_cksum(pseudo + segment) == 0
                checksum_checks.append(number)
    own_rows = [{k: packet[k] for k in rows[0]} for packet in result['packets'] if 'protocol' in packet] if rows else []
    assert rows == own_rows, 'independent packet tuples differ'
    own_dns = [{k: message[k] for k in ('packet_number', 'response', 'rcode', 'questions')} for message in result['dns'] if 'stream_packets' not in message]
    assert dns == own_dns, 'independent DNS decoding differs'
    own_requests = [{k: request[k] for k in ('method', 'target', 'host')} for flow in result['flows'] for request in flow['http'] if 'method' in request]
    for request in requests: assert {k: request[k] for k in ('method', 'target', 'host')} in own_requests
    if path.name == 'http.cap': assert len(requests) == len(own_requests) == 2
    return {'validator': 'dpkt', 'version': dpkt.__version__, 'packet_tuples_checked': len(rows),
            'dns_messages_checked': len(dns), 'complete_single_packet_requests_checked': requests,
            'constructed_ipv4_transport_checksums_checked': checksum_checks,
            'scope': 'Independent decoding of selected tuples/DNS and complete single-packet HTTP requests; not full parser equivalence or production accuracy.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True); parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--public', action='store_true'); parser.add_argument('--independent', action='store_true')
    parser.add_argument('--dependencies-dir', type=Path)
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', args.run_id): raise ValueError('invalid run ID')
    if args.out.exists(): raise ValueError('validation artifact must be fresh')
    if args.dependencies_dir: sys.path.insert(0, str(args.dependencies_dir.resolve()))
    run = ROOT / 'output/network' / args.run_id
    if run.exists(): raise ValueError('run directory must be fresh')
    constructed = run / 'constructed'; expected = build(constructed)
    db = constructed / 'endpoint.sqlite'; ingest(constructed / 'endpoint.jsonl', db)
    result = write_bundle(constructed / 'constructed.pcap', run / 'constructed-report', endpoint_db=db,
                          scope_path=constructed / 'scope.json', context_path=constructed / 'context.json')
    assert result['summary']['packets'] == 17
    assert Counter(lead['id'] for lead in result['leads']) == {'NET-001': 1, 'NET-002': 1, 'NET-003': 1}
    assert len(result['endpoint_pivots']['pivots']) == 1 and len(result['endpoint_pivots']['pivots'][0]['candidates']) == 2
    assert result['readiness']['verdict'] == 'unassessed'
    request = next(r for f in result['flows'] for r in f['http'])
    assert request['body_sha256'] == expected['request_body_sha256'] and request['body_complete']
    assert result['flows'][1]['streams'][0]['quality']['retransmitted_bytes'] == 70
    extracted = extract_packet(constructed / 'constructed.pcap', 6, expected['capture_sha256'])
    assert digest(bytes.fromhex(extracted['frame_hex'])) == extracted['anchor']['frame_sha256']
    checks = {'constructed': independent(constructed / 'constructed.pcap', result)} if args.independent else {}
    public_results = []
    if args.public:
        catalog = json.loads((ROOT / 'data/network-catalog.json').read_text(encoding='utf-8'))
        for name, spec in catalog.items():
            path = fetch(spec)
            context_path = run / ('public-' + name + '-context.json')
            context_path.write_text(json.dumps({'capture_sha256': spec['sha256'], 'kind': 'public_sample', 'assets': []}, indent=2) + '\n', encoding='utf-8', newline='\n')
            public = write_bundle(path, run / ('public-' + name), context_path=context_path)
            for field, value in spec['expected'].items(): assert public['summary'][field] == value, (name, field)
            assert not public['leads'] and public['readiness']['verdict'] == 'unassessed'
            public_results.append({'name': name, 'source': public['source'], 'summary': public['summary'], 'diagnostics': public['diagnostics'],
                                   'requests': [r for f in public['flows'] for r in f['http']],
                                   'dns_question_count': sum(len(m['questions']) for m in public['dns']), 'scope': spec['kind']})
            if args.independent: checks[name] = independent(path, public)
    hashes = {p.name: digest(p.read_bytes()) for p in sorted((ROOT / 'soclab').glob('*.py'))}
    artifact = {'version': __version__, 'validated_at': datetime.now(timezone.utc).isoformat(), 'run_id': args.run_id,
                'constructed': {'source': result['source'], 'summary': result['summary'], 'expectations': expected,
                                'lead_counts': dict(Counter(l['id'] for l in result['leads'])), 'dns_connection_candidates': len(result['dns_connection_candidates']),
                                'two_endpoint_candidates_retained': True, 'verdict': result['readiness']['verdict'],
                                'original_frame_extraction_verified': True, 'report': (run / 'constructed-report').relative_to(ROOT).as_posix()},
                'public_samples': public_results, 'independent_checks': checks, 'source_hashes': hashes,
                'scope': 'Public protocol captures and inert constructed bytes; no real compromise, packet capture, payload execution, remote IOC contact or containment.'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8', newline='\n') as stream: stream.write(json.dumps(artifact, indent=2) + '\n')
    print(json.dumps({'version': __version__, 'constructed_packets': 17, 'public_samples': len(public_results),
                      'independent_dpkt': bool(checks), 'two_ambiguous_endpoint_candidates_retained': True}, indent=2))


if __name__ == '__main__': main()
