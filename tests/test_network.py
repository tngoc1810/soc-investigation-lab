"""Malformed packet boundaries, ambiguous identity and false-positive counterexamples."""

import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.request import Request

from scripts.network_fixtures import BASE, CLIENT, SERVER, RESOLVER, build, dns_wire, frame, pcap, tcp, tls_hello, udp
from scripts.validate_network import approved_capture_url, CatalogRedirect, fetch
from soclab.network import analyze_capture, dns_name, endpoint_pivots, extract_packet, parse_dns, parse_http, parse_tls, read_document, reassemble, write_bundle
from soclab.network_report import readiness, render_html
from soclab.store import ingest


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.fixture = self.root / 'fixture'
        self.expected = build(self.fixture); self.capture = self.fixture / 'constructed.pcap'

    def capture_bytes(self, records, **settings):
        path = self.root / 'experiment.pcap'; path.write_bytes(pcap(records, **settings)); return path

    def test_download_redirect_allows_only_exact_official_upload_path(self):
        spec = json.loads(Path('data/network-catalog.json').read_text())['http']
        self.assertTrue(approved_capture_url(spec, spec['url']))
        self.assertTrue(approved_capture_url(spec, spec['redirect_url']))
        handler = CatalogRedirect(spec); request = Request(spec['url'])
        self.assertEqual(handler.redirect_request(request, None, 302, '', {}, spec['redirect_url']).full_url, spec['redirect_url'])
        for url in ('http://gitlab.com/wireshark/wireshark/-/wikis/uploads/http.cap',
                    spec['redirect_url'] + '?next=evil', spec['redirect_url'] + '#fragment',
                    spec['redirect_url'].replace('/wireshark/wireshark/', '/attacker/project/'),
                    'https://wiki.wireshark.org/other.cap', 'https://gitlab.com.evil.test/capture'):
            with self.subTest(url=url):
                self.assertFalse(approved_capture_url(spec, url))
                with self.assertRaises(ValueError): handler.redirect_request(request, None, 302, '', {}, url)
        with self.assertRaises(ValueError): approved_capture_url({**spec, 'redirect_url': 'https://gitlab.com/other'}, spec['url'])

    def test_download_checks_content_before_publishing_and_rechecks_cache(self):
        spec = json.loads(Path('data/network-catalog.json').read_text())['http']
        raw = b'inert'; spec = {**spec, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        folder = self.root / 'download'; opener = MagicMock()
        def response(data, url):
            stream = io.BytesIO(data); stream.geturl = lambda: url
            return stream
        with patch('scripts.validate_network.build_opener', return_value=opener):
            for data, url in ((b'wrong', spec['redirect_url']), (raw + b'extra', spec['redirect_url']), (raw, 'https://evil.test/')):
                opener.open.return_value = response(data, url)
                with self.assertRaises(ValueError): fetch(spec, folder)
                self.assertFalse((folder / spec['filename']).exists())
            opener.open.return_value = response(raw, spec['redirect_url'])
            path = fetch(spec, folder); self.assertEqual(path.read_bytes(), raw)
            path.write_bytes(b'wrong')
            with self.assertRaises(ValueError): fetch(spec, folder)

    def test_constructed_backup_alerts_without_malicious_verdict_and_retains_retransmission(self):
        result = analyze_capture(self.capture)
        self.assertEqual(result['summary'], {'packets': 17, 'flows': 9, 'dns_messages': 4, 'http_requests': 1, 'tls_client_hellos': 1})
        self.assertEqual([lead['id'] for lead in result['leads']], ['NET-001', 'NET-002', 'NET-003'])
        http = next(r for f in result['flows'] for r in f['http'])
        self.assertTrue(http['body_complete']); self.assertEqual(http['body_sha256'], self.expected['request_body_sha256'])
        self.assertEqual(http['packets'], [6, 7, 8])
        flow = next(f for f in result['flows'] if f['http'])
        self.assertEqual(flow['streams'][0]['quality']['retransmitted_bytes'], 70)
        # TTL=60s excludes four later periodic starts; do not extend DNS evidence indefinitely.
        self.assertEqual(len(result['dns_connection_candidates']), 4)
        self.assertEqual(readiness(result, json.loads((self.fixture / 'context.json').read_text()))['verdict'], 'unassessed')

    def test_original_packet_offset_hash_and_changed_source_rejection(self):
        result = analyze_capture(self.capture); packet = result['packets'][5]
        raw = self.capture.read_bytes()[packet['record_offset'] + 16:packet['record_offset'] + 16 + packet['captured_bytes']]
        extracted = extract_packet(self.capture, 6, result['source']['sha256'])
        self.assertEqual(bytes.fromhex(extracted['frame_hex']), raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), packet['frame_sha256'])
        with self.assertRaises(ValueError): extract_packet(self.capture, 6, '0' * 64)

    def test_all_endianness_and_timestamp_precision_variants(self):
        for endian in ('<', '>'):
            for nano in (False, True):
                result = analyze_capture(self.capture_bytes([(BASE + .25, udp(dns_wire('example.test')))], endian=endian, nano=nano))
                self.assertEqual(result['packets'][0]['timestamp_ns'], BASE * 1_000_000_000 + 250_000_000)

    def test_invalid_file_records_and_input_caps_fail_before_bundle_publication(self):
        for raw in (b'', b'\x0a\x0d\x0d\x0a', pcap([(BASE, tcp())])[:-1], pcap([]) + b'broken'):
            self.capture.write_bytes(raw)
            with self.assertRaises(ValueError): write_bundle(self.capture, self.root / 'failed')
            self.assertFalse((self.root / 'failed').exists())
        with patch('soclab.network.MAX_CAPTURE', 10):
            with self.assertRaises(ValueError): analyze_capture(self.capture)

    def test_packet_cap_and_bad_fraction_are_rejected(self):
        with patch('soclab.network.MAX_PACKETS', 2):
            with self.assertRaises(ValueError): analyze_capture(self.capture)
        raw = bytearray(pcap([(BASE, tcp())])); struct.pack_into('<I', raw, 28, 1_000_000)
        self.capture.write_bytes(raw)
        with self.assertRaises(ValueError): analyze_capture(self.capture)

    def test_vlan_raw_and_linux_cooked_link_types(self):
        ethernet = tcp(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
        packets = [(1, tcp(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n', vlan=True)),
                   (101, ethernet[14:]), (113, bytes(14) + b'\x08\x00' + ethernet[14:])]
        for link, packet in packets:
            result = analyze_capture(self.capture_bytes([(BASE, packet)], link=link))
            self.assertEqual(result['summary']['http_requests'], 1)

    def test_snapshot_truncation_ip_fragments_and_ipv6_are_diagnostics(self):
        fragments = frame(17, b'not reassembled', fragment=0x2000)
        ipv6 = bytes(12) + b'\x86\xdd' + bytes(40)
        result = analyze_capture(self.capture_bytes([(BASE, tcp()[:30], 54), (BASE + 1, fragments), (BASE + 2, ipv6)]))
        self.assertEqual(len(result['diagnostics']), 3)
        self.assertEqual(result['summary']['http_requests'], 0)

    def test_tcp_gap_and_conflict_suppress_application_parsing(self):
        prefix = b'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1024\r\n\r\n'
        for tail in ((prefix[20:], 1030), (b'BAD', 1005)):
            result = analyze_capture(self.capture_bytes([(BASE, tcp(prefix[:20], seq=1000)), (BASE + 1, tcp(tail[0], seq=tail[1]))]))
            self.assertEqual(result['summary']['http_requests'], 0)
            self.assertTrue(any(f['streams'][0]['quality']['gaps'] or f['streams'][0]['quality']['conflicting_bytes'] for f in result['flows']))

    def test_tcp_sequence_wrap_out_of_order_and_duplicate_are_reassembled(self):
        value, quality, refs = reassemble([(2, b'cdef', 1), (0xFFFFFFFE, b'abcd', 2), (2, b'cdef', 3)])
        self.assertEqual(value, b'abcdcdef')  # Overlap-free sequence wrap with repeated second segment.
        self.assertEqual(quality['retransmitted_bytes'], 4)
        self.assertEqual(refs, [1, 2, 3])

    def test_dns_pointer_cycle_truncated_records_and_name_bounds(self):
        with self.assertRaises(ValueError): dns_name(b'\xc0\x00', 0)
        with self.assertRaises(ValueError): parse_dns(dns_wire('example.test', response=True)[:-1])
        with self.assertRaises(ValueError): dns_name((b'\x3f' + b'a' * 63) * 5 + b'\0', 0)

    def test_dns_txid_collision_keeps_question_and_retransmission_ambiguity(self):
        records = [(BASE, udp(dns_wire('one.test', 7))), (BASE + .1, udp(dns_wire('two.test', 7))),
                   (BASE + .2, udp(dns_wire('one.test', 7))), (BASE + .3, udp(dns_wire('one.test', 7, response=True), 53, 53000, RESOLVER, CLIENT))]
        result = analyze_capture(self.capture_bytes(records))
        self.assertEqual(result['dns_transactions'][0]['candidate_query_packets'], [1, 3])
        self.assertEqual(result['dns_transactions'][0]['association'], 'ambiguous')
        self.assertFalse(result['dns_connection_candidates'])

    def test_http_body_is_not_scanned_for_invented_requests(self):
        fake = b'GET /fake HTTP/1.1\r\nHost: evil.test\r\n\r\n'
        data = f'POST /real HTTP/1.1\r\nHost: expected.test\r\nContent-Length: {len(fake)}\r\n\r\n'.encode() + fake
        result = parse_http(data)
        self.assertEqual(len(result), 1); self.assertEqual(result[0]['host'], 'expected.test')

    def test_http_ambiguous_framing_and_incomplete_upload(self):
        for headers in (b'Content-Length: 1\r\nContent-Length: 2\r\n', b'Content-Length: 1\r\nTransfer-Encoding: chunked\r\n', b'Content-Length: -1\r\n'):
            with self.assertRaises(ValueError): parse_http(b'POST / HTTP/1.1\r\n' + headers + b'\r\nX')
        request = parse_http(b'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9999\r\n\r\nX')[0]
        self.assertFalse(request['body_complete']); self.assertIsNone(request['body_sha256'])
        chunked = parse_http(b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n')[0]
        self.assertFalse(chunked['body_complete'])
        for bad_header in (b'Content-Length : 1', b'Host: bad\0host'):
            with self.assertRaises(ValueError): parse_http(b'GET / HTTP/1.1\r\n' + bad_header + b'\r\n\r\n')

    def test_tls_sni_is_metadata_and_truncated_records_fail(self):
        self.assertEqual(parse_tls(tls_hello())['server_names'], ['telemetry.example'])
        with self.assertRaises(ValueError): parse_tls(tls_hello()[:-1])

    def test_endpoint_exact_scope_protocol_and_ambiguity(self):
        db = self.root / 'endpoint.sqlite'; ingest(self.fixture / 'endpoint.jsonl', db)
        result = analyze_capture(self.capture); scope = json.loads((self.fixture / 'scope.json').read_text())
        pivots = endpoint_pivots(result, db, scope)['pivots']
        self.assertEqual(len(pivots), 1); self.assertEqual(len(pivots[0]['candidates']), 2)
        for field, value in [('capture_sha256', 'f' * 64), ('endpoint_source_sha256', []), ('collection_reason', '')]:
            bad = copy.deepcopy(scope); bad[field] = value
            with self.assertRaises(ValueError): endpoint_pivots(result, db, bad)

    def test_context_priority_requires_capture_bound_ownership_and_never_closes(self):
        result = analyze_capture(self.capture); context = json.loads((self.fixture / 'context.json').read_text())
        report = readiness(result, context)
        self.assertTrue(all(p['priority'] == 'review_first' for p in report['priorities']))
        self.assertEqual(report['verdict'], 'unassessed')
        context['capture_sha256'] = 'a' * 64
        with self.assertRaises(ValueError): readiness(result, context)

    def test_html_injection_is_inert_and_bundles_are_exclusive(self):
        result = analyze_capture(self.capture); result['readiness'] = readiness(result, None)
        result['source']['filename'] = '</script><img src=x onerror=alert(1)>'
        html = render_html(result)
        self.assertNotIn('</script><img', html); self.assertIn('\\u003c/script\\u003e', html)
        output = self.root / 'bundle'; write_bundle(self.capture, output)
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        with self.assertRaises(ValueError): write_bundle(self.capture, output)
        self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})

    def test_failed_render_never_publishes_partial_bundle(self):
        with patch('soclab.network_report.render_html', side_effect=OSError('injected output failure')):
            with self.assertRaises(OSError): write_bundle(self.capture, self.root / 'bundle')
        self.assertFalse((self.root / 'bundle').exists())

    def test_endpoint_protocol_and_clock_mismatch_do_not_join(self):
        events = [json.loads(line) for line in (self.fixture / 'endpoint.jsonl').read_text().splitlines()]
        events[0]['event_data']['Protocol'] = 'udp'
        events[1]['timestamp'] = '2026-10-07T03:00:00+00:00'
        source = self.root / 'wrong-context.jsonl'; source.write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
        db = self.root / 'wrong.sqlite'; ingest(source, db)
        scope = {'capture_sha256': self.expected['capture_sha256'], 'endpoint_source_sha256': [hashlib.sha256(source.read_bytes()).hexdigest()], 'collection_reason': 'Counterexample'}
        self.assertEqual(endpoint_pivots(analyze_capture(self.capture), db, scope)['pivots'], [])

    def test_reused_tcp_tuple_starts_new_session_and_syn_retransmission_does_not(self):
        records = [(BASE, tcp(seq=100, flags=2)), (BASE + .1, tcp(seq=100, flags=2)),
                   (BASE + 2, tcp(seq=200, flags=2)), (BASE + 3, tcp(b'GET / HTTP/1.1\r\n\r\n', seq=201))]
        result = analyze_capture(self.capture_bytes(records))
        self.assertEqual(len(result['flows']), 2)
        self.assertEqual(result['flows'][0]['packets'], [1, 2])
        self.assertEqual(result['flows'][1]['packets'], [3, 4])

    def test_tcp_dns_multiple_messages_keep_distinct_ids_and_approximate_timing(self):
        queries = [dns_wire('one.test', 7), dns_wire('two.test', 8)]
        replies = [dns_wire('one.test', 7, response=True), dns_wire('two.test', 8, response=True)]
        encode = lambda messages: b''.join(struct.pack('!H', len(m)) + m for m in messages)
        records = [(BASE, tcp(encode(queries), sport=53000, dport=53)),
                   (BASE + 1, tcp(encode(replies), sport=53, dport=53000, source=SERVER, destination=CLIENT))]
        result = analyze_capture(self.capture_bytes(records))
        self.assertEqual(len(result['dns']), 4)
        self.assertEqual(len({m['message_id'] for m in result['dns']}), 4)
        self.assertEqual(len(result['dns_transactions']), 2)
        self.assertTrue(all('approximate' in t['association'] for t in result['dns_transactions']))
        self.assertEqual(result['dns_connection_candidates'], [])

    def test_context_document_size_and_duplicate_keys_are_rejected(self):
        path = self.root / 'context.json'
        path.write_text('{"capture_sha256":"one","capture_sha256":"two"}')
        with self.assertRaises(ValueError): read_document(path)
        path.write_bytes(b' ' * 131_073)
        with self.assertRaises(ValueError): read_document(path)

    def test_ambiguous_asset_inventory_and_unknown_priority_are_rejected(self):
        result = analyze_capture(self.capture); context = json.loads((self.fixture / 'context.json').read_text())
        duplicate = copy.deepcopy(context); duplicate['assets'].append(duplicate['assets'][0])
        with self.assertRaises(ValueError): readiness(result, duplicate)
        context['assets'][0]['criticality'] = 'urgent'
        with self.assertRaises(ValueError): readiness(result, context)

    def test_late_dns_answer_does_not_link_earlier_connection(self):
        records = [(BASE, tcp(seq=100, flags=2)), (BASE + 1, udp(dns_wire('backup.example', 10))),
                   (BASE + 2, udp(dns_wire('backup.example', 10, response=True), 53, 53000, RESOLVER, CLIENT))]
        result = analyze_capture(self.capture_bytes(records))
        self.assertEqual(result['dns_connection_candidates'], [])

    def test_stream_span_limit_is_an_observable_gap_and_suppresses_http(self):
        records = [(BASE, tcp(b'GET / HTTP/1.1\r\n', seq=100)), (BASE + 1, tcp(b'\r\n', seq=999_999))]
        result = analyze_capture(self.capture_bytes(records))
        self.assertEqual(result['summary']['http_requests'], 0)
        self.assertIn('span bound', result['diagnostics'][0]['reason'])


if __name__ == '__main__': unittest.main()
