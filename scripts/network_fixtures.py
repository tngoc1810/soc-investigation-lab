"""Construct inert packet bytes offline. No socket, capture, resolver or attack execution."""

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

BASE = 1_791_331_200  # 2026-10-07 00:00 UTC
CLIENT, SERVER, RESOLVER = '192.0.2.10', '198.51.100.20', '192.0.2.53'


def checksum(data):
    if len(data) % 2: data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16: value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(proto, body, source=CLIENT, destination=SERVER, *, fragment=0, vlan=False):
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1, fragment, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    ethernet = bytes.fromhex('020000000002020000000001') + (b'\x81\x00\x00\x07\x08\x00' if vlan else b'\x08\x00')
    return ethernet + header + body


def udp(payload, sport=53000, dport=53, source=CLIENT, destination=RESOLVER):
    segment = struct.pack('!HHHH', sport, dport, len(payload) + 8, 0) + payload
    pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed + struct.pack('!BBH', 0, 17, len(segment))
    value = checksum(pseudo + segment) or 65535
    return frame(17, segment[:6] + struct.pack('!H', value) + segment[8:], source, destination)


def tcp(payload=b'', sport=41000, dport=80, seq=1000, flags=0x18, source=CLIENT, destination=SERVER, vlan=False):
    segment = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload
    pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address(destination).packed + struct.pack('!BBH', 0, 6, len(segment))
    segment = segment[:16] + struct.pack('!H', checksum(pseudo + segment)) + segment[18:]
    return frame(6, segment, source, destination, vlan=vlan)


def dns_wire(name, identifier=1, *, response=False, rcode=0, address=SERVER):
    encoded = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + ipaddress.ip_address(address).packed if response and not rcode else b''
    return struct.pack('!6H', identifier, (0x8180 if response else 0x0100) | rcode, 1, bool(answer), 0, 0) + encoded + struct.pack('!HH', 1, 1) + answer


def pcap(records, *, endian='<', nano=False, link=1):
    magic = (b'\x4d\x3c\xb2\xa1' if nano else b'\xd4\xc3\xb2\xa1') if endian == '<' else (b'\xa1\xb2\x3c\x4d' if nano else b'\xa1\xb2\xc3\xd4')
    content = magic + struct.pack(endian + 'HHIIII', 2, 4, 0, 0, 65535, link)
    for record in records:
        timestamp, packet = record[:2]
        wirelen = record[2] if len(record) > 2 else len(packet)
        seconds = int(timestamp); fraction = round((timestamp - seconds) * (1e9 if nano else 1e6))
        content += struct.pack(endian + 'IIII', seconds, fraction, len(packet), wirelen) + packet
    return content


def tls_hello(name='telemetry.example'):
    encoded = name.encode('ascii')
    names = b'\0' + struct.pack('!H', len(encoded)) + encoded
    extension = struct.pack('!HHH', 0, len(names) + 2, len(names)) + names
    body = b'\x03\x03' + bytes(32) + b'\0' + b'\0\x02\x13\x01' + b'\x01\0' + struct.pack('!H', len(extension)) + extension
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake


def build(root):
    root = Path(root)
    if root.exists(): raise ValueError('fixture workspace must be fresh')
    root.mkdir(parents=True)
    long_name = 'abcdefghijklmnopqrstuvwxyz0123456789abcdefghij.telemetry.example'
    records = [
        (BASE, udp(dns_wire('backup.example', 10))),
        (BASE + .05, udp(dns_wire('backup.example', 10, response=True), 53, 53000, RESOLVER, CLIENT)),
        (BASE + .1, udp(dns_wire(long_name, 11))),
        (BASE + .15, udp(dns_wire(long_name, 11, response=True, rcode=3), 53, 53000, RESOLVER, CLIENT)),
        (BASE + 1, tcp(seq=1000, flags=2))
    ]
    body = b'INERT_APPROVED_BACKUP_EXERCISE\n' * 80
    request = f'POST /backup HTTP/1.1\r\nHost: backup.example\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n\r\n'.encode() + body
    split = 70
    records += [(BASE + 1.1, tcp(request[split:], seq=1001 + split)),  # Deliberately out of order.
                (BASE + 1.2, tcp(request[:split], seq=1001)),
                (BASE + 1.3, tcp(request[:split], seq=1001)),  # Exact retransmission.
                (BASE + 2, tcp(seq=1001 + len(request), flags=0x11)),
                (BASE + 3, tcp(seq=3000, flags=2, sport=43000, dport=443)),
                (BASE + 3.1, tcp(tls_hello(), seq=3001, sport=43000, dport=443))]
    for index in range(6):
        records.append((BASE + 10 + index * 30, tcp(sport=42000 + index, dport=8443, seq=2000 + index, flags=2)))
    capture = pcap(records); (root / 'constructed.pcap').write_bytes(capture)
    source_hash = hashlib.sha256(capture).hexdigest()
    # Two observed endpoint candidates with the same tuple/time: ambiguity must survive.
    events = []
    for index, image in enumerate(('C:\\Lab\\backup.exe', 'C:\\Lab\\unverified.exe'), 1):
        events.append({'timestamp': datetime.fromtimestamp(BASE + 1, timezone.utc).isoformat(), 'host': 'WS-EXERCISE',
                       'channel': 'Microsoft-Windows-Sysmon/Operational', 'provider': 'Microsoft-Windows-Sysmon', 'event_id': 3, 'record_id': index,
                       'event_data': {'Protocol': 'tcp', 'SourceIp': CLIENT, 'SourcePort': '41000', 'DestinationIp': SERVER, 'DestinationPort': '80',
                                      'ProcessGuid': f'{{00000001-0000-0000-0000-{index:012d}}}', 'Image': image, 'Initiated': 'true'},
                       'provenance': {'kind': 'synthetic', 'construction': 'Ambiguous endpoint attribution counterexample; no process was executed'}})
    event_bytes = ''.join(json.dumps(e, sort_keys=True) + '\n' for e in events).encode()
    (root / 'endpoint.jsonl').write_bytes(event_bytes)
    scope = {'capture_sha256': source_hash, 'endpoint_source_sha256': [hashlib.sha256(event_bytes).hexdigest()],
             'collection_reason': 'Constructed same scenario; intentionally ambiguous tuple/time evidence, not an observed incident.'}
    context = {'capture_sha256': source_hash, 'kind': 'synthetic', 'assets': [
        {'ip': CLIENT, 'name': 'WS-EXERCISE', 'owner': 'exercise-endpoint-owner', 'business_service': 'Finance exercise workstation',
         'criticality': 'high', 'data_classification': 'Constructed confidential-data context; no real business data'},
        {'ip': SERVER, 'name': 'BACKUP-EXERCISE', 'owner': 'exercise-backup-owner', 'business_service': 'Backup service exercise',
         'criticality': 'medium', 'data_classification': 'Inert repeated text only'}]}
    for filename, value in [('scope.json', scope), ('context.json', context)]:
        (root / filename).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8', newline='\n')
    return {'capture_sha256': source_hash, 'packet_count': len(records), 'request_body_sha256': hashlib.sha256(body).hexdigest(),
            'request_body_bytes': len(body), 'request_sha256': hashlib.sha256(request).hexdigest(), 'long_name': long_name}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--out', type=Path, required=True)
    print(json.dumps(build(parser.parse_args().out), indent=2))
