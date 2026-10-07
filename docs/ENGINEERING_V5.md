# Network evidence and response readiness

Version 5 extends the single-host pilot with offline PCAP investigation. It asks a different question from a Windows keyword detector: what can the captured bytes actually support, and which endpoint/business evidence is still needed? The operating path from v4 remains available. Development and initial validation used Codex assistance.

## Acquisition and trust boundaries

Two public historical Wireshark captures are cataloged by URL, exact size and SHA-256 in `data/network-catalog.json`. They are independent protocol samples, not a linked attack or known compromise. The downloader permits only the exact cataloged HTTPS Wiki URL and its corresponding official Wireshark GitLab wiki upload URL, with size and hash checked before publication. Original captures stay under ignored `data/raw/network`; the repository contains attribution and selected derived metadata, not redistributed capture files. No captured URL/domain is visited or resolved.

The constructed exercise writes inert packet bytes locally without sockets. Its endpoint events and asset inventory are explicitly fictional. Original source SHA-256 plus PCAP record offset identifies a packet UID; captured-frame SHA-256 identifies that frame's bytes. An analyst can extract a selected frame after providing the approved capture hash. These references identify received bytes, not an authenticated acquisition or complete sensor coverage.

## Parsing and reconstruction

The standard-library parser accepts classic PCAP version 2.4 in both byte orders and microsecond/nanosecond precision. It bounds input at 32 MiB, 50,000 packets and 2,000 flows. Ethernet with up to two VLAN tags, raw IPv4 and Linux cooked v1 are supported. IPv6, PCAPNG, IP fragmentation and unsupported transport appear as explicit gaps or format rejection; they are not silently decoded as another protocol. Snapshot truncation prevents application inference from that frame.

TCP directions are reconstructed by sequence numbers, including wrap, reordered segments and exact retransmissions. A gap or conflicting overlap suppresses application parsing and creates a diagnostic. Stream span is bounded at 128 KiB. First observed source is not automatically the client. SYNs help identify session boundaries, but tuple reuse without a new observed SYN can remain ambiguous. Counters represent captured traffic, including retransmissions; they are not unique transferred application bytes. Packet checksums are not generally validated by this engine.

DNS inspection bounds compression traversal and rejects pointer cycles, truncated records and oversized names/counts. Question type/class and response code remain separate. A response association requires matching question, transaction ID, reverse tuple, flow and time; retransmitted candidates stay ambiguous. CNAME answer chains and A records can propose a subsequent connection by the same captured client within TTL/300 seconds. Shared addresses, DNS caches and NAT prevent hostname/process identity proof. TCP DNS messages have approximate stream-level timing, so they are excluded from DNS-to-connection timing joins.

HTTP/1 request parsing starts at a reconstructed stream boundary and examines at most 100 requests per direction; it is not an exhaustive HTTP inventory for long streams. It follows Content-Length framing instead of scanning bodies for request-looking strings. Ambiguous headers, invalid field names/values and conflicting Content-Length/Transfer-Encoding are rejected. Chunked bodies are retained as unsupported/incomplete; response bodies and response acceptance are not analyzed. A captured complete request body has a byte hash, not an exfiltration verdict. TLS inspection extracts SNI from a supported first ClientHello; handshake fragmentation across TLS records is a gap. No TLS decryption, certificate validation, HTTP/2 or JA3 claim is made.

Primary protocol references: [classic PCAP](https://wiki.wireshark.org/FileFormatReference/libpcap), [DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), [HTTP/1.1 RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), and [TLS SNI RFC 6066](https://www.rfc-editor.org/rfc/rfc6066). These references define protocol behavior; the implementation deliberately supports only the documented subset.

## Review heuristics and counterexamples

| Policy | Selected observable | Fixed demonstration threshold | Competing explanation |
| --- | --- | --- | --- |
| NET-001 | Long, varied DNS label | Label length ≥40 and Shannon entropy ≥3.5 bits/character | CDN/cache IDs, legitimate telemetry, encoded data |
| NET-002 | HTTP request declares an upload | POST/PUT/PATCH with declared body ≥1,024 bytes | Backup, ordinary application upload, unauthorized transfer |
| NET-003 | Repeated TCP SYN starts | At least six starts over ≥120 seconds; interval CV ≤0.1 | Health checks, agent polling, beacon-like attempts |

Thresholds are explicit educational heuristics. Six SYNs do not establish six successful connections. A long label is not proof of DNS tunneling. A POST is not proof of data theft. The constructed backup/monitoring scenario intentionally produces all three leads; the tool keeps `unassessed` rather than auto-closing them using the generator's intended activity. There is no independent malicious/benign network accuracy benchmark in this release.

## Endpoint and business context

Cross-source pivots require a manifest approving the exact capture hash and the complete endpoint-source hash set, with a collection reason. Only matching Sysmon Operational event-3 provider/channel, protocol, IP/port tuple and a ±2-second interval are candidates. The index avoids a full event rescan per flow. Multiple candidates remain visible. A single candidate still needs capture-vantage, NAT, clock and process-creation/ProcessGuid validation. The public HTTP/DNS samples must not be joined to the historical Windows cases.

Business context is separately bound to the capture hash. Each declared asset needs a unique IP, name, owner, service, classification and criticality. A high/critical asset moves the associated heuristic into `review_first`; this is triage priority based on declared context, not incident severity or confidence. Unknown assets remain visible. Context/scope files are bounded at 128 KiB and reject duplicate JSON keys.

The readiness report distinguishes recorded integrity references, collection gaps, declared ownership, endpoint candidates, missing authorization and missing response authority. Proposed actions include an owner, required approval, business impact, rollback and verification. They never perform isolation, blocking or account changes. This reflects the risk-management perspective described in [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final); it is not a claim of compliance or certification.

## Artifacts and verification

Each fresh bundle contains `network.json`, a self-contained interactive `index.html`, and a file-hash manifest. Publication stages the complete directory before renaming; existing bundles are rejected. The HTML needs no external library/service, renders evidence through textContent and blocks network requests. It displays a bounded packet/flow list while the JSON retains the complete inventory. Capture/summary/context files can contain sensitive data and stay local by default.

Twenty-seven new regression tests exercise malformed captures, both precision/byte-order variants, VLAN/raw/cooked links, DNS cycles and transaction ambiguity, TCP wrap/gaps/conflicts/retransmissions, HTTP framing, TLS truncation, exact approved source scope, endpoint ambiguity, TTL/time boundaries, context validation, HTML injection failed/exclusive publication, exact official download redirects and corrupt download/cache rejection. The optional pinned `dpkt==1.9.8` validator independently decodes selected packet tuples, DNS questions and complete single-packet HTTP requests. It also verifies checksums on every constructed frame. This is an independent cross-check of selected fields, not proof of complete parser equivalence.

The public network step is a separate CI job; core matrix jobs reproduce the constructed scope/ambiguity exercise without external Python dependencies. Original v4/v3 measurements remain dated historical artifacts. Network analysis has not been endurance-tested on high-volume captures or deployed as a sensor, IDS, EDR or multi-user incident platform.
