# CASE-006: HTTP and DNS packet evidence

## Collection boundary

Two independent public historical protocol captures come from [Wireshark SampleCaptures](https://wiki.wireshark.org/samplecaptures). The HTTP capture is 25,803 bytes, SHA-256 `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d`; DNS is 4,338 bytes, SHA-256 `041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28`. Bytes remain locally downloaded; metadata and derived checks are published. No malicious intent or real incident is labeled by this project.

## HTTP observation

The HTTP sample contains 43 frames, three TCP/UDP flows, two DNS messages and two HTTP requests. One observed client is `145.254.160.237`. The requests include `GET /download.html` with Host `www.ethereal.com`, and a separate advertising request with Host `pagead2.googlesyndication.com`. These historical names are observed text; they were not visited or queried for current reputation.

DNS query frame 13 asks for `pagead2.googlesyndication.com`; response frame 17 contains CNAME links to `pagead2.google.com` and `pagead.google.akadns.net`, with A answers including `216.239.59.99`. A subsequent TCP flow uses that address. The analyzer proposes a bounded DNS/address/client/time association. That is not identity proof: shared IPs, resolver cache and capture vantage still matter.

The two decoded HTTP requests independently match dpkt's complete single-packet request decoding. Request observation does not establish download completion, content safety or endpoint process identity. The tool does not execute/render response bodies and does not label an old domain as currently malicious or safe.

## DNS observation

The separate DNS sample contains 38 frames/messages across eight UDP flows. Questions include A, AAAA, PTR, MX, TXT, NS, SRV and other types. The analyzer decodes selected A/AAAA/name/TXT answers and retains other RDATA hashes/types; it does not pretend all record-specific formats were decoded. An AAAA question can travel over IPv4 without making the capture an IPv6 packet capture.

Examples include `google.com` TXT/MX questions, reverse-address PTR questions and directory-service SRV names. A legitimate directory-service name can be long. Domain length alone cannot establish tunneling. NXDOMAIN/other response codes must be interpreted with the question, resolver context and capture window; one failure does not establish a DGA.

## Assessment and missing evidence

Verdict remains unassessed. No selected network heuristic matched these samples, but the samples do not establish endpoint safety. Missing facts include authenticated acquisition, sensor/drop coverage, asset owner, endpoint process context and business authorization. No cross-source join to the Windows casebook is justified. Follow-up is to retain the capture, verify original frame offsets/hashes, inspect the protocol relationship and state exactly what cannot be concluded.

Reproduce with `python scripts/validate_network.py --public --independent --run-id YOUR-NEW-ID --out output/YOUR-NEW-ID.json` after installing the optional decoder. The [runbook](../../docs/RUNBOOK_V5.md) documents dependency placement and fresh paths.
