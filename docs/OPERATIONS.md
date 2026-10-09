# Runbook vận hành

Tôi dùng runbook này cho implementation một workstation. Lệnh chạy từ source checkout. Log/packet/recorded command luôn được coi là dữ liệu; nội dung command quan sát được chưa phải hướng dẫn thao tác máy.

## 1. Preflight và workspace

Core Python 3.11+, native EVTX/channel cần Windows PowerShell và nguồn đọc được. Public download/optional runtime dùng official catalog đã pin. Source ở repo; continuous-write private DB ở `%LOCALAPPDATA%/SOCInvestigationLab/live/default`. Dùng run/output mới; raw private/context/snapshot giữ private cache hoặc ignored data/local.

```powershell
python --version
python -m soclab --help
python scripts/verify_checksums.py
```

Collector chỉ đọc channel hiện hữu, không install Sysmon/enable audit. Ghi thiếu Security/Sysmon trước diễn giải. Native evidence đã công bố dạng aggregate là finite run lịch sử, không chứng minh current fleet coverage.

## 2. Native collection và review

```powershell
python -m soclab live run --channels System --seconds 3600 --interval 10
```

Thêm PowerShell khi readable:

```powershell
python -m soclab live run --channels System Microsoft-Windows-PowerShell/Operational --seconds 3600 --interval 10
```

Restart cùng workspace resume committed cursor. seconds 0 một cycle; invocation bounded một ngày; Ctrl+C dừng foreground, không installed service. Terminal khác:

```powershell
python -m soclab live serve --port 8766
python -m soclab live status
```

Console localhost 8766, metrics ở /metrics. Kiểm coverage/errors/gaps/backlog/private holds trước review. Native held_private đúng thiết kế, không relabel để queue xanh. Đọc original anchors, ghi rationale/current revision, phân công nhãn owner, triage/investigate trước escalate/close. Stale revision reload.

Live closure dùng suspicious_activity/expected_activity/insufficient_evidence; separate case confirmed_in_lab/expected_activity/insufficient_evidence. Due target chưa measured SLA. Promotion verify/recover case linkage, không đồng bộ verdict tự động. Export revision/hash giữ độc lập; original acquisition lưu riêng. Không action cô lập host/block/account trong console.

## 3. Windows retrospective

```powershell
./scripts/reproduce.ps1 -RunId acquisition-20261009
python scripts/verify_portfolio.py
python scripts/build_advanced.py --run-id reconstruction-20261009
python scripts/verify_advanced.py
python scripts/build_operations.py --run-id investigation-20261009
./scripts/inspect_ast.ps1 -InputPath output/operations/investigation-20261009/public-quoted.txt -OutputPath output/operations/investigation-20261009/public-quoted.ast.json
python scripts/verify_operations.py --run-id investigation-20261009
python -m soclab serve --operations-db output/operations/investigation-20261009/cases.sqlite
```

Explorer localhost 8765. output/portfolio/index.json giữ DB/source path thực tế, supplement riêng. verify_portfolio refresh evidence/portfolio-validation.json theo thiết kế; đó là regenerated local attestation, cần review trước thay release inventory. Routine operation không dùng publish-evidence builders.

```powershell
python -m soclab query auth_summary --db output/portfolio/acquisition-20261009/case-002/evidence.sqlite
python -m soclab search --db output/portfolio/acquisition-20261009/case-002/evidence.sqlite --event-id 4624
python -m soclab query powershell_content --db output/portfolio/acquisition-20261009/case-003/evidence.sqlite
```

Public authentication file chỉ failures; không success trong acquisition chưa chứng minh mọi nguồn đều không success. Supplement/network capture độc lập không dùng điền narrative thiếu.

## 4. Optional Loki/Grafana và delivery

```powershell
./scripts/runtime.ps1 -Action Install -Component Loki
./scripts/runtime.ps1 -Action Start -Component Loki
./scripts/runtime.ps1 -Action Status
```

Grafana cùng Loki dùng Component All. [Runtime lock](../deployment/runtime-lock.json) pin official version/hash; mutable runtime/credential ngoài Git. Loopback Loki 3100/Grafana 3000; cấu hình chi tiết ở [RUNBOOK_V3.md](RUNBOOK_V3.md).

```powershell
python scripts/validate_backend.py --run-id backend-20261009 --out output/backend-20261009-validation.json
python scripts/validate_live.py --backend --run-id reliability-20261009 --out output/reliability-20261009-validation.json
```

Historical query giữ original time; replay_now stream riêng giữ original timestamp trong JSON. Backend exercise dùng controlled input, actual HTTP 503/fresh process/19 unique UID actual Loki. Không backend flag thì success dùng acceptance test double; chưa tương đương actual backend proof.

```powershell
./scripts/runtime.ps1 -Action Stop
```

| Quan sát | Xử lý |
| --- | --- |
| Channel error/gap/reset | Giữ cursor/archive/diagnostic; xác minh nguồn/quyền/retention; recent bootstrap chưa phục hồi lost history |
| Pending tăng | Kiểm backend/error và persisted payload; không xóa queue |
| Sending sau crash | Đợi lease expiry; remote có thể đã nhận |
| Dead letter | Sửa nguyên nhân, explicit actor/reason redrive |
| Private holds | Giữ đúng classification; cân nhắc retention/workspace mới |
| Capacity reject | Snapshot/retention decision; không advance cursor thủ công |
| Audit/revision/export mismatch | Giữ divergent state, điều tra/reload; không reseal verdict ưa thích |

Synthetic redrive sau sửa backend:

```powershell
python -m soclab live retry --workspace output/live/reliability-20261009 --actor operator --reason "Backend da duoc sua; tiep tuc giao nhan du lieu tu dung."
python -m soclab live drain --workspace output/live/reliability-20261009
python -m soclab live status --workspace output/live/reliability-20261009
```

At-least-once vẫn có khả năng lặp. Old arrivals ngoài scheduler cần retrospective step, restore chưa tự evaluate mọi old record.

## 5. Packet investigation

Giữ PCAP/hash/acquisition reason/time/vantage/coverage trước phân tích. Classic-PCAP IPv4 subset, diagnostic/gap chưa clean verdict.

```powershell
python -m soclab network --capture data/local/acquisition.pcap --out output/network/acquisition-20261009
python -m soclab network --capture data/local/acquisition.pcap --endpoint-db data/local/endpoint.sqlite --scope data/local/network-scope.json --context data/local/asset-context.json --out output/network/context-20261009
```

Scope gồm capture_sha256, complete endpoint_source_sha256 set và collection_reason. Context bind capture hash, kind và assets với IP/name/owner/service/criticality/classification. Private acquisition dùng private_host, không fictional inventory. Hash declaration chưa authenticated approval. Hai endpoint candidate vẫn hai; priority chưa severity verdict.

```powershell
python -m http.server 8767 --bind 127.0.0.1 --directory output/network/acquisition-20261009
```

Static viewer localhost 8767, Ctrl+C dừng; private report không public artifact. Không truy cập historical observed domains/chạy body.

```powershell
python scripts/validate_network.py --public --run-id protocol-20261009 --out output/protocol-20261009-validation.json
python -m pip install --target output/validation-deps --require-hashes -r requirements-network-validation.txt
python scripts/validate_network.py --public --independent --dependencies-dir output/validation-deps --run-id independent-protocol-20261009 --out output/independent-protocol-20261009-validation.json
```

Expected public HTTP: 43 packet, 3 flow, 2 DNS message, 2 request; DNS: 38 packet, 8 flow, 38 DNS message. Constructed: 17 packet, ba lead, hai candidate, verdict unassessed, không attack traffic generation. Original frame extraction cần exact source hash; [network runbook](RUNBOOK_V5.md) giữ ví dụ.

## 6. Service readiness v6

Scenario acceptance không thu host thật:

```powershell
python scripts/validate_service_readiness.py --run-id service-20261009 --out output/service-20261009-validation.json
python -m http.server 8768 --bind 127.0.0.1 --directory output/service-readiness/service-20261009/report
```

Mốc cố định 09/10/2026 03:00 UTC. Báo cáo có hai asset, 12 event, năm requirement, bốn requirement cần review, hai alert mở và một host chưa mapping. Diagnostic và owners tự dựng. Không đánh đồng với native outage hoặc current monitoring.

Đánh giá lại collection đã review vào destination mới:

```powershell
python -m soclab readiness --workspace output/service-readiness/service-20261009/source/workspace --profile output/service-readiness/service-20261009/source/context.json --as-of 2026-10-09T03:00:00Z --window-seconds 3600 --out output/readiness-reviewed-20261009
```

Operational private profile phải giữ trong private cache/data/local, kind private_host; chọn workspace private và private destination. Bỏ as-of mặc định UTC hiện tại. Người vận hành lập profile mới sau review inventory/batch hash, không dùng synthetic example cho private/native claims. Native batch mới → exact set thay đổi → reject profile cũ; không có auto-approve command. [Schema/limits](ENGINEERING_V6.md) định nghĩa bắt buộc.

Trong giao diện, kiểm asset service/owner, quality/window/lag/clock/heartbeat, unmatched events, unmapped hosts, outbox và handoff. Fresh scope heartbeat chưa sensor-health proof. Missing event ID chưa audit-disabled proof. Readiness không sửa alert owner/revision/verdict, không gửi ticket. as_of chỉ là evaluation reference của current state.

Giữ bốn file bundle/manifest cùng context hash. Dữ liệu raw không nằm hết trong report; acquisition archive phải retained. Verify manifest trước gửi hồ sơ đã approved. Không overwrite output; render/publication failure chọn run mới sau xử lý nguyên nhân. SQLite SHM/zero-frame WAL có thể xuất hiện từ read-only connection; không sửa data tables.

## 7. Snapshot/restore

```powershell
$taskLiveRoot = Join-Path $env:LOCALAPPDATA "SOCInvestigationLab/live"
python -m soclab live snapshot --out (Join-Path $taskLiveRoot "snapshot-20261009.zip")
python -m soclab live restore --source (Join-Path $taskLiveRoot "snapshot-20261009.zip") --workspace (Join-Path $taskLiveRoot "restored-20261009")
python -m soclab live status --workspace (Join-Path $taskLiveRoot "restored-20261009")
```

Destination mới, inventory/hash/database integrity phải verified. Giữ original khi kiểm; không chạy hai delivery copies. Interrupted restore có thể partial, giữ để xem và dùng destination mới cho retry. Published checksums chỉ cover deliberately published artifacts, private retention riêng. Chưa measured RTO/RPO hoặc automated retention.
