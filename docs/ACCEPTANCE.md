# Hồ sơ nghiệm thu v6.0.0

Tôi nghiệm thu theo ba mức: chức năng đã triển khai, phép chạy có artifact và phần ngoài phạm vi. Version/name tính năng không thay thế kết quả thực thi. [Báo cáo](PROJECT_REPORT_VI.md) ghi reasoning; [validation có ngày](VALIDATION.md) giữ lịch sử từng engine.

## Điều kiện bàn giao

| Gate | Điều kiện | Căn cứ |
| --- | --- | --- |
| Nguồn | Source hash/line/original object, malformed import rollback | Core tests, source catalogs |
| Attribution | Scope/provider/channel/identity/time đúng; missing/conflict giữ lại | Case005 và tests |
| Reliability | Cursor không tiến thiếu evidence, queue persists/restart, explicit retry | Live validation, actual Loki responses |
| Decision | Stale revision/illegal state/tampered audit fail, export retained | Operations/live regressions/browser proof |
| Network | Original frames, TCP gap/conflict boundaries, candidate ambiguity | Network tests, dpkt cross-check |
| Service v6 | Exact/time-valid profile, verified archive/DB/audit/outbox, no source mutation | 24 new tests, [local artifact](../evidence/service/local-validation.json) |
| Quality v6 | Missing field/clock/lag/channel/heartbeat/no-events phân biệt | Case008 và validator |
| Bàn giao | Owner/approval/impact/rollback/verification là đề xuất, alert state giữ nguyên | Generated JSON/Markdown, preservation tests |
| Riêng tư | Kind/path/scope guards, raw private excluded | Private-boundary tests, staged inventory review |
| Release | Tested target, full published checksums, fresh report manifest | [v6 artifacts](../evidence/service/README.md) |

Local Python 3.11.5/3.12.14 pass 151 tests. CI workflow có bốn Windows/Linux Python 3.11/3.12 matrix jobs, Sigma, actual native Loki và independent network/service artifact job. Kết quả CI cụ thể và tested commit được ghi sau khi download/verify logs và artifact trong evidence; workflow định nghĩa chưa phải kết quả pass.

## Kết quả v6 và ranh giới

Constructed validator giữ hai asset, 12 event, một host chưa mapping, năm requirement, bốn cần review và hai alert mở; all anchors/manifest verified. Database chính/archive/nonempty WAL unchanged sau readiness; SHM/zero-frame WAL coordination có thể mới xuất hiện. Chưa claim every physical file immutable.

Finance có auth coverage đúng policy nhưng vẫn two review leads; future process/missing parent/network port/old incomplete 4104 cần bổ sung. Backup không observation/heartbeat; chưa audit-disabled/compromise/benign verdict. Context priority không overwrite detector severity/alert owner/decision.

Snapshot current lúc đọc; as_of evaluation reference chưa historical version. Reviewer/owner self-declared, hash approval chưa verified authority. Report chỉ đọc/point-in-time theo lần gọi; không continuous monitor hoặc external ticket.

## Kiểm chứng hệ thống trước và sau nâng cấp

Các tests cũ nằm trong suite 151. CI Windows rebuild native public EVTX/graph/operations; backend job query pinned native Loki; network job đối chiếu public fields bằng dpkt và constructed checksums. Historical aggregate/detection evaluation không được đổi để tạo kết quả đẹp.

| Phép đo được giữ | Kết quả và giới hạn |
| --- | --- |
| Windows corpus | 6.087 primary +295 independent supplement; không một attack |
| Hunting | 48 query runs |
| Native v4 | 60 records/XML privately held; six matches unreviewed; Security/Sysmon unavailable |
| Outage/backend | Actual 503/fresh process/19 unique UID; controlled input |
| Network public | 81 tuple/40 DNS message/2 complete HTTP request checked, protocol samples |
| Constructed network | 17 packet, ba lead, hai candidate, unassessed |
| Graph holdout | F1 57,1% thấp hơn baseline 72,7%; tám related constructed variants |
| Benchmark | Khoảng 24,2× scoped graph median; không system throughput |
| RAM | Historical 145,51 MiB selected idle components; không total/peak8GB guarantee |

Không thu native batch mới trong v6 và không gắn case008 diagnostic tự dựng với host outage thật.

## Failure behavior được yêu cầu

Reject context expired/new source/kind mismatch/ambiguous alias/missing policy, archive corruption, DB/source mismatch, alert-audit divergence, missing outbox, event/archive/profile caps và public destination cho private report. Unknown host/related alert không bị mất. Renderer/content injection không tạo executable markup. Failed render/permanent publication lock không để final partial bundle; output hiện hữu không bị overwrite.

Giới hạn được ghi rõ: một filesystem owner vẫn copy/reseal được dữ liệu; rename không protocol nhiều publisher; private output path không thay IAM; scope heartbeat không chứng minh sensor host; late replay không chứng minh outage.

## Phần ngoài nghiệm thu

Enterprise fleet deployment, authenticated multi-user IAM/RBAC, HA, automatic retention, production endurance/RTO/RPO, independent field-accuracy benchmark, live packet sensor, full protocol IDS, CMDB/ticket APIs, automated approval và containment. Chưa có cam kết tuyển dụng hoặc độ chính xác tổng quát. Phạm vi bàn giao là implementation một workstation chạy được, với source/reports/evidence kiểm tra lại được.

## Hồ sơ giao nhận

Source/policy/catalog/deployment lock, tám case report, tiếng Việt README/report/architecture/runbook/acceptance/design v6, HTML/JSON/Markdown service bundle và checksum manifest. Public artifact chỉ gồm selected derived results và inert constructed input. Raw private telemetry, credentials, original third-party acquisitions không đưa vào release review bundle.
