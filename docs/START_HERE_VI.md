# Hồ sơ dự án SOC Investigation & Operations

Đây là mục lục hồ sơ triển khai v6.0.0, cập nhật ngày 09/10/2026. Tài liệu trình bày dự án từ bài toán đến kiến trúc, vận hành, điều tra và nghiệm thu; không dùng cấu trúc giáo án.

## Tài liệu chính

| Hồ sơ | Nội dung |
| --- | --- |
| [Báo cáo dự án](PROJECT_REPORT_VI.md) | Yêu cầu, quyết định thiết kế, data/evidence policy, quy trình vận hành, tám cuộc điều tra và kết quả |
| [Kiến trúc](ARCHITECTURE.md) | Component ownership, storage, transaction/outbox, inference/trust boundary, decision model và capacity guards |
| [Runbook vận hành](OPERATIONS.md) | Native collection, retrospective investigation, optional backend, queue maintenance, PCAP và recovery |
| [Nghiệm thu](ACCEPTANCE.md) | Điều kiện bàn giao, executed checks, failure behavior, release/source identity và phần ngoài phạm vi |
| [Validation có ngày](VALIDATION.md) | Kết quả gốc theo phiên bản, CI/artifact/release attestations và giới hạn phép đo |
| [Schema](DATA_SCHEMA.md) | Original event object, provider/channel, timestamp, source hash và physical references |

## Hồ sơ điều tra

| Case | Câu hỏi điều tra |
| --- | --- |
| [001](../cases/001-mshta-scheduled-task/report.md) | Process chain/network/task artifact hỗ trợ persistence hypothesis đến đâu? |
| [002](../cases/002-authentication/report.md) | Failure burst có chứng minh successful access không; supplement có cùng collection không? |
| [003](../cases/003-powershell-string/report.md) | Download-looking script text có phải executable syntax không? |
| [004](../cases/004-context-tuning/report.md) | Context annotation giảm review priority mà vẫn giữ được evidence/variant thế nào? |
| [005](../cases/005-multisource-chain/report.md) | Identity/ancestry và exact source scope có hỗ trợ multi-stage lead không? |
| [006](../cases/006-public-network/report.md) | Public HTTP/DNS capture hỗ trợ những protocol relationship nào? |
| [007](../cases/007-network-context/report.md) | Hai endpoint candidates và asset criticality ảnh hưởng attribution/priority/response proposal thế nào? |
| [008](../cases/008-telemetry-readiness/report.md) | Quality/clock/channel/heartbeat, inventory và bàn giao theo dịch vụ hỗ trợ quyết định đến đâu? |

## Bằng chứng bàn giao

[Windows hunting/forensics/workflow](../evidence/operations/README.md), [native collection và operational reliability](../evidence/live/README.md), [network/CI/release verification](../evidence/network/README.md) và [checksum inventory](../evidence/checksums.json) giữ các kết quả đã công bố. Original third-party acquisitions và raw private telemetry không nằm trong bộ hồ sơ public.

Source phát triển có Codex hỗ trợ. Data origin, controlled validation và real native collection được phân biệt ở từng case/artifact. Hồ sơ mô tả hệ thống một workstation đã triển khai và kiểm chứng theo phạm vi, không phải kinh nghiệm xử lý production incident hay vận hành SOC doanh nghiệp.

[Thiết kế v6](ENGINEERING_V6.md) trình bày context có thời hạn, source approval, chất lượng telemetry và bàn giao theo dịch vụ. [Case 008](../cases/008-telemetry-readiness/report.md) giữ kết quả và giới hạn của input tự dựng.
