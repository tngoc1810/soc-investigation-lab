# Phạm vi và tác giả dự án

Tôi triển khai SOC Investigation & Operations theo phạm vi một workstation: Windows acquisition, evidence/delivery, scoped detection/reconstruction, static PowerShell, analyst decision/audit/export/recovery, packet investigation và service readiness. Tám hồ sơ giữ observations, giả thuyết cạnh tranh, assessment và missing evidence.

[Báo cáo](PROJECT_REPORT_VI.md), [kiến trúc](ARCHITECTURE.md), [vận hành](OPERATIONS.md), [nghiệm thu](ACCEPTANCE.md) và [thiết kế v6](ENGINEERING_V6.md) là bộ hồ sơ chính. Chúng mô tả implementation, lựa chọn thiết kế và kết quả có phạm vi; chưa phải kinh nghiệm vận hành SOC doanh nghiệp.

Phát triển và phân tích ban đầu có hỗ trợ Codex. Public acquisition authors được credit trong catalog/case. Constructed inputs/collector diagnostics/inventory đều có nhãn; native collection là finite run có ngày, raw records giữ riêng tư. Góc nhìn người làm dự án không đồng nghĩa tự tay độc lập viết mọi module hoặc đã xử lý commercial incident.

SQLite và native Loki/LogQL là executed query paths; Sigma condition được parse; KQL/SPL chưa chạy trên target platforms. Benchmark/working-set/evaluation giữ đúng unit và giới hạn. Graph holdout có F1 thấp hơn baseline, chưa được xóa hoặc thay bằng training score.

Readiness đọc current state, exact/time-valid source context và verified acquisition/audit. Missing telemetry chưa compromise/sensor-disabled verdict. Owner/reviewer khai báo chưa authenticated authority; proposed handoff chưa gửi ticket hoặc containment.

Source/policy/UI/runbooks/case/evidence đã bàn giao theo local scope. Enterprise fleet/IAM/HA/retention automation, continuous packet sensor, containment và field accuracy/endurance chưa được nhận là kết quả. Tested release commit tách rõ các attestation/docs được ghi sau CI.
