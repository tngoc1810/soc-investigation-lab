# Bằng chứng v6 — Chất lượng telemetry và bàn giao

Ngày hoàn thiện 09/10/2026. Tôi giữ artifacts của một run tự dựng riêng, không gộp vào public Windows corpus hoặc native host collection lịch sử.

- [Local pipeline validation](local-validation.json): exact summary, archive/database anchors, readonly persistent bytes, clock/channel/missing fields và manifest.
- [Full regression output](test-results.txt), [test metadata/source hashes](test-validation.json): 151 test trên Python 3.11.5 và 3.12.14, 24 readiness test mới.
- [Context](context.json): thời hạn và exact sources của inventory tự dựng. [Năm input JSONL](../../data/fixtures/service-readiness/) giữ byte được fixture thực sự ingest.
- [JSON đầy đủ](report/readiness.json), [HTML](report/index.html), [biên bản](report/ban-giao.md), [manifest](report/manifest.json): output engine, không viết lại observation thủ công.
- [Browser validation](browser-validation.json): bốn tab, asset search, original anchors, queue/source approval, bàn giao, scope và bố cục narrow/desktop.

Headline hai asset/12 event/một unmapped host/năm requirement/bốn cần review/hai alert mở. Collector diagnostic, owner và business context trong run này đều tự dựng. Kết luận readiness luôn chưa kết luận sự cố.

![Tài sản và chất lượng dữ liệu](screenshots/01-service-readiness.jpg)

![Tài sản backup chưa có nguồn](screenshots/02-missing-telemetry.jpg)

![Bàn giao theo chủ dịch vụ](screenshots/03-service-handoff.jpg)

Ảnh là screenshot trình duyệt thật, không chỉnh sửa. Desktop breakpoint được kiểm ở viewport 1280×900; default narrow layout được kiểm riêng và viewport đã reset. SQLite reader có thể tạo SHM/zero-frame WAL coordination; readonly proof không tuyên bố mọi file vật lý bất biến. as_of là evaluation reference của current DB state, chưa time-travel snapshot.

[Thiết kế](../../docs/ENGINEERING_V6.md), [case008](../../cases/008-telemetry-readiness/report.md) và [runbook](../../docs/OPERATIONS.md) giữ giới hạn suy luận/triển khai. CI/release giữ tested commit và full response riêng; local proof không thay actual CI/backend proof.

[CI bảy job](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37894582621), [downloaded artifact checks](ci-artifact-validation.json), [service response](ci-service-responses.json), [network response](ci-network-responses.json), [native Loki response](ci-backend-responses.json), [outage/recovery response](ci-live-responses.json) và [initial failure](ci-initial-failure.json) ghi identity/run đã kiểm. Snapshot digest CI khác local do actual audit time; context/quality results khớp. [Bản phát hành](https://github.com/tngoc1810/soc-investigation-lab/releases/tag/v6.0.0) trỏ commit `04dc9283c3e10b9a16bc25796c182be9e4ff4fbf`.

## Xác minh bản phát hành

[Release validation](release-validation.json) xác nhận tag trỏ tested commit, GitHub asset digest đúng, byte tải lại giống file upload và exact manifest của ZIP 299 file. ZIP được giải nén vào thư mục mới; core CLI chạy được, checksum verifier kiểm đủ 124 evidence file có trong bundle và pipeline service tái lập kết quả. Attestation upload được ghi sau publish nên không nằm trong ZIP đã upload; inventory hiện tại của repo còn giữ attestation này.
