# Bằng chứng bổ sung v6.1

Đợt cập nhật ngày 11/10/2026 bổ sung kiểm gói readiness ở phía nhận và biên tập hồ sơ điều tra. Tôi giữ kết quả mới ở đây để không thay artifact nghiệm thu v6.0.

- [Pipeline](pipeline-validation.json): fixture mới được thu vào workspace, readiness kiểm acquisition/audit và verifier kiểm bundle. Dữ liệu/diagnostics là tự dựng.
- [CLI acceptance](cli-validation.json): CLI thật chấp nhận bundle v6 có anchor cố định, từ chối bốn bản sao được sửa riêng. Original bundle không thay đổi.
- [Test attestation](test-validation.json): Python/version, code hashes và hai kết quả 170 test.
- [Full test output](test-results.txt): transcript đầy đủ, gồm 19 verifier regressions mới.
- [Documentation checks](document-validation.json): file links, command parsing và PowerShell AST syntax; không thực thi command operational trong tài liệu.

Digest của manifest gói v6 giữ độc lập trong repo/script nghiệm thu. Điều này đủ đối chiếu retained artifact trong phép kiểm, chưa chứng minh secure external delivery. Verifier không chạy HTML, gọi mạng hoặc kiểm lại original acquisition. Không có native collection hoặc containment mới được nhận là kết quả đợt này.

[Thiết kế](../../docs/ENGINEERING_V61.md), [quyết định thiết kế](../../docs/DESIGN_DECISIONS_VI.md) và [nghiệm thu](../../docs/ACCEPTANCE.md) giữ lý do/phạm vi. [Checksum inventory](../checksums.json) liệt kê exact public evidence files; sau này regenerate cần review và ghi kết quả theo run mới.

## CI đã kiểm

[Run 38140112524](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/38140112524) pass bảy job trên commit 92ebf1c85feb981177f05cb95a0cd1d413045029. [CI](ci-validation.json) và [artifact verification](ci-artifact-validation.json) giữ downloaded-log counts, digest/inventory/Git blob identity.

Full responses: [handoff](ci-handoff-responses.json), [readiness](ci-service-responses.json), [network](ci-network-responses.json), [Loki historical](ci-backend-responses.json), [outage/recovery](ci-live-responses.json). Handoff có một accept/bốn reject; readiness khớp local về context/assessment, snapshot identity độc lập theo audit time.

[Release verification](release-validation.json) giữ tag target, asset digest, downloaded bytes, 327-file inventory và bốn smoke commands chạy trong thư mục mới. Attestation được ghi sau upload, không nằm trong ZIP đã công bố.
