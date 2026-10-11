# CASE-007 — Upload, DNS label dài và SYN định kỳ: ưu tiên review mà chưa kết luận C2

Tôi dựng 17 packet inert, hai endpoint event và inventory giả lập để kiểm reassembly, attribution và business context. Generator không mở kết nối hay chạy backup. Ý định backup/monitoring được biết từ cách dựng scenario, chưa được suy ra chỉ bằng packet.

## Quan sát và giới hạn

| Quan sát | Điều dữ liệu hỗ trợ | Điều tôi chưa kết luận |
| --- | --- | --- |
| Label dài, nhiều loại ký tự dưới telemetry.example | NET-001 cần context | DNS tunnel hoặc data theft |
| POST /backup, body hoàn chỉnh khai báo 2.480 byte | NET-002 giữ framing và inert-body hash | Server đã nhận hoặc file nhạy cảm bị đánh cắp |
| Sáu SYN start cách 30 giây | NET-003 thấy nỗ lực đều đặn | Sáu C2 session thành công |
| TCP reorder và một exact retransmission | Một request, ghi 70 repeated byte | Nhiều upload độc lập |
| ClientHello có SNI telemetry.example | Client cung cấp tên trong hello hỗ trợ | Server identity đã xác thực hoặc application content đã giải mã |
| Hai Sysmon 3 cùng tuple/time | Hai process candidate | Chọn process thuận tiện rồi bỏ candidate kia |

Body là text lặp inert. Hai candidate có metadata `backup.exe` và `unverified.exe`, chưa có process creation để xác minh origin. Tên executable hoặc destination quen thuộc chưa kiểm content/hash/ownership.

## Cách tôi ưu tiên

Inventory khai báo workstation finance có mức critical, nên ba lead nhận `review_first`. Criticality ảnh hưởng thứ tự kiểm tra, không tăng confidence về maliciousness. Verdict vẫn `unassessed` dù fixture author mô tả backup exercise.

Tôi giữ capture/source hashes, frame anchors, endpoint events và context đúng lần review. Cần capture vantage, time synchronization, ProcessGuid/process creation, executable/hash/signature, file access, destination owner và approval. NAT/proxy hoặc clock khác có thể làm tuple/time association không còn hợp lệ.

## Đề xuất bàn giao

| Công việc | Người phụ trách dự kiến và phê duyệt | Ảnh hưởng/phục hồi | Xác minh |
| --- | --- | --- | --- |
| Giữ capture/endpoint logs | Analyst/custodian, theo retention/data handling được duyệt | Chi phí lưu trữ/privacy, giữ original | Mở lại nguồn, so hash và coverage |
| Kiểm backup/monitoring authorization | Chủ tài sản/ứng dụng, lấy change record | Sửa giả định sai mà giữ quyết định cũ | So executable/content/destination/schedule |
| Cân nhắc hạn chế hẹp khi đủ căn cứ | Incident lead/network owner có quyền phê duyệt | Có thể ngừng backup; giữ cấu hình và thủ tục phục hồi | Kiểm hiệu lực, telemetry tiếp tục, dịch vụ phục hồi |

Project chưa block, isolate host hoặc sửa account. Entropy/periodicity threshold chưa đủ để chặn shared destination. Hồ sơ chuyển cấp phải nói quan sát, giả thuyết cạnh tranh, tác động và dữ liệu còn thiếu.

## Kiểm boundary

Tôi kiểm POST connection để đối chiếu body hash và retransmission count, đồng thời giữ cả hai endpoint candidate. Exact source scope cho phép tương quan, chưa loại ambiguity. Trong experiment mới, đổi protocol hoặc timestamp làm pivot biến mất; thiếu request segment hoặc conflicting overlap phải chặn application inference. Collection gốc được giữ riêng.

[Runbook](../../docs/OPERATIONS.md), [network proofs](../../evidence/network/README.md) và [bản tiếng Anh đã lưu](report.en.md) giữ đường tái lập. Tình huống này kiểm logic trên dữ liệu biết trước, chưa đo detection hiệu quả ngoài thực tế.
