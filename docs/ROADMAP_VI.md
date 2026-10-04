# Lộ trình xây portfolio SOC intern

Thời lượng dự kiến: 8–10 tuần, 10–12 giờ/tuần. Điều chỉnh theo kiến thức đầu vào. Ưu tiên hoàn thành bằng chứng và khả năng giải thích trước khi tăng số công cụ.

## Hiện trạng

Đã có pipeline local, dữ liệu mô phỏng, exporter EVTX, 8 rule đơn sự kiện, 1 rule tương quan đăng nhập, regression tests và một case EVTX công khai được phân tích mẫu. Đây là nền móng; bạn cần tự điều tra, ghi lại lựa chọn và bảo vệ kết luận để biến thành portfolio của mình.

## Tuần 1 — Hiểu bằng chứng

- Học event provider/channel/Event ID, record ID, UTC và EventData.
- Chạy demo; truy ngược một alert về dòng JSONL gốc và dữ liệu trong SQLite.
- Hoàn thành bài đầu trong START_HERE_VI.md, giải thích vì sao một command backup hợp lệ vẫn alert.
- Deliverable: learning log và một trang phân tích độc lập có evidence references.

## Tuần 2 — Process và script

- Phân biệt PID với ProcessGuid; tìm parent-child cùng host/scenario.
- Đọc command line, PowerShell script block, Windows path và user context.
- Tự dựng lại case mshta trước khi đối chiếu report mẫu; ghi timestamp lệch và telemetry thiếu.
- Deliverable: timeline và bản report do bạn sửa/viết, có ít nhất một giả thuyết thay thế.

## Tuần 3–4 — Authentication investigation

- Học 4624/4625, logon type, target/subject account, Status/SubStatus và source IP.
- Chọn bộ dữ liệu có mô tả kịch bản; ghi log cần có và log thực tế có.
- Kiểm tra repeated-failure-to-success, stale credentials, NAT và khác biệt giữa guessing/spraying.
- Deliverable: case 002 và bảng test ngưỡng/window; không kết luận account compromise chỉ từ count.

## Tuần 5 — Persistence investigation

- Đọc task XML, trigger, principal, service và Run key; chọn một cơ chế để làm sâu.
- Phân biệt lệnh tạo task, task artifact và bằng chứng task thực thi.
- Liên kết telemetry bổ sung nếu cùng dataset; kiểm tra hoạt động quản trị hợp lệ.
- Deliverable: case 003, collection checklist và response proposal có rollback/recovery checks.

## Tuần 6 — False positive và detection validation

- Chọn một rule, lập positive/benign/lookalike test trước khi tuning.
- Viết lý do ngoại lệ; giới hạn theo executable/path/host context nếu có bằng chứng.
- Chạy lại cả positive và benign tests; ghi việc tuning làm mất tín hiệu nào.
- Deliverable: case 004, before/after table và regression test có ý nghĩa.

## Tuần 7–8 — SIEM, triage và escalation

- Thực hành trên lab SIEM sẵn có qua trình duyệt hoặc máy được cấp; chọn một nền tảng theo điều kiện truy cập.
- Học field mapping, time filters, event search, aggregation và correlation query.
- Viết lại ít nhất hai detection thành truy vấn của nền tảng; lưu câu truy vấn và evidence output được phép chia sẻ.
- Deliverable: playbook triage, mẫu escalation ticket và phần so sánh offline/SIEM.

## Tuần 9–10 — Đóng gói và bảo vệ

- Đảm bảo người khác chạy lại được từng case với nguồn và hash rõ ràng.
- Viết README/CV bullet tiếng Anh đúng những việc đã thực hiện; ghi đóng góp và công cụ hỗ trợ.
- Quay video 5–7 phút từ alert đến quyết định; luyện trả lời các câu hỏi trong INTERVIEW.md.
- Deliverable: bốn case hoàn chỉnh, validation table, video và learning log.

## Tiêu chuẩn hoàn thành

- [ ] Bốn case có bằng chứng, giả thuyết thay thế, quyết định và giới hạn.
- [ ] Ít nhất hai case có nhiều loại event liên kết được trong cùng kịch bản.
- [ ] Một case đóng/giữ chờ vì ngữ cảnh hợp lệ hoặc thiếu bằng chứng.
- [ ] Detection có positive và benign regression tests, nguồn/attribution rõ ràng.
- [ ] Có trải nghiệm query/triage trên một SIEM và mô tả đúng giới hạn quyền truy cập.
- [ ] Có số liệu đo thật cùng cách đo và phạm vi.
- [ ] Bạn giải thích được code, rule, evidence và tradeoff mà không phụ thuộc vào report mẫu.
