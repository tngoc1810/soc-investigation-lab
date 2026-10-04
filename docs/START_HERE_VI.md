# Bài 01 — Từ alert đến bằng chứng

Đây là bài nền tảng để bắt đầu học trong chat. Bản hiện tại là v3: xem [10 mô-đun đầy đủ](MASTERCLASS_VI.md) và [runbook dựng toàn bộ lab](RUNBOOK_V3.md) sau khi hiểu cách truy một finding về event gốc.

Mục tiêu: sau buổi đầu, bạn giải thích được alert nói gì, không nói gì, và tìm lại được event gốc. Dự kiến 60–90 phút, có thể chia nhỏ.

## 1. Chạy demo

Mở terminal tại thư mục project. Không cần cài thêm package.

~~~powershell
python -m soclab ingest data/fixtures/demo.jsonl --db output/lesson-01/evidence.sqlite
python -m soclab analyze --db output/lesson-01/evidence.sqlite --out output/lesson-01/run-01
~~~

Mở findings.jsonl và case-notes.md trong output/lesson-01/run-01. Tất cả dữ liệu demo đều là mô phỏng; command chỉ là chuỗi ký tự trong log, không được chạy.

## 2. Điều tra một PowerShell alert

~~~powershell
python -m soclab search --db output/lesson-01/evidence.sqlite --term EncodedCommand
python -m soclab search --db output/lesson-01/evidence.sqlite --event-id 4104
python -m soclab search --db output/lesson-01/evidence.sqlite --term backup
~~~

Ghi câu trả lời vào learning/LOG.md:

1. Image, CommandLine, User và ParentProcessGuid của encoded command là gì?
2. Chỉ nhìn switch mã hóa có đủ kết luận malicious không? Vì sao?
3. Event 4104 cho biết gì? Việc xuất hiện gần event khác có đủ để liên kết process không?
4. Vì sao backup command hợp lệ vẫn trigger WIN-002? Cần ngữ cảnh nào trước khi đóng case?
5. Dùng event_uid, source_sha256 và source_line nào để người khác kiểm tra kết luận?

## 3. Đọc public EVTX

Chạy các lệnh public-case trong README. Tìm event có schtasks và các network event. Trước khi đọc report mẫu, thử tự trả lời:

- Host và user nào liên quan?
- Bốn process trong chuỗi liên kết bằng GUID nào, trên host nào?
- Có task artifact không? Có bằng chứng task đã chạy không?
- System/TimeCreated và EventData.UtcTime có nhất quán không?
- Rule cần Security 4698 có đánh giá được trên file chỉ có Sysmon không?

Sau đó đối chiếu cases/001-mshta-scheduled-task/report.md và ghi lại điều bạn thay đổi trong kết luận. Không truy cập URL lịch sử trong log và không chạy command trích từ bằng chứng; bài này chỉ cần đọc dữ liệu.

## 4. Nộp sản phẩm đầu tiên

Hoàn thành một bản report theo templates/incident-report.md, tập trung vào PowerShell demo. Ghi rõ synthetic dataset ở đầu. Một report tốt có thể kết luận chưa đủ bằng chứng; không cần biến mọi alert thành incident.
