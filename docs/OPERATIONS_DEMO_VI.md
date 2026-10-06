# Demo vận hành và những câu hỏi cần tự trả lời

V4 có hai luồng độc lập: log thật trên máy được giữ private; bài thực hành công khai dùng 19 bản ghi mô phỏng. Đừng trình bày tám alert của bài thực hành như tám sự cố thật.

1. Mở console `http://127.0.0.1:8766`. Giải thích retained events, backlog, private hold, open alerts và review target. Một queue trống không chứng minh endpoint an toàn khi Security/Sysmon thiếu hoặc không đọc được.
2. Chọn AUTH-001. Tìm năm 4625 và một 4624 trong log gốc. Giải thích vì sao cần cùng host, domain, account, IP, logon type và collection. Hai đợt thu thập khác nhau vẫn có thể thuộc cùng một collection đã cấu hình.
3. Đọc phần alternative explanations. Nêu ít nhất hai giả thuyết khác trước khi nói đến brute force. Đăng nhập thành công chưa đủ để xác nhận tài khoản bị chiếm.
4. Phân công, triage, investigate và ghi bước tiếp theo. Thử cập nhật với revision cũ qua CLI để hiểu vì sao bị từ chối. Chọn verdict rõ ràng trước khi đóng.
5. Mở anchored case, xuất packet, kiểm tra SHA-256 và các file `alert-audit.json`, `evidence.jsonl`, `manifest.json`. Nêu khác nhau giữa audit tương đối và chữ ký độc lập.
6. Chạy validator với Loki. Chỉ ra lần HTTP 503, queue còn 19 bản ghi sau khi mở tiến trình mới, rồi Loki trả đủ 19 UID. Giải thích tình huống backend nhận nhưng client chết trước ACK: có thể gửi lại, không phải exactly-once.
7. Tạo snapshot và restore sang workspace mới. Kiểm tra queue, cursor, audit và case link. Giải thích vì sao không chạy cả bản gốc và bản restore cùng lúc.
8. Mở bài PowerShell backup. Match policy-bypass vẫn tồn tại dù fixture được gắn nhãn expected activity. Trong môi trường thật cần kiểm tra script hash/content, chủ sở hữu và change approval; filename không đủ để whitelist.

Máy hiện tại đã đọc được System và PowerShell Operational qua nhiều poll. Security/Sysmon không truy cập được trong phiên kiểm chứng. Collector cũng có thể tự xuất hiện trong log PowerShell; đó là một nguồn false positive cần điều tra. Toàn bộ raw XML, script text, hostname và account ở cache private `%LOCALAPPDATA%/SOCInvestigationLab/live`, ngoài Git và OneDrive; không đưa vào ảnh demo.

Sau khi hiểu được luồng này, bước học kế tiếp là vận hành vài buổi, viết learning log của chính bạn và tự giải thích một lỗi thu thập, một lỗi delivery, một false positive và một missing-telemetry case. Các nhãn actor, review target và bài diễn tập không thay cho kinh nghiệm làm SOC tại doanh nghiệp.
