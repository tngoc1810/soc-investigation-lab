# Lộ trình học từ project đã hoàn thành

Bản 1.0 đã có bốn báo cáo điều tra, log EVTX công khai có nguồn và hash, pipeline Python/SQLite, 12 detection, giao diện đọc bằng chứng, ảnh chụp thực tế, 36 regression tests và số liệu đo trên máy. Bạn có thể chạy lại bằng scripts/reproduce.ps1. Phần xây dựng được hỗ trợ bởi Codex; phần hiểu, phản biện và trình bày trong phỏng vấn cần bạn tự thực hành.

## Sáu buổi học trong chat

Theo docs/TEACHING_VI.md, mỗi buổi gồm giải thích, thao tác trên case và câu hỏi kiểm tra:

1. Event, alert và incident; truy một finding về sự kiện gốc.
2. Process tree, ProcessGuid, mshta và scheduled task; tách bằng chứng tạo task khỏi bằng chứng thực thi.
3. Authentication: 4625, Status/SubStatus, cửa sổ thời gian và ý nghĩa khác nhau của 4648.
4. PowerShell: nhận diện chuỗi văn bản, script block và giới hạn của token matching.
5. Tuning: ngoại lệ có điều kiện, giữ lại finding và kiểm tra tình huống gần giống.
6. SQL, kiểm thử và trình bày project; giải thích phạm vi đo RAM và những gì chưa biết.

Không cần cài nhiều máy ảo để bắt đầu. Đọc báo cáo, chạy SQLite và viewer trên máy 8 GB RAM trước; thời gian học tùy kiến thức hiện tại.

## Những việc bạn nên tự làm trước khi đưa vào CV

- Chạy lại ít nhất một case và đối chiếu record ID, dòng nguồn, timestamp và hash.
- Viết learning/LOG.md bằng lời của bạn, ghi cả chỗ bạn chưa đồng ý hoặc chưa hiểu.
- Thay một ngưỡng correlation và dự đoán kết quả trước khi chạy.
- Giải thích một false positive và dữ liệu cần thu thập để ra quyết định.
- Luyện demo 6 phút theo docs/DEMO_SCRIPT.md và trả lời docs/INTERVIEW.md.
- Dùng CV bullet trong docs/PORTFOLIO_NOTES.md sau khi hiểu công việc; nói rõ vai trò của công cụ hỗ trợ khi được hỏi.

## Mở rộng sau này

Khi có quyền truy cập một SIEM, chuyển hai detection sang backend đó, kiểm tra field mapping và lưu kết quả thực thi được phép chia sẻ. KQL/SPL trong repo hiện là tham chiếu; SQLite đã được chạy thật. Video demo và trải nghiệm SIEM trực tiếp là phần mở rộng, không phải bằng chứng đã có trong bản 1.0.

Chất lượng phỏng vấn đến từ khả năng bảo vệ kết luận và thừa nhận giới hạn. Repo giúp bạn có dữ liệu cụ thể để luyện điều đó.
