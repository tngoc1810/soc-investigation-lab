# Phạm vi đóng góp và cách sử dụng hồ sơ

Tôi phát triển SOC Investigation & Operations làm dự án cá nhân phục vụ hồ sơ ứng tuyển SOC Analyst intern. Repo chứa hệ thống chạy được, dữ liệu kiểm chứng, các hồ sơ điều tra và kết quả có thể tái lập trên phạm vi một workstation.

Trong quá trình phát triển và phân tích tôi có dùng Codex hỗ trợ code, kiểm thử và soạn thảo. Tôi giữ thông tin này cùng credit của dataset công khai để phân biệt công cụ hỗ trợ với nguồn bằng chứng. Những mô tả ở ngôi “tôi” nói về lựa chọn và cách tổ chức dự án; chúng không khẳng định mọi dòng code được tự viết độc lập. Tôi chưa dùng hồ sơ này để nhận đã xử lý incident cho doanh nghiệp hoặc đã có kinh nghiệm trực SOC.

Các tài liệu chính là [báo cáo](PROJECT_REPORT_VI.md), [quyết định thiết kế](DESIGN_DECISIONS_VI.md), [runbook](OPERATIONS.md), [nghiệm thu](ACCEPTANCE.md) và thiết kế [v6](ENGINEERING_V6.md)/[v6.1](ENGINEERING_V61.md). Tám case giữ dữ liệu nguồn, quan sát, giả thuyết, quyết định và yêu cầu bổ sung. Bảy bản tiếng Anh trước đây vẫn giữ cạnh bản tiếng Việt để đối chiếu khi cần.

Public samples thuộc tác giả được ghi ở catalog/case. Các scenario tự dựng, owner/approval giả lập và collector diagnostics đều được đánh dấu. Lần native collection có số lượng/thời điểm và raw log giữ riêng; không gọi fixture là thu thập host thật.

SQLite và Loki/LogQL là query paths đã chạy. Sigma condition đã parse; KQL/SPL giữ làm tham chiếu vì chưa chạy trên hai nền tảng đó. Holdout graph F1 thấp hơn baseline vẫn được công bố. Kết quả RAM/benchmark ghi phạm vi phép đo, không phải năng lực xử lý fleet.

Owner/reviewer là nhãn khai báo, chưa là danh tính được xác thực. Readiness không đổi verdict hay gửi ticket. Hash giúp đối chiếu byte với anchor, không chứng minh người gửi có thẩm quyền. Enterprise IAM/HA/retention tự động, continuous packet sensor và containment chưa triển khai.

Một hồ sơ có code và screenshot chưa thay cho khả năng giải thích hệ thống. Khi mô tả đóng góp cá nhân, chỉ nhận phần thực sự đã đọc, kiểm chứng hoặc trực tiếp thay đổi; không dùng tài liệu để tạo trải nghiệm công việc chưa có.
