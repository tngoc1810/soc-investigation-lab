# Lộ trình học để tự trình bày và bảo vệ project

Mục tiêu là tự làm lại được các bước quan trọng và giải thích được từng quyết định. Repo có hỗ trợ Codex trong quá trình phát triển và phân tích ban đầu. Đừng trình bày các case mô phỏng như kinh nghiệm xử lý sự cố tại doanh nghiệp. Khi học trong chat, mỗi buổi đi theo thứ tự: hiểu log → tự dự đoán → chạy kiểm chứng → viết kết luận → phản biện.

## Buổi 1 — Đọc kiến trúc và phân loại bằng chứng

Phân biệt ba nguồn: EVTX công khai, fixture mô phỏng và 20 log System thực đọc trên máy. Dữ liệu private chỉ giữ local. Bộ 6.087 log primary gồm nhiều collection độc lập; con số này không mô tả một cuộc tấn công.

Tự vẽ đường đi EVTX → export JSONL → SQLite → rule/graph → analyst case → export. Vẽ thêm nhánh replay Loki/Grafana và giải thích vì sao log backend không thay thế file thu thập gốc.

Bài tập: tìm source hash, event UID, record ID và source line của một log. Viết hai câu giải thích khác nhau giữa “file không đổi” và “file là nguồn đáng tin”. Hash hỗ trợ kiểm tra tính toàn vẹn tương đối, không tự chứng minh ai tạo log.

## Buổi 2 — Windows log và authentication

Đọc các trường trong 4625 và 4624: host, domain, account, IP, logon type, logon ID/GUID và failure reason khi có. Giải thích vì sao trùng username chưa đủ để ghép phiên đăng nhập. 4648 ghi nhận dùng credential tường minh, không mặc định là đăng nhập thất bại.

Bài tập: mở case 002, chạy hunt authentication. Có bốn nhóm với tổng 3.561 failure; nhóm lớn nhất là 3.558. Tìm ba bản ghi khác điều kiện. Tìm 4624 trong collection này và viết kết luận đúng khi kết quả bằng 0.

Đáp án cần bảo vệ: chỉ nói “không có 4624 trong file đã thu thập”. Chưa đủ để nói không có đăng nhập thành công ở nơi khác. Không ghép bộ supplement độc lập để lấp chỗ trống này.

## Buổi 3 — Process ancestry và correlation

Đọc ProcessGuid/ParentProcessGuid trong Sysmon 1, ProcessGuid và Initiated trong Sysmon 3. Xem graph case 001 rồi case 005. Trong case 005, lần theo failed logon → success → process có session phù hợp → network → descendant schtasks.

Bài tập: chọn một edge, mở log gốc và chỉ ra trường tạo nên edge. Sau đó xem các variant thiếu GUID, parent chưa được thu thập, conflicting creation, IP khác hoặc Initiated=false.

Đáp án: không dùng PID hay khoảng thời gian gần nhau để thay cho GUID đã thiếu. Không có full chain không đồng nghĩa hoạt động an toàn. Chain hoàn chỉnh cũng chưa tự xác nhận compromise.

## Buổi 4 — Detection engineering và đánh giá sai số

Phân biệt event rule, auth correlation và chain policy. Đọc rule requirement, false positive và blind spot. Hiểu vì sao context allowlist vẫn giữ finding thay vì xóa dấu vết.

Bài tập: tự tính precision = TP/(TP+FP), recall = TP/(TP+FN). Holdout của graph có TP=2, FP=1, TN=3, FN=2: precision 66,7%, recall 50%. So với baseline username/time, graph ít false positive hơn nhưng baseline có F1 cao hơn trên bộ nhỏ này.

Đáp án phỏng vấn: không tuyên bố thuật toán graph tốt hơn trong mọi tình huống. Các fixture có quan hệ với nhau và không đại diện cho toàn bộ môi trường doanh nghiệp. V3 tối ưu truy vấn tương quan, không sửa threshold để làm đẹp kết quả holdout.

## Buổi 5 — Threat hunting theo giả thuyết

Đọc tám câu hỏi trong Hunt notebook. Tách “returned rows”, số nhóm và số event gốc. Một kết quả rỗng cần kiểm tra coverage: ví dụ không có Sysmon 13 trong các collection này không chứng minh registry persistence không xảy ra.

Bài tập: chọn HUNT-02, đọc SQL join và so sánh với graph engine. Chỉ ra một điều graph kiểm tra chặt hơn. Đọc HUNT-06 trên supplement: 294 quan sát, 41 target account; giải thích vì sao chưa thể gọi tất cả là password failure.

Viết một hunt note ngắn: giả thuyết, nguồn, truy vấn, quan sát, giải thích khác, bằng chứng cần bổ sung. Đừng bắt đầu từ một câu kết luận “đã bị hack” rồi tìm log để minh họa.

## Buổi 6 — PowerShell forensics

Mở case 003. Đọc toàn bộ ScriptBlockText, không chỉ IEX/downloadString. Xem parser AST ghi nhận 0 command và 0 member invocation cho đoạn public bị quote. Đối chiếu với module log Out-Default trong report.

Bài tập: đọc ba nhóm fragment: complete, missing và conflict. Thử sắp part theo số thứ tự. Giải thích vì sao conflict không được tự chọn một bản cho tiện. Xem command Base64 được decode thành text, rồi xem AST của text đó.

Đáp án: decode không phải execute; AST node không phải execution trace. Muốn kết luận runtime cần ngữ cảnh process, session/module, network và endpoint. Không chạy lệnh lấy từ log hoặc payload public để “chứng minh” điều chưa thu thập.

## Buổi 7 — Loki, LogQL và Grafana thật

Khởi động backend bằng runbook. Tự chọn Replay run và time range trên dashboard. Phân biệt original time với replay-now time. Nhãn stream hỗ trợ tìm collection; GUID và command nằm trong JSON để tránh tạo quá nhiều stream.

Bài tập: đọc một LogQL count và một UID pivot trong backend-validation.json. Chỉ ra request time bounds, expected count và actual response. Giải thích vì sao POST thành công chưa đủ: lịch sử ingest/query cần chunk flush và index resync trong cấu hình filesystem lab này.

Đáp án: project đã chạy LogQL trên Loki thật. KQL/SPL chỉ là reference chưa chạy trên backend tương ứng. Grafana này là dashboard replay; detector Python vẫn là pipeline phân tích riêng, chưa phải hệ thống cảnh báo liên tục.

## Buổi 8 — Triage, escalation và evidence packet

Thử mở một case từ record đã chọn. Ghi rationale rồi chuyển triaged → investigating → escalated. Gắn thêm 4698 và giải thích điều nó thay đổi. Đọc packet revision 5 với 10 anchors.

Bài tập: viết escalation gồm collection boundary, bằng chứng đã xác nhận, điều chưa biết, severity có lý do và yêu cầu bằng chứng tiếp theo. Phân biệt schtasks /Create, event đăng ký task và bằng chứng task thực chạy.

Đáp án: case mô phỏng có evidence đăng ký task, chưa chứng minh task execution hay payload behavior. Các containment step chỉ là đề xuất; lab không cô lập máy hay chặn địa chỉ IP. Đóng case cần verdict và rationale, không bấm đóng chỉ vì dashboard ít alert.

## Buổi 9 — Integrity, concurrency và giới hạn bảo vệ

Hiểu revision conflict: hai lần sửa cùng revision không được cùng ghi đè. Đọc audit payload, previous hash và final anchor. ZIP manifest kiểm tra từng file; export không ghi đè cùng revision.

Bài tập: ở workspace dùng cho thử nghiệm, sửa một audit row rồi chạy kiểm tra và quan sát lỗi. Dùng file copy riêng; giữ export đã review. Giải thích vì sao người có toàn quyền SQLite vẫn có thể viết lại toàn bộ chain và case.

Đáp án: hash chain không phải chữ ký số hoặc chứng minh danh tính analyst. Actor là nhãn tự khai. Muốn dùng nhiều người thật cần authentication, authorization, lưu anchor độc lập và quy trình quản lý bằng chứng rộng hơn.

## Buổi 10 — Performance, CI và demo phỏng vấn

Đọc benchmark v2/v3: cùng workload 1.200 log, 200 incomplete candidates, sáu process độc lập và cùng output digest. Median giảm khoảng 1,53 s xuống 0,046 s. Phân biệt thời gian hàm investigate với RAM toàn máy và throughput backend.

Bài tập: chuẩn bị demo 8 phút: kiến trúc và scope (1 phút), graph case 005 (2), một counterexample/holdout miss (1), Loki query và timestamp (1), PowerShell string/AST (1), decision/export (1), giới hạn và cải tiến tiếp theo (1).

Tập trả lời: “Vì sao em dùng SQLite?”, “Em đã chạy backend gì thật?”, “Nguồn nào là synthetic?”, “Em biết rule sai ở đâu?”, “4698 chứng minh gì?”, “Ai có thể viết lại audit?”, “Tại sao bộ baseline có F1 cao hơn?”. Nếu chưa tự giải thích được, quay lại log và code thay vì học thuộc câu trả lời.

## Điều kiện sẵn sàng đưa vào CV

Bạn tự replay được project, điều tra được ít nhất một case public, giải thích được một false positive và một false negative, và tự viết lại escalation bằng lời của mình. Giữ nhận định cụ thể trong CV: log engineering, detection validation, hunting, static forensics, actual Loki queries và local analyst workflow. Không chuyển những bằng chứng lab này thành kinh nghiệm production chưa có.
