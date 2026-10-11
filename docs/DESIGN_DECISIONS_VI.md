# Những quyết định thiết kế trong dự án

Tôi ghi lại các lựa chọn này để khi đọc code có thể thấy cả lý do và đánh đổi. Các quyết định dựa trên implementation, case và kết quả đã giữ trong repo. Những ví dụ về SOC thực tế là bối cảnh thiết kế, chưa phải sự cố doanh nghiệp tôi đã xử lý.

## 1. Giữ hệ thống trong phạm vi một workstation

Máy mục tiêu có 8 GB RAM. Tôi chọn Python standard library, SQLite và PowerShell cho core, còn Loki/Grafana là backend native tùy chọn. Nhờ vậy có thể chạy phần evidence/detection/case mà chưa cần khởi động backend.

Đánh đổi là hệ thống chưa giải quyết fleet enrollment, HA hoặc multi-user access. Tôi không dùng con số working set lúc idle để cam kết RAM tối đa. Mutable database được đặt ở private cache của Windows; source ở OneDrive không đồng nghĩa DB đang ghi cũng nên ở đó.

## 2. Giữ acquisition trước khi diễn giải

Một timeline đã chuẩn hóa tiện cho query, nhưng không đủ để kiểm nguồn khi field bị hiểu sai. Tôi giữ original object/XML, source SHA-256 và physical line. Event UID gắn với byte export; observation fingerprint giải quyết poll overlap bằng identity/content trong scope.

Hai loại identity phục vụ hai câu hỏi: event nào ở file nào, và hai lần poll có quan sát cùng record không? Tôi không dùng riêng record ID vì channel có thể reset hoặc ID được dùng lại. Hash giúp đối chiếu một anchor đã giữ, chưa xác thực sensor hoặc ngăn filesystem owner viết lại tất cả dữ liệu.

## 3. Provider/channel là điều kiện rule

Event ID có nghĩa trong provider/channel của nó. Tôi yêu cầu ba thành phần trước khi xét nội dung. [Case 008](../cases/008-telemetry-readiness/report.md) có Sysmon provider/Event ID 1 ở sai channel để kiểm rằng record đó không tăng process coverage.

Đánh đổi là export thiếu provider/channel bị từ chối hoặc không match thay vì được đoán theo message text. Tôi chấp nhận mất coverage có giải trình hơn một join không có căn cứ.

## 4. Giữ finding riêng với kết luận incident

WIN-009 thấy download/evaluate text nhưng [case 003](../cases/003-powershell-string/report.md) cho thấy quoted string có thể khớp. Detection giữ dấu hiệu để analyst đọc; verdict cần ngữ nghĩa và evidence khác.

Tôi không đổi rule thành chỉ bắt executable-looking text rồi nhận là đã giải quyết false positives. AST parse cũng chưa chứng minh thực thi. Workflow giữ rationale, revision và trạng thái; đóng case không xóa source.

## 5. Không dùng thời gian gần nhau thay cho identity

[Case 005](../cases/005-multisource-chain/report.md) nối host, domain-qualified account, nonzero logon GUID, process GUID và ancestry được quan sát. Scope duyệt exact source set, tránh ghép public files độc lập thành một incident hấp dẫn nhưng sai.

Khi thiếu GUID hoặc parent, engine giữ incomplete candidate. Holdout graph F1 57,1% thấp hơn baseline 72,7% được công bố nguyên vẹn. Graph giúp giải thích quan hệ hẹp hơn, không chứng minh detection luôn tốt hơn.

## 6. Tuning có dấu vết thay vì xóa alert

[Case 004](../cases/004-context-tuning/report.md) annotate một exact backup context và giữ cả bốn findings. Profile phải khớp host/user/executable/parent/full command, kèm hash và lý do. Broad exclusion cho service account có thể che biến thể.

Đổi script content mà giữ command vẫn có thể qua profile. Vì thế expected context không thay cho script hash/signature và approval có thời hạn. Fixture change reference chưa có thẩm quyền doanh nghiệp.

## 7. Commit evidence, cursor và outbox cùng transaction

Nếu cursor tiến mà record chưa được lưu, restart có thể bỏ mất record. Nếu HTTP thành công nhưng acknowledgment chưa commit, retry có thể gửi lặp. Tôi lưu archive trước, rồi commit observation/outbox/cursor trong SQLite transaction.

Outbox giữ payload/time, lease, backoff và dead letter để phục hồi. Đây là at-least-once delivery; remote đã nhận mà local chưa biết vẫn có thể duplicate. Phép thử Loki HTTP 503/fresh-process recovery xác minh 19 unique UID trong controlled run, chưa đo endurance hay mọi failure mode của production.

## 8. Không chọn process chỉ vì tên có vẻ hợp lý

[Case 007](../cases/007-network-context/report.md) có hai Sysmon connection candidates, `backup.exe` và `unverified.exe`, cùng tuple/time. Tôi giữ cả hai. Source approval cho phép đưa nguồn vào phép nối; nó không xác định candidate nào là origin.

Muốn tăng confidence cần ProcessGuid/process creation, executable content và clock/capture vantage. NAT, proxy và shared IP có thể làm phép nối hiện tại không đủ. Asset criticality chỉ tăng ưu tiên review.

## 9. TCP thiếu byte thì dừng suy luận application

Parser xử lý supported sequence wrap/reorder/exact retransmission. Khi có gap hoặc conflicting overlap, tôi không ghép một request đẹp từ các byte không đủ căn cứ. Body hash chỉ được giữ theo framing hoàn chỉnh hỗ trợ.

Giới hạn là classic-PCAP/IPv4 và một phần DNS/HTTP/TLS. Chưa có TLS decryption, HTTP/2 hay continuous sensor. dpkt cross-check 81 public tuples/40 DNS/hai HTTP requests là kiểm protocol fields, chưa phải malicious classification.

## 10. Thiếu telemetry cần được hiện lên cùng alert

Không alert có thể do thiếu dữ liệu. Readiness đối chiếu asset/policy/provider/channel/Event ID, required fields, age, lag, clock và collector scope heartbeat. Backup asset không có event trong [case 008](../cases/008-telemetry-readiness/report.md) vẫn cần review.

Không có 4624 chưa chứng minh audit disabled; scope heartbeat mới chưa chứng minh mọi host sensor khỏe. Profile có expiry/exact source set; batch mới cần review nguồn mới. Đây là retained assessment, chưa phải policy monitor tự cập nhật liên tục.

## 11. Báo cáo đã giao phải quay lại đúng revision

Analyst review dùng optimistic revision để tránh ghi đè quyết định cũ bằng giao diện stale. Audit/export giữ anchor; snapshot/restore kiểm inventory và database integrity. Owner/actor hiện là nhãn khai báo, chưa phải IAM.

Readiness đọc current database state trong transaction. `as_of` chọn mốc đánh giá event/freshness/due time, không đưa database trở về một trạng thái lịch sử. SQLite reader có thể tạo SHM/WAL coordination, nên readonly proof không tuyên bố mọi file vật lý bất biến.

## 12. Người nhận cần tham chiếu nằm ngoài gói nhận được

v6.1 bổ sung kiểm gói readiness với manifest digest giữ độc lập. Nếu chỉ dùng manifest nằm cùng báo cáo, một bộ đã sửa và reseal vẫn tự nhất quán. Lệnh mới kiểm byte, inventory và render lại hai tài liệu từ JSON.

Tôi giữ riêng phạm vi: kiểm chuyển giao chưa phải đọc lại source acquisition, xác thực reviewer hay chữ ký số. Renderer khác có thể khiến kiểm byte HTML thất bại dù chỉ đổi formatting; đó là lý do phải giữ version phù hợp khi trao đổi bundle. [Thiết kế v6.1](ENGINEERING_V61.md) định nghĩa contract này.

## Những phần tôi sẽ cần thay trước khi dùng cho nhiều người

IAM/RBAC, authenticated sensor/asset inventory, retention/recovery objective, fleet capacity measurement, trusted approvals và ticket integration cần thiết kế riêng. Chúng không được coi là đã hoàn thành chỉ vì có trường owner, due time và dashboard. Phạm vi hiện tại cho phép kiểm đầy đủ hơn một số bài toán điều tra và lỗi vận hành trên một workstation.
