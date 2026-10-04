# Hướng dẫn học project từ đầu

Project đã được xây dựng và kiểm chứng dưới dạng casebook offline. Phần học dưới đây giúp bạn hiểu các quyết định, chạy lại bằng chứng và trình bày trong phỏng vấn. Không cần học thuộc toàn bộ code trước khi bắt đầu.

## Buổi 1 — Hiểu luồng dữ liệu

EVTX là định dạng Windows lưu event log. Exporter đọc file bằng API Windows, giữ XML và chuyển các field sang JSONL: một dòng là một event. Python kiểm tra schema, chuyển thời gian hiển thị sang UTC và lưu SQLite. Detection đọc các event để tạo lead; analyst dùng bằng chứng để kết luận.

Ba lớp cần tách biệt:

| Lớp | Ví dụ | Điều có thể kết luận |
| --- | --- | --- |
| Event | Process mshta được tạo với một command line | Hành vi đã được nguồn log ghi nhận |
| Alert/finding | Rule thấy mshta cùng URL HTTP | Cần điều tra ngữ cảnh |
| Incident assessment | Chuỗi process, artifact và ngữ cảnh hỗ trợ nghi ngờ | Analyst quyết định chuyển cấp, đóng hoặc yêu cầu thêm dữ liệu |

Một alert không tự biến thành incident. Một event không alert cũng không tự trở thành an toàn. Vì vậy timeline chứa cả các event không trigger rule.

Hãy mở case 001. Tìm event 4127 trong timeline và findings. Đối chiếu Image, CommandLine, ParentProcessGuid, source hash và số dòng. Bạn phải chỉ ra được event gốc hỗ trợ mỗi câu trong kết luận.

## Buổi 2 — Điều tra process và persistence

PID có thể được hệ điều hành sử dụng lại. ProcessGuid của Sysmon giúp liên kết các event của một process; vẫn cần cùng host và cùng kịch bản. ParentProcessGuid nối process con với process cha nếu bằng chứng cha có trong collection.

Case 001 có cmd → rundll32 → mshta → schtasks. Network event dùng GUID của mshta. File task do svchost tạo có GUID khác: liên hệ tên task/thời gian hỗ trợ giả thuyết, nhưng không phải quan hệ cha-con trực tiếp.

Phân biệt ba điều: lệnh yêu cầu tạo task; task object/artifact tồn tại; task thực sự chạy. Case này hỗ trợ hai điều đầu ở mức khác nhau, chưa xác nhận điều cuối. Security 4698 không có trong file, nên rule cần 4698 không đánh giá được. WIN-008 dùng observable khác trong Sysmon 1.

Đừng coi ngày giờ gần nhau là đủ để nối hai hành vi. Các network payload timestamp trong case 001 lệch nhiều giờ so với System/TimeCreated. Giữ cả hai và ghi giới hạn thay vì tự sửa để có timeline đẹp.

## Buổi 3 — Authentication

4625 là failed logon, 4624 là successful logon, 4648 là dùng credential được chỉ định rõ. 4648 không nói credential đó đúng hay sai.

Subject là ngữ cảnh tạo event; target là account được dùng/được thử. Logon type 3 là network logon, type 2 là interactive. Domain và source IP giúp tránh ghép các account/source khác nhau. Status/SubStatus cho biết kiểu lỗi; không nên gom mọi failure thành sai password.

Case 002 có 3.561 failure, không có success. AUTH-001 không trigger vì giả thuyết của nó cần success; AUTH-002 giải quyết burst failure. Không sửa rule bằng cách tự thêm event success vào dữ liệu để có một câu chuyện đẹp hơn.

Supplement có nhiều 4648 cho các target account khác nhau, nhưng là host và năm khác. Giữ độc lập. Gọi đây là lead giống spraying, không xác nhận cùng password đã được dùng hoặc authentication thất bại.

Thực hành: chạy auth_summary, đọc từng nhóm user/domain/IP/logon type/substatus. Sau đó giải thích tại sao 3561 events chỉ tạo một burst finding và tại sao một finding giữ mười event không phải toàn bộ số lần thử.

## Buổi 4 — PowerShell và syntax

Base64 là cách biểu diễn dữ liệu, không phải bằng chứng độc hại. Giải mã một chuỗi để đọc khác với chạy nội dung đã giải mã. Không cần thực thi command lịch sử để điều tra project này.

Case 003 có từ IEX và downloadString, nhưng biểu thức nằm trong dấu nháy kép. Event 4103 có Out-Default với InputObject bằng chuỗi đó. Chạy check_literal.ps1: AST chứa StringConstantExpressionAst và output là chữ. Lệnh download không được gọi trong thí nghiệm.

Đây là lý do WIN-009 chỉ tạo review lead. Một rule substring không phân biệt code với literal. Nếu ScriptBlockText bị chia nhiều phần, các keyword còn có thể nằm ở event khác nhau; cần thu đủ MessageNumber/MessageTotal và ngữ cảnh trước khi nâng cấp engine.

## Buổi 5 — Tuning và kiểm thử

Case 004 bắt đầu với bốn finding. Profile exact-match kiểm tra host, user, image, parent và toàn bộ command. Một finding được đánh dấu context_allowlisted; ba finding vẫn cần review. Finding cũ và bằng chứng vẫn được giữ.

Không dùng ngoại lệ rộng kiểu bỏ qua mọi PowerShell của backup.svc. Chỉ một field thay đổi cũng phải được đánh giá lại. Tuy vậy, cùng command mà nội dung backup.ps1 bị đổi vẫn có thể khớp: profile không kiểm tra script content. Đây là giới hạn cần nói được trong phỏng vấn.

Một lưu ý syntax: phần thêm sau -File có thể là argument của script, không phải switch của PowerShell host. Fixture chỉ kiểm tra biên của substring/context matching; nó không chứng minh encoded payload thực sự đã chạy.

Kiểm thử cần positive, benign và lookalike. Test tốt kiểm tra sai lầm có thể làm điều tra lệch: ghép nhầm host/source, xóa evidence, quá ngưỡng thời gian, broad allowlist hoặc đọc keyword thành execution. Không lấy vài fixture để tuyên bố precision/recall ngoài thực tế.

## Buổi 6 — Code, query và giới hạn

Đọc lần lượt events.py → store.py → detections.py/correlation.py → context.py → report.py → webapp.py. SQLite dùng parameterized filters; query pack chỉ chạy các truy vấn đã check-in trên connection read-only. Web UI dùng textContent để hiển thị command như dữ liệu và chỉ bind localhost.

Sigma là format rule dùng để chia sẻ logic. Parse thành công chưa xác nhận mapping của SIEM. KQL dùng WindowsEvent fields; SPL cần JSON sourcetype mapping. Fixed time bins của KQL không hoàn toàn tương đương sliding window/cooldown của Python.

Benchmark đo process xử lý offline, không đo MTTD. MTTD trong một hệ thống live cần mốc hành vi, ingestion, detection và clock đáng tin cậy. Đừng dùng thời gian chạy Python để mô tả tốc độ SOC production.

## Chuẩn bị phỏng vấn

Với bản 2.0, học thêm case 005 sau sáu buổi trên. Mở Reconstruction, chọn mshta, đối chiếu LogonGuid với event 4624 rồi dùng ProcessGuid để tìm network event. Giải thích vì sao ba file được ghép trong case này nhưng các case công khai vẫn độc lập. Trong Evaluation, tự chọn một FP và một FN, chỉ rõ engine biết gì, thiếu gì và vì sao F1 của baseline lại cao hơn. Đây là phần cần phản biện, không phải học thuộc một con số accuracy.

Chọn hai case bạn hiểu rõ, giải thích theo thứ tự: câu hỏi → evidence → giả thuyết thay thế → quyết định → thiếu gì → cải thiện rule. Thừa nhận phần được Codex hỗ trợ và nêu việc bạn đã kiểm tra/thay đổi sau đó. Nhà tuyển dụng có thể hỏi rất cụ thể một event; hiểu bằng chứng sẽ hữu ích hơn học thuộc report.
