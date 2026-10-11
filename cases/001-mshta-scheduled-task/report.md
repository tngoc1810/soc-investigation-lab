# CASE-001 — Từ mshta đến lệnh tạo scheduled task

Điểm đáng chú ý trong collection này là chuỗi `cmd → rundll32 → mshta → schtasks`, kèm kết nối mạng của process mshta và một file được tạo trong thư mục task của Windows. Tôi đánh giá đây là hoạt động đáng chuyển cấp để điều tra. Bằng chứng đủ rõ về quan hệ process, nhưng chưa đủ để xác nhận payload đã chạy hay task đã thực thi định kỳ.

## Nguồn và phạm vi

Tôi phân tích một mẫu EVTX công khai của [Yamato Security](https://github.com/Yamato-Security/hayabusa-sample-evtx), có nguồn gốc từ [SBousseaden](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES). [File gốc tại commit cố định](https://github.com/Yamato-Security/hayabusa-sample-evtx/blob/0845333ecb4afcf64c55c6e10946383f168f308c/EVTX-ATTACK-SAMPLES/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx) có SHA-256 `fb5679aec77dc45a35902f705b513811dfea0f2f93c9c8503464a20270c3222f`.

Host là `IEWIN7`, user process là `IEWIN7\IEUser`. File có tám Sysmon event: bốn process creation (1), ba network connection (3), một file creation (11). Thời gian System/TimeCreated trải từ 21/05/2019 15:32:57.286254 đến 15:33:01.141798 UTC. XML giữ precision gốc; timeline chuẩn hóa đến microsecond.

Bản JSONL dùng ở lần phân tích đã lưu có SHA-256 `ed4ca4495a28b76afca39aa837dae4cfb8524e019714b494b5160d4fec7421b4`. Hash export có thể khác giữa serializer/platform; khi tái lập cần giữ manifest của lần chạy mới. Collection không có Security 4698, task XML, task operational history, nội dung file hay hồ sơ thay đổi được duyệt. Đây là dữ liệu lịch sử của tác giả mẫu, không phải sự cố trên máy của tôi.

## Những gì tôi đối chiếu

| Giờ UTC | Dòng / record | Quan sát | Nhận định |
| --- | --- | --- | --- |
| 15:32:57.286254 | 1 / 4125 | cmd có rundll32, JavaScript và lời gọi mshta với URL | Cần kiểm tra chuỗi thực thi; command text chưa chứng minh mọi thao tác thành công |
| 15:32:57.286254 | 2 / 4126 | ParentProcessGuid của rundll32 trỏ đúng GUID của cmd | Có quan hệ cha-con dù timestamp hiển thị bằng nhau |
| 15:32:57.867089 | 3 / 4127 | mshta trỏ tới hxxps://hotelesms[.]com/talsk.txt, parent là rundll32 | WIN-004 khớp; cần nội dung tải về và bối cảnh sử dụng |
| 15:32:59.389278 | 4 / 4128 | GUID mshta có kết nối TCP tới 108[.]179[.]232[.]58:443 | Có hoạt động mạng của process; chưa có nội dung phản hồi |
| 15:32:59.769825 | 5 / 4129 | schtasks, parent mshta, có /Create /sc MINUTE /MO 60 /TN MSOFFICE_ và action mshta URL | Có yêu cầu tạo task lặp lại; WIN-008 khớp |
| 15:32:59.809883 | 6 / 4130 | svchost tạo C:\Windows\System32\Tasks\MSOFFICE_ | Hỗ trợ giả thuyết đăng ký task; chưa đọc được định nghĩa hay lịch sử thực thi |
| 15:33:00.140358 | 7 / 4131 | Cùng GUID mshta nối 105[.]73[.]6[.]112:80 | Có thêm kết nối; payload time không thống nhất System time |
| 15:33:01.141798 | 8 / 4132 | Cùng GUID mshta nối 105[.]73[.]6[.]105:80 | Giữ cùng giới hạn thời gian |

Tôi dùng GUID ghi trong từng event để nối process, không dùng việc chúng xuất hiện gần nhau. cmd có GUID `{365abb72-1a29-5ce4-0000-001054e32101}`, rundll32 `{365abb72-1a29-5ce4-0000-00107be42101}`, mshta `{365abb72-1a29-5ce4-0000-001079f92101}`, schtasks `{365abb72-1a2b-5ce4-0000-00102f502201}`. File event của svchost có GUID khác; tên file và thời gian hỗ trợ quan hệ với task, không tạo ra một cạnh cha-con mới.

## Chỗ tôi chưa thể giải thích

Record 4128 có System time `15:32:59.3892786Z` nhưng EventData.UtcTime là `06:58:39.888` cùng ngày. Hai record mạng sau cũng lệch nhiều giờ. Collection không giải thích nguyên nhân. Tôi giữ cả hai giá trị, dùng System time thống nhất cho timeline và không tự sửa theo giả định timezone. GUID vẫn giúp liên hệ process; thời lượng và thứ tự mạng chính xác cần nguồn bổ sung.

## Quyết định và phần cần bổ sung

Giả thuyết chính là thực thi nội dung từ xa rồi tạo persistence bằng task. Các hành vi liên quan T1218.005/T1053.005; rundll32 là hướng hunting T1218.011, chưa phải coverage đã kiểm đủ. Một bài kiểm thử được phép hoặc hệ thống HTA cũ cũng có thể tạo một phần mẫu này.

Nếu tiếp nhận tương tự trong SOC, tôi đề xuất chuyển cấp cùng chuỗi GUID, file artifact và giới hạn collection. Mức high chỉ là đề xuất chờ xác minh tài sản, account và tác động. Cần task XML/history, process/script/AV telemetry, nội dung đã thu nhận an toàn, change record và network log có thời gian đáng tin cậy. Tám event không chứng minh credential theft, exfiltration hoặc malware family.

Việc giữ bằng chứng, đề nghị cô lập host hoặc xóa task sau khi xác minh trái phép là phương án xử lý, chưa phải thao tác đã làm. Phải tính ảnh hưởng dịch vụ, quyền phê duyệt, cấu hình trước thay đổi và cách phục hồi. Các indicator lịch sử được làm mất khả năng bấm nhầm; tôi không truy cập chúng hay gán reputation hiện tại.

## Thay đổi detection từ case này

Ban đầu WIN-004 tìm thấy mshta nhưng WIN-005 không tạo finding vì rule cần Security 4698/TaskContent mà file không có. WIN-008 bổ sung Sysmon 1 cho schtasks.exe, `/Create` và nội dung script interpreter. Sau thay đổi, record 4129 được giữ thành finding riêng.

| Kiểm tra | Trước | Sau |
| --- | --- | --- |
| mshta URL trong file công khai | 1 | 1 |
| Lệnh tạo task trong file công khai | 0 | 1 |
| Fixture schtasks /Query có script text | Chưa áp dụng | 0 |
| Fixture backup task dùng script | Chưa áp dụng | 1 finding cần context |

Các phép kiểm này chứng minh hành vi rule trên mẫu cụ thể; chưa đo false-positive rate hay recall toàn kỹ thuật. WIN-008 cũng không bao phủ mọi cách tạo task qua API/COM.

Tái lập và đường dẫn DB thực tế nằm trong [runbook](../../docs/OPERATIONS.md). Tôi pivot theo `schtasks`, Event ID 3 và GUID mshta; giữ original JSON/XML, source hash và physical line để kiểm lại từng nhận định. [Bản tiếng Anh đã lưu](report.en.md) giữ nguyên hồ sơ trước đợt biên tập.
