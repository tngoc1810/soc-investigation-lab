# CASE-003 — Text có IEX chưa đủ để kết luận downloader đã chạy

Điểm khiến tôi giữ verdict mở là dấu ngoặc kép quanh toàn bộ biểu thức `IEX(New-Object Net.WebClient).downloadString(...)`. Keyword search thấy dấu hiệu download/evaluate, nhưng record 4103 đi kèm có `Out-Default` nhận chính text ấy. Bằng chứng nghiêng về việc in ra một string; file chưa chứng minh có download hoặc thực thi nội dung tải về.

## Nguồn và context

File `ID4103-4104-Payload download via PowerShell.evtx` nằm trong [sample cố định](https://github.com/Yamato-Security/hayabusa-sample-evtx/tree/0845333ecb4afcf64c55c6e10946383f168f308c/EVTX-to-MITRE-Attack/TA0002-Execution/T1059.001-PowerShell), có credit gốc [JPCERT/CC](https://github.com/JPCERTCC/EVTX-to-MITRE-Attack). SHA-256: `76da739520ecfb51c0bc93a5856ff45c0cd5e038114826fee30790f92fce0fca`.

Host `fs03vuln.offsec.lan`. Ba record cùng System time 24/01/2022 20:11:11.361955 UTC, gồm hai 4104 và một 4103. ContextInfo ghi ConsoleHost, Windows PowerShell 4.0 và `OFFSEC\admmig`; đó là context lịch sử, không phải user vận hành repo này.

## Tôi đọc các record cùng nhau

| Dòng / record | Nội dung | Nhận định |
| --- | --- | --- |
| 1 / 83421, 4104 | String trong double quotes chứa IEX/WebClient/downloadString | WIN-009 khớp text; quoting ảnh hưởng cách diễn giải |
| 2 / 83422, 4103 | CommandInvocation(Out-Default), InputObject bằng biểu thức trên | Hỗ trợ giả thuyết text được xuất ra |
| 3 / 83423, 4104 | ScriptBlockText là prompt | Chưa có download trong record này |

URL trong string trỏ ảnh PNG trên image host công khai. Tôi giữ đây là text quan sát được, không truy cập URL hay gán reputation. Timestamp bằng nhau không chứng minh thứ tự thực thi chính xác. Hai 4104 có ScriptBlockId khác nhau; context user/runspace của 4103 không tự động xác thực identity của mọi 4104 gần đó.

Theo [Microsoft về PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1), log có script text. Việc một token tồn tại trong text không chứng minh phương thức tương ứng đã được gọi.

## Kiểm tra cú pháp và giới hạn

WIN-009 vẫn giữ một finding. Tôi giữ both quoted-data và executable-text fixtures vì substring detection chưa giải quyết được ngữ nghĩa. Chạy AST parser giúp phân biệt node cú pháp; bản thân một command/member AST vẫn chưa chứng minh thực thi.

`scripts/check_literal.ps1` dùng biểu thức inert với `example.invalid`, parse node và in string, không evaluate network expression. Phép kiểm giải thích vì sao cùng từ khóa có thể xuất hiện như dữ liệu; không thay thế nguồn của sample lịch sử. Pipeline forensics còn giữ MessageNumber/MessageTotal, thiếu fragment hoặc conflict thay vì ghép tùy ý.

## Quyết định của tôi

Tôi chưa xác nhận incident downloader. Cần original script, đầy đủ message parts, runspace/session logs, process creation và network telemetry để xác minh hoạt động thực tế. Ba record chưa đủ để khẳng định cả session benign. Riêng keyword match không phải căn cứ thực hiện containment.

Case này thể hiện sự khác nhau giữa detection text và kết luận hành vi. [Runbook](../../docs/OPERATIONS.md), [forensics](../../docs/POWERSHELL_FORENSICS.md) và [bản tiếng Anh đã lưu](report.en.md) giữ đường tái lập/phạm vi gốc.
