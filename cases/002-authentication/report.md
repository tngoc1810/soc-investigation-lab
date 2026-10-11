# CASE-002 — Đăng nhập thất bại dồn dập, chưa có bằng chứng truy cập thành công

Collection chính có 3.561 Security 4625 trong khoảng 163 giây. Trong đó 3.560 lần nhắm vào Administrator; mọi record cùng địa chỉ nguồn. Tôi đánh giá mẫu này cần điều tra về hoạt động đoán mật khẩu hoặc client lỗi. Không có 4624 trong file nên tôi giữ kết quả truy cập là chưa xác định.

## Collection tôi sử dụng

Nguồn là `DeepBlueCLI/smb-password-guessing-security.evtx` trong [Yamato sample collection tại commit cố định](https://github.com/Yamato-Security/hayabusa-sample-evtx/tree/0845333ecb4afcf64c55c6e10946383f168f308c/DeepBlueCLI); tác giả gốc là [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI). SHA-256 EVTX: `19202585fe053e7b0acf43458dec26957c16a2ddb6f87a21f5f85e6cba98b89c`.

Host `DESKTOP-M5SN04R`, source `192.168.198.149`, logon type 3. System time từ 19/09/2016 16:50:06.477878 đến 16:52:49.399674 UTC. Record ID trải từ 2455 đến 6016; số record trong collection là 3.561, không suy số lượng bằng phép trừ ID.

Substatus gồm một `0xc0000064`, 3.558 `0xc000006a` và hai `0xc0000072`: lần lượt liên quan user không tồn tại, sai mật khẩu và account bị disabled theo [tài liệu Microsoft 4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625). Tôi giữ nhóm account/domain/source/logon type/substatus khi query để không làm mất bối cảnh trong một con số tổng.

## Vì sao tôi tách AUTH-002 khỏi AUTH-001

AUTH-001 tìm failures rồi success, vì vậy không tạo finding ở file chỉ có failures. Đó là kết quả đúng với điều kiện của rule, nhưng chưa mô tả được burst trước mắt. Tôi bổ sung AUTH-002: ít nhất mười failed network logon cùng source file, host, target account/domain, source IP và logon type trong năm phút. Cooldown năm phút tránh tạo một finding cho từng lần thử.

| Giờ UTC | Record / dòng | Quan sát |
| --- | --- | --- |
| 16:50:06.477878 | 2455 / 1 | Unknown-user failure nhắm account khác |
| 16:50:06.513129 | 2456 / 2 | Administrator failure đầu tiên trong threshold evidence |
| 16:50:06.977120 | 2465 / 11 | Lần Administrator thứ mười, đủ AUTH-002 |
| 16:52:49.399674 | 6016 / 3561 | Failure cuối của collection |

Mười record trong finding chứng minh threshold; truy vấn toàn collection mới cho số 3.561. Tốc độ và mức tập trung phù hợp với hoạt động tự động, nhưng chưa xác định người thực hiện, mật khẩu sử dụng hoặc tính được phép. Credential cũ, service cấu hình sai hay client lặp retry vẫn là giả thuyết cần kiểm.

## Supplement được giữ riêng

File `DeepBlueCLI/password-spray.evtx` có 295 record trên `DESKTOP-JR78RLP` tháng 04/2019: một Security 1102 và 294 Security 4648. Nó khác host/ngày/collection với burst năm 2016; tôi không dùng supplement để lấp chỗ thiếu 4624 của case chính.

Các 4648 có 41 target username thuộc domain DOMAIN, cùng địa chỉ `172.16.144.128`, trải khoảng 315 giây. AUTH-003 tạo hai finding theo threshold mười account khác nhau trong năm phút và cooldown. WIN-007 giữ audit-log clear thành finding riêng.

[4648](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4648) là sử dụng credential tường minh, không phải kết quả authentication thất bại. Vì thế tôi mô tả multi-account credential-use lead; collection không cho phép khẳng định 294 failed logon hay cùng một password được spray.

## Bàn giao điều tra

Tôi đề xuất xác minh source asset/owner, client/service đang dùng credential, lockout/disabled-account context và 4624 cùng endpoint event trước/sau window. Cần xem dữ liệu ngoài file đã export trước khi kết luận outcome. Nếu cân nhắc containment thì phải xác minh phạm vi và tác động; chỉ riêng rule match chưa đủ để disable Administrator.

Supplement cần hồ sơ riêng về credential origin, audit clear và change context. Project chưa block địa chỉ hay thay đổi account. Distributed guessing, NAT, identity thiếu và export trùng vẫn có thể gây bỏ sót hoặc ghép nhầm.

[Runbook](../../docs/OPERATIONS.md) có lệnh tái lập và query `auth_summary`; validation giữ original/export hashes và rule counts. [Bản tiếng Anh đã lưu](report.en.md) giữ số liệu gốc.
