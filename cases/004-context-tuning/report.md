# CASE-004 — Giảm hàng chờ review nhưng giữ nguyên finding

Tôi dùng bốn record tự dựng để kiểm một thay đổi tuning: backup context biết trước có được ghi nhận mà không che các biến thể user, parent và command không? Baseline có bốn finding trên ba event. Profile chính xác ghi chú một finding là `context_allowlisted`, để ba finding còn lại cần review. Cả bốn vẫn ở findings.jsonl cùng evidence references.

## Điều kiện thử nghiệm

`data/fixtures/context-tuning.jsonl` được tạo bởi `scripts/build_context_case.py`. Host, user, GUID, time và mã thay đổi đều giả lập. Generator ghi command thành string, không chạy PowerShell.

Context yêu cầu host `WS-TUNING-LAB`, user `LAB\backup.svc`, Windows PowerShell executable, parent `taskeng.exe` và full command `powershell.exe -ExecutionPolicy Bypass -File C:\Lab\backup.ps1`. `SYNTHETIC-CHANGE-004` là mô tả fixture, không phải approval của công ty.

## So sánh từng record

| Record / dòng | Biến thể | Baseline | Có context |
| --- | --- | --- | --- |
| 2000 / 1 | Đúng user, parent, command backup | WIN-002 review | Annotate expected context, giữ finding |
| 2001 / 2 | Cùng path/command, user khác và explorer parent | WIN-002 review | Vẫn review |
| 2002 / 3 | Có thêm EncodedCommand | WIN-001 và WIN-002 review | Cả hai vẫn review |
| 2003 / 4 | Inventory command không bypass/encoding | Không match | Không match, chưa có safety verdict |

Tôi tránh loại bỏ mọi PowerShell của service account vì sẽ mất các biến thể có ích. Profile bind từng trường chính xác; correlation finding không dùng annotation single-event này. Manifest giữ context hash, finding giữ ID/reason/change reference. Bỏ profile rồi chạy lại có thể khôi phục baseline từ cùng nguồn.

## Điều profile chưa kiểm được

Nội dung backup.ps1 có thể bị thay mà command giữ nguyên. Path/user/parent không xác minh content, signature, thời hạn phê duyệt hoặc tính hợp lệ của process cha. Để dùng trong vận hành cần nguồn đáng tin cậy cho script và approval; fixture chưa cung cấp thẩm quyền ấy.

Record 2002 đặt EncodedCommand sau `-File`. Tùy cách PowerShell nhận argument, nó có thể là tham số script chứ không phải host switch. Rule substring vẫn match. Tôi dùng record này để kiểm boundary command thay đổi, không nói encoded payload đã chạy.

## Kết quả và tái lập

Trong scenario biết trước, exact expected finding có thể được đóng bằng quyết định có lý do; hai event thay đổi context vẫn cần review. Bốn finding không phải bốn incident. Giảm từ bốn xuống ba ở fixture này chưa đo false-positive reduction trong SOC thực tế.

`scripts/reproduce.ps1` tạo cả baseline và contextual bundles. Đối chiếu findings_by_status, records 2000–2003 và `rules/context-lab.json`. Regression thay từng trường ràng buộc, kiểm finding gốc không mất. [Bản tiếng Anh đã lưu](report.en.md) giữ chi tiết trước biên tập.
