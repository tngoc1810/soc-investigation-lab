# CASE-005 — Kiểm tra log authentication có thuộc cùng process chain không

Tôi dùng một collection tự dựng gồm Security và Sysmon được sinh cùng scenario để kiểm identity join. Collection có 2.511 event: bảy Security trên `WS-CHAIN-LAB`, bốn Sysmon trên host đó và 2.500 logoff inert trên `QUIET-WS-LAB`. Command không được thực thi; noise chỉ tạo nền cho truy vấn, không phải hàng nghìn compromise hay một phép đo tải lớn.

## Câu hỏi và ranh giới nguồn

Tôi kiểm failure và success có cùng authentication context trước, rồi mới nối success với process bằng session identity. Username giống nhau hoặc hai event gần thời gian chưa đủ. Scope duyệt ba exact source hash; nguồn chưa duyệt, nguồn khai báo nhưng thiếu và scope không giải thích được đều bị reject.

Scope nói các nguồn được thu trong cùng fixture, không phải authorization chạy command hoặc verdict malicious. Domain dùng `example.invalid`, IP thuộc documentation ranges. Public cases độc lập không được ghép vào chuỗi này.

## Chuỗi đã dựng lại

| UTC ngày 03/09/2026 | Nguồn / record / dòng | Quan sát và điều kiện nối |
| --- | --- | --- |
| 10:00:00–04 | chain-security / 100–104 / 1–5 | Năm 4625 cùng host, account/domain, IP và network logon type |
| 10:00:05 | chain-security / 105 / 6 | 4624 khớp context; giữ nonzero LogonGuid và TargetLogonId |
| 10:00:06 | chain-sysmon / 106 / 1 | cmd có cùng domain-qualified user, LogonGuid, LogonId |
| 10:00:07 | chain-sysmon / 107 / 2 | mshta URL, ParentProcessGuid bằng GUID cmd đã thấy |
| 10:00:08 | chain-sysmon / 108 / 3 | Initiated connection mang ProcessGuid mshta |
| 10:00:09 | chain-sysmon / 109 / 4 | schtasks /Create /TR là descendant quan sát được |
| 10:00:10 | chain-security / 110 / 7 | 4698 LabUpdater, subject logon ID khớp success |

CHAIN-001 dùng năm bước failures, success, risky process, initiated connection, descendant task command. 4698 là evidence thêm cho analyst; engine chưa parse task XML hoặc tự bind task đăng ký với lần chạy sau. Kết quả có ba process node, hai parent edge, một complete chain và bốn event/auth findings riêng.

Tôi giữ source hash/physical line và original object sau khi dựng graph. GUID thiếu hoặc zero không được thay bằng username/PID. Ngữ nghĩa identity theo [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) và [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## Dữ liệu thiếu và kết quả không thuận lợi

D12/H05 có approved intent theo người tạo fixture nhưng vẫn tạo chain vì engine chưa có trusted approval context: chúng được giữ như false positives. H03 thiếu nonzero success GUID, H04 thiếu descendant task process nên chỉ tạo incomplete candidate dù có attack intent trong label. Tôi giữ missing requirements để đề nghị bổ sung log, không gọi host an toàn.

Exact overlapping observations được đếm một lần trong scope rõ ràng, vẫn giữ multiple source references. Record ID dùng lại với content khác được giữ riêng. Hai process-creation record xung đột cùng host/GUID làm node đó không đủ điều kiện causal join.

| Holdout gồm tám scenario | Graph | Baseline username/time |
| --- | --- | --- |
| TP / FP / TN / FN | 2 / 1 / 3 / 2 | 4 / 3 / 1 / 0 |
| Precision / recall / F1 | 66,7% / 50,0% / 57,1% | 57,1% / 100% / 72,7% |

Tôi giữ kết quả graph F1 thấp hơn baseline. Graph trả lời câu hỏi có bằng chứng nối cụ thể nhưng nhạy với telemetry thiếu. Đây là tám related constructed variants, chưa phải field accuracy. Policy cố định trước đo, evaluator nhận event/scope chứ không nhận label/rationale; development và holdout đều được version.

## Quyết định và yêu cầu tiếp theo

Tôi đề xuất chuyển cấp chuỗi để xác minh account/host. Cần source authentication context, ownership, task XML/execution telemetry, downloaded content, network transaction và change approval. TCP event không cho biết URL trả nội dung gì; fixture chưa chứng minh business impact, credential theft, lateral movement hoặc exfiltration.

Giữ acquisition, scope, graph và stage references trước thay đổi. Các phương án ứng phó trong hồ sơ chưa được thực thi. [Runbook](../../docs/OPERATIONS.md) mô tả rebuild/explorer/evaluation; [bản tiếng Anh đã lưu](report.en.md) giữ chi tiết gốc.
