# Học từ byte gốc đến quyết định SOC

Bản v5 bổ sung network forensics và business-context triage. Đây là tài liệu thực hành, chưa phải learning log do bạn tự hoàn thành. Dữ liệu công khai và bài mô phỏng phải được giới thiệu đúng nguồn. Codex đã hỗ trợ viết mã và phân tích ban đầu; hãy dùng các bài dưới đây để biến artifact thành kiến thức của chính bạn.

## 1. Nguồn và độ tin cậy

Chạy validator với một run ID mới. Ghi PCAP SHA-256, số packet, thời gian đầu/cuối và giới hạn capture. Trích packet 4 từ capture HTTP, giải thích `record_offset`, `captured_bytes`, `wire_bytes`, frame hash và packet UID. Hash khớp có xác nhận tác giả capture hoặc việc không mất packet không?

Nộp: một bảng nguồn, packet trích xuất và đoạn nhận định về acquisition/coverage. Không viết "capture đầy đủ" khi chưa có sensor/drop counters.

## 2. Ethernet, IP và transport

Từ byte packet, tìm EtherType, IPv4 header length, protocol, IP nguồn/đích, port và TCP flags. Giải thích sự khác nhau giữa MAC, IP, port và process. Đọc diagnostics cho packet bị cắt, IP fragment và IPv6. Vì sao AAAA query có thể nằm trong packet IPv4?

Nộp: sơ đồ byte của một frame và một ví dụ câu hỏi không thể trả lời từ capture hiện có. Đừng đổi một diagnostic thành kết luận an toàn.

## 3. DNS

Trong capture công khai, chọn một query/response và đối chiếu ID, question, type/class, tuple, response code và time. Giải thích DNS compression pointer và vì sao phải chống pointer cycle. Theo chuỗi CNAME trong case HTTP đến A answer rồi TCP flow. Nêu ít nhất hai lý do đây mới là candidate association.

Nộp: timeline có packet numbers, tên, địa chỉ, TTL và giới hạn NAT/cache/shared-IP. TXT, SRV hay tên dài không tự động là malicious.

## 4. TCP

Trong exercise, request được ghi không đúng thứ tự và có retransmission. Giải thích cách sequence numbers khôi phục một request. Đếm packet bytes và application body bytes; vì sao hai số không giống nhau? Sáu SYN có chứng minh sáu session thành công không? ACK, SYN-ACK, FIN/RST và capture vantage bổ sung điều gì?

Nộp: một bảng sequence/length/packet, giải thích 70 byte lặp và một case thiếu/conflicting segment. Đọc test thay vì chỉ học thuộc kết quả.

## 5. HTTP và TLS

Đọc method, Host, URI, Content-Length và body hash của POST. Phân biệt declared size, captured complete body, response acceptance và data classification. Tự tạo counterexample có chuỗi `GET /fake HTTP/1.1` trong body: parser không được phát minh request mới. Nêu giới hạn chunked, HTTP/2, TLS encryption, SNI và certificate validation.

Nộp: kết luận quan sát upload kèm những bằng chứng còn thiếu để nói đến exfiltration. Không mở URL lấy từ capture.

## 6. Attribution qua endpoint

Đọc manifest scope và hai Sysmon candidate. Giải thích tại sao phải kiểm tra provider/channel, protocol, IP/port, clock và hash nguồn. Một candidate có đủ để khẳng định process không? Cần event 1/ProcessGuid, NAT map và capture-vantage evidence gì? Chạy một phiên riêng với protocol hoặc timestamp sai để kiểm tra pivot bị loại.

Nộp: giả thuyết backup, giả thuyết hoạt động không được duyệt, bằng chứng ủng hộ/phản bác và request cụ thể. Không ghép capture công khai với một case Windows khác chỉ vì gần tên hoặc thời gian.

## 7. Tuning và chất lượng detection

Đọc NET-001/002/003 và threshold. Bài backup/monitoring tạo cả ba lead: vì sao? Thiết kế ít nhất hai benign counterexample và hai suspicious review scenario; ghi nhãn trước khi chạy detector. Phân biệt label "cần review" với "đã xác nhận compromise". Không trình bày ba rule mới như benchmark độ chính xác.

Nộp: intent labels, điều kiện telemetry, outcomes, false positives/misses và blind spots. Giữ phần evaluation Windows cũ, kể cả baseline có F1 tốt hơn.

## 8. Business context và prioritization

Đổi criticality trong một context mới có cùng capture hash; giải thích vì sao thứ tự review đổi nhưng confidence không đổi. Nếu IP chưa có owner thì phải làm gì? Inventory cung cấp bởi analyst có phải asset discovery không? Một destination chung ảnh hưởng bao nhiêu dịch vụ nếu block?

Nộp: bảng owner/service/classification/criticality, priority rationale và thông tin chưa xác thực.

## 9. Handoff và ứng phó

Viết ticket một trang: quan sát, UTC range, tài sản, packet/event anchors, giả thuyết thay thế, confidence bằng lời, business impact, missing evidence và bước tiếp theo. Với mỗi response proposal, ghi owner, approval, impact, rollback và verification. Phân biệt đề xuất với hành động đã làm. Không tự bịa một cuộc gọi owner hoặc approval ID.

Nộp: ticket kỹ thuật và một đoạn tóm tắt cho người quản lý không chuyên. Dùng case 007 làm mẫu phản biện, không sao chép thành trải nghiệm cá nhân.

## 10. Failure paths và reproducibility

Giải thích test DNS pointer loop, duplicate Content-Length, stale/incorrect source scope, TCP conflicting bytes, HTML injection và failed publication. So sánh parser của dự án với dpkt: fields nào đã đối chiếu, phần nào chưa? Vì sao 125 tests pass vẫn chưa chứng minh production accuracy hoặc sức chịu tải?

Nộp: run ID, Git commit, manifest, test output và một lỗi phân tích bạn tự tìm được. Ghi learning log bằng lời của mình ở `learning/LOG.md`; mẫu bài tập này không xác nhận bạn đã hoàn thành.

## Tự kiểm tra trước phỏng vấn

Mỗi bài chỉ được coi là hiểu khi bạn tái lập kết quả, mở bằng chứng gốc, nêu một counterexample và giải thích giới hạn mà không cần đọc câu mẫu. Buổi demo khoảng 10 phút có thể đi qua public DNS→HTTP, reconstructed backup request, endpoint ambiguity, business priority và response proposal. Không cần chạy thêm VM; trọng tâm là quyết định có căn cứ.
