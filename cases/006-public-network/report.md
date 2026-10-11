# CASE-006 — Đọc HTTP/DNS từ packet và đối chiếu bằng decoder độc lập

Tôi dùng hai capture công khai, độc lập từ [Wireshark SampleCaptures](https://wiki.wireshark.org/samplecaptures) để kiểm parser. Mục tiêu là xác minh tuple, question/answer và request framing. Các mẫu này không có nhãn attack intent của project, vì vậy kết quả chưa phải phân loại malicious/benign.

## Nguồn

| Capture | Dung lượng | SHA-256 |
| --- | --- | --- |
| HTTP | 25.803 byte | `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d` |
| DNS | 4.338 byte | `041eeb6f98bb398f1ee8b09651b5b5a84f6a62639f95bf226f9e7b77355d9f28` |

Original captures giữ ở local download; repo công bố metadata và derived checks. Tôi không nối hai file thành một session chung hoặc ghép với Windows casebook.

## HTTP: quan hệ có thể quan sát

Capture có 43 frame, ba flow, hai DNS message và hai HTTP request. Một client là `145.254.160.237`. Requests gồm `GET /download.html`, Host `www.ethereal.com`, và advertising request với Host `pagead2.googlesyndication.com`. Đây là tên lịch sử trong file; tôi không truy cập hay kiểm reputation hiện tại.

DNS query frame 13 hỏi `pagead2.googlesyndication.com`; response frame 17 có CNAME tới `pagead2.google.com`, `pagead.google.akadns.net` và A answer gồm `216.239.59.99`. TCP flow sau dùng IP này. Tôi giữ association có giới hạn theo client/address/time, chưa xác nhận identity vì shared IP, cache và capture vantage có thể ảnh hưởng.

Hai request đối chiếu khớp complete single-packet decoding của dpkt. Thấy request chưa chứng minh download hoàn tất, content an toàn hay process gửi. Tool không chạy/render response body. Packet number, offset và frame/source hashes là đường quay lại byte gốc.

## DNS: coverage thực tế của parser

Capture riêng có 38 frame/message trên tám UDP flow. Có question A, AAAA, PTR, MX, TXT, NS, SRV và loại khác. Parser đọc selected A/AAAA/name/TXT answers; các RDATA chưa hỗ trợ giữ type/hash, không nhận là đã decode đầy đủ. Một AAAA question có thể đi trong packet IPv4.

Ví dụ gồm TXT/MX của `google.com`, reverse PTR và directory-service SRV. SRV hợp lệ có thể dài, nên độ dài domain chưa chứng minh tunneling. NXDOMAIN phải đi cùng question/resolver/window; một lỗi resolve chưa đủ kết luận DGA.

## Kết quả và những gì còn thiếu

Verdict giữ `unassessed`. Ba heuristic network đang có không match các sample; đó chưa phải bằng chứng endpoint an toàn. Còn thiếu acquisition authentication, sensor/drop coverage, owner, process context và authorization nghiệp vụ.

Tôi bàn giao capture references, quan hệ giao thức và giới hạn kết luận. Tái lập bằng `scripts/validate_network.py --public --independent` sau cài decoder tùy chọn như [runbook](../../docs/RUNBOOK_V5.md). Tổng đối chiếu hai file là 81 packet tuple, 40 DNS message, hai HTTP request, không phải IDS accuracy. [Bản tiếng Anh đã lưu](report.en.md).
