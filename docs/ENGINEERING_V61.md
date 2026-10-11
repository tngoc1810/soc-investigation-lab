# v6.1 — Kiểm gói readiness ở phía người nhận

Ngày cập nhật: 11/10/2026. Thay đổi code ở [service_verify.py](../soclab/service_verify.py), CLI và validator. [Tests](../tests/test_service_verify.py) giữ các nhánh accept/reject. Engine thu nhận và detection không thay policy trong đợt này.

## Bài toán

v6 tạo bốn file: readiness.json, index.html, ban-giao.md, manifest.json. Manifest hash từng báo cáo. Điều đó giúp phát hiện file đổi so với manifest, nhưng một người sửa cả manifest có thể tạo gói mới tự nhất quán. Tôi bổ sung một bước yêu cầu digest của manifest đã giữ qua kênh độc lập từ lúc bàn giao.

Kênh độc lập có thể là attachment/ticket đã được xác minh hoặc bản tham chiếu được người nhận giữ trước đó. Chỉ tính digest từ manifest vừa nhận rồi truyền lại vào lệnh sẽ không cung cấp bảo vệ so với gói đã reseal. Lệnh không tự đánh giá kênh ấy đáng tin cậy hay danh tính người gửi.

## Contract

```powershell
python -m soclab verify-readiness --bundle evidence/service/report --manifest-sha256 7cec40b06c4e378cda911ddf8f61a9ed36324437f9ad58b49e092b3df8134691
```

Digest mẫu khớp manifest v6 đã giữ trong repo. Trước khi nhận một bundle khác phải lấy đúng digest của bundle ấy. Không tái sử dụng digest của ví dụ.

Thành công trả JSON và exit 0. Gói sai trả error và exit 2. Output chỉ có format, manifest digest, số file đã kiểm, consistency flag, summary và giới hạn; không in owner, user, host hoặc command từ báo cáo.

## Trình tự kiểm

1. Xác minh digest có đúng 64 lowercase hex; thư mục không là symlink/reparse point.
2. Yêu cầu đúng bốn tên file, không nhận thư mục con hoặc file thừa.
3. Đọc manifest tối đa 64 KiB, so digest với anchor truyền vào trước khi dùng nội dung.
4. Parse UTF-8 JSON, reject duplicate keys/nonfinite numbers và định dạng chưa hỗ trợ.
5. Manifest chỉ được chỉ định đúng ba file báo cáo cố định, không có arbitrary path.
6. Đọc từng report file tối đa 16 MiB, reject symlink/reparse point/nonregular file và hash lệch.
7. Đối chiếu schema 1, context kind/hash, snapshot hash, scope và verdict chưa kết luận.
8. Đếm lại asset/check/gap/unmapped host từ phần chi tiết; kiểm integer counts, asset/check/event bounds. Duplicate alert giữa assets phải có cùng nội dung.
9. Kiểm active count trong giới hạn có thể suy ra từ mapped alert states và unmapped IDs.
10. Render lại HTML/Markdown bằng renderer hiện tại, so exact byte với các file nhận được.

Toàn bộ đọc file có giới hạn; verifier không mở browser, thực thi JavaScript/command, gọi backend hay ghi DB. Các đường dẫn tổ tiên thuộc filesystem mà người chạy đang kiểm soát; lệnh không phải sandbox chống một filesystem owner đổi đường dẫn giữa lúc stat/open/read. Giữ thư mục ổn định trong lúc kiểm, không chạy trên workspace đang được bên khác sửa liên tục.

## Những điều lệnh không xác minh lại

Report chỉ có một phần sample anchors, không toàn bộ acquisition. Vì vậy verifier không tái đếm selected events từ nguồn, không tính lại acquisition snapshot, không kiểm source XML và không chạy detector. `source_acquisition_rechecked` luôn false trong kết quả.

Cờ archive/database đã verified trong JSON là claim của producer được giữ trong gói, không thành phép kiểm acquisition mới. Source phải được kiểm ở bước tạo readiness nếu cần tái nghiệm thu nội dung.

Mapped active alerts có state đầy đủ; unmapped entries chỉ giữ alert IDs nên không xác định active count chính xác của chúng. Verifier chỉ kiểm lower/upper bound. Nó không tự suy owner/state còn thiếu hoặc quyết định verdict.

Exact render dùng implementation hiện tại. Renderer thay đổi trong phiên bản sau có thể khiến bundle cũ fail dù JSON không đổi; giữ code/version tương ứng khi xác minh. Lệnh không nhận mọi report format hoặc toàn bộ release ZIP như cùng một loại bundle.

Nếu anchor đầu vào đã bị thay hoặc người nhận tự tính nó từ bộ đã sửa, một gói tự nhất quán vẫn có thể pass. SHA-256 chưa là signature; không xác thực reviewer/authority. Chính sách giữ raw private data của v6 vẫn áp dụng.

## Kiểm chứng

19 test mới kiểm gói hợp lệ không ghi file; HTML/Markdown bị sửa; whole-bundle reseal so anchor cũ; context/snapshot mismatch; summary/boolean count; unmapped count boundary; file thiếu/thừa; traversal trong manifest; duplicate keys; nonfinite JSON; size bounds; directory/symlink; malformed report; unsupported format và exit code CLI.

Validator [validate_service_readiness.py](../scripts/validate_service_readiness.py) chạy verifier trên báo cáo nó vừa tạo. Anchor tính tại producer trong controlled acceptance chỉ kiểm wiring, không giả lập một secure out-of-band channel. [validate_handoff.py](../scripts/validate_handoff.py) còn giữ kết quả CLI trên bundle v6 đã công bố và các bản sao sửa riêng. Nó không sửa artifact v6.

Các test/CI của v6.0 là hồ sơ lịch sử. Nghiệm thu v6.1 có kết quả riêng tại [ACCEPTANCE.md](ACCEPTANCE.md) và [evidence/handoff](../evidence/handoff/README.md).
