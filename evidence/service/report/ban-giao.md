# Biên bản sẵn sàng điều tra và bàn giao dịch vụ

Mốc đánh giá: 2026-10-09T03:00:00.000000Z. Cửa sổ event: 3600 giây.

Context SHA-256: `c6dade804ccccf036d5f9eb08a08f8bfebadba9ee7555dc5a28d1baee29b94f6`.
Snapshot SHA-256: `b5cf55ea1799c5436ee8547ea945c7c6cc58a0790d4a0d36413ba7289c133038`.

Kết luận: **chưa kết luận sự cố**. Đây là ảnh chụp chỉ đọc; người nhận/chủ tài sản do context khai báo, không phải người đã được xác thực hay thông báo.

## Tài sản: Máy trạm tài chính tự dựng

Dịch vụ: Xử lý nghiệp vụ tài chính tự dựng.
Chủ sở hữu: Chủ dịch vụ tài chính trong scenario. Đầu mối điều tra: Đầu mối SOC trong scenario.
Mức quan trọng khai báo: Rất quan trọng. Độ ưu tiên: ưu_tiên_review.

### Quan sát và khoảng trống

- AUTH-COVERAGE: 6 event trong cửa sổ; 6 event đúng policy trong collection.
  - Anchor: `2b9e22467b33284e03efd1a8e97409adc66e6be6b82038c1f89aa81a6bea339e`, source `3be9778af132318ef3cfd9949c2efb2f53b9811025889325024f67170f89f5af`, dòng 1.
  - Anchor: `6119eeb2e1f8cb542566b08dab87704dbcba1a1fd589cc312532de5d0a9d92d8`, source `460909f535555889395d7f4dcceda0df98c3d4ad8be1be07fb2ee07751f31b97`, dòng 1.
  - Anchor: `d19e32c5de6c07c9c8eba1ae0176a94bf20d5474d21d6d41a82a3ca19a1b7d4a`, source `460909f535555889395d7f4dcceda0df98c3d4ad8be1be07fb2ee07751f31b97`, dòng 4.
  - Anchor: `d5bad6c88f3c963687006b6949522c8d89b1fa7ff43ca9c24607149a39de5612`, source `460909f535555889395d7f4dcceda0df98c3d4ad8be1be07fb2ee07751f31b97`, dòng 3.
  - Anchor: `ddf7aad5e2dc7657aa7e3c7d872b972cb2689401f89d5c25ca43d400d3ac6806`, source `460909f535555889395d7f4dcceda0df98c3d4ad8be1be07fb2ee07751f31b97`, dòng 2.
- PROCESS-QUALITY: 1 event trong cửa sổ; 2 event đúng policy trong collection.
  - Collector scope có lỗi/gap, heartbeat cũ hoặc chưa có heartbeat.
  - Timestamp tương lai hoặc received time trước event time; cần kiểm tra đồng hồ.
  - Trường phục vụ điều tra bị thiếu hoặc rỗng.
  - Anchor: `2e3ef07697f373cd17a047240cfe015485ad55c819db804010a9ee2832f57538`, source `85e997cd6b15350e5cd42691a74ccc5e8a403580959fa6988bf93a4b05d0c604`, dòng 3.
  - Anchor: `e0ebceeb938c5de3e0af63c52023796df138a1190925191003eeb798bb8bbbaa`, source `85e997cd6b15350e5cd42691a74ccc5e8a403580959fa6988bf93a4b05d0c604`, dòng 1.
- NETWORK-QUALITY: 1 event trong cửa sổ; 1 event đúng policy trong collection.
  - Collector scope có lỗi/gap, heartbeat cũ hoặc chưa có heartbeat.
  - Trường phục vụ điều tra bị thiếu hoặc rỗng.
  - Anchor: `69fe00918b71942a7c44429638f94ff1ae84db48dcf82eb8c40844da5b43a811`, source `85e997cd6b15350e5cd42691a74ccc5e8a403580959fa6988bf93a4b05d0c604`, dòng 2.
- SCRIPT-COVERAGE: 0 event trong cửa sổ; 1 event đúng policy trong collection.
  - Có event nhận trễ theo received time lưu trong workspace.
  - Hoạt động event cũ hơn ngưỡng đã khai báo; chưa đủ căn cứ nói sensor ngừng chạy.
  - Một số Event ID chưa xuất hiện trong cửa sổ; không suy ra cấu hình audit bị tắt.
  - Trường phục vụ điều tra bị thiếu hoặc rỗng.
  - Anchor: `47d3764eedc3ac39fbfd7b91f974ba8729b31025bf07831ba84df9700e374963`, source `045db800e8863b056ed17beb283f29c3e2509433139d6312db23d3cf0c5923af`, dòng 1.

Event chưa ánh xạ policy: 1. Không tự coi chúng là độc hại hoặc hợp lệ.

### Alert đang lưu

- `WIN-001` / `b21779a991372e8d2a609da92e4e561d1c486017b6ae39a8b1ef7c5e1e2dc3c9`: Mới; revision 1; owner chưa phân công; quá hạn review: không.
- `AUTH-001` / `f4052e4ffbd190d283b3c533a25fa64d40484035811a80438e267fb83442ae81`: Mới; revision 1; owner chưa phân công; quá hạn review: không.

### Đề xuất bàn giao

Chủ sở hữu/context do người vận hành khai báo; chưa xác thực danh tính hoặc quyền ứng phó.

- Giữ acquisition, đối chiếu thời gian và bổ sung nguồn/trường còn thiếu.
  - Người phụ trách dự kiến: Đầu mối SOC trong scenario.
  - Phê duyệt: Phê duyệt truy cập và lưu giữ dữ liệu.
  - Ảnh hưởng: Chi phí thu nhận/lưu trữ và dữ liệu nhạy cảm.
  - Phục hồi: Không xóa acquisition gốc; giữ snapshot trước thay đổi.
  - Xác minh: Hash/UID đúng, telemetry gap có giải trình.
- Xác minh hoạt động với chủ dịch vụ trước khi đề xuất containment.
  - Người phụ trách dự kiến: Chủ dịch vụ tài chính trong scenario.
  - Phê duyệt: Change/ticket và người có thẩm quyền phải được xác minh.
  - Ảnh hưởng: Có thể gián đoạn dịch vụ nếu chặn nhầm.
  - Phục hồi: Phải có cấu hình trước thay đổi và cách phục hồi được phê duyệt.
  - Xác minh: Đối chiếu process/session, nội dung, destination và tình trạng dịch vụ.

## Tài sản: Máy backup khai báo chưa có log

Dịch vụ: Dịch vụ backup tự dựng.
Chủ sở hữu: Chủ dịch vụ backup trong scenario. Đầu mối điều tra: Đầu mối SOC trong scenario.
Mức quan trọng khai báo: Quan trọng. Độ ưu tiên: ưu_tiên_review.

### Quan sát và khoảng trống

- BACKUP-AUTH-COVERAGE: 0 event trong cửa sổ; 0 event đúng policy trong collection.
  - Chưa có quan sát đúng provider/channel/Event ID trong nguồn được duyệt.
  - Collector scope có lỗi/gap, heartbeat cũ hoặc chưa có heartbeat.
  - Một số Event ID chưa xuất hiện trong cửa sổ; không suy ra cấu hình audit bị tắt.

Event chưa ánh xạ policy: 0. Không tự coi chúng là độc hại hoặc hợp lệ.

### Alert đang lưu

Chưa có alert liên quan trong snapshot; không chứng minh tài sản an toàn.

### Đề xuất bàn giao

Chủ sở hữu/context do người vận hành khai báo; chưa xác thực danh tính hoặc quyền ứng phó.

- Giữ acquisition, đối chiếu thời gian và bổ sung nguồn/trường còn thiếu.
  - Người phụ trách dự kiến: Đầu mối SOC trong scenario.
  - Phê duyệt: Phê duyệt truy cập và lưu giữ dữ liệu.
  - Ảnh hưởng: Chi phí thu nhận/lưu trữ và dữ liệu nhạy cảm.
  - Phục hồi: Không xóa acquisition gốc; giữ snapshot trước thay đổi.
  - Xác minh: Hash/UID đúng, telemetry gap có giải trình.
- Xác minh hoạt động với chủ dịch vụ trước khi đề xuất containment.
  - Người phụ trách dự kiến: Chủ dịch vụ backup trong scenario.
  - Phê duyệt: Change/ticket và người có thẩm quyền phải được xác minh.
  - Ảnh hưởng: Có thể gián đoạn dịch vụ nếu chặn nhầm.
  - Phục hồi: Phải có cấu hình trước thay đổi và cách phục hồi được phê duyệt.
  - Xác minh: Đối chiếu process/session, nội dung, destination và tình trạng dịch vụ.

## Phạm vi bàn giao

Ảnh chụp chỉ đọc của collection được phê duyệt. Không sửa owner/status/verdict, không đánh giá mọi audit policy, không gửi thông báo hoặc thực hiện containment.

Không gửi email/ticket, không thay đổi alert, không chặn mạng hoặc cô lập endpoint.
