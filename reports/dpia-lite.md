# DPIA-lite

Đây là ghi chú ngắn em tự lập cho bài lab. Mục tiêu của em là nhìn được dữ liệu
nào đi vào agent, agent dùng để làm gì và có thể đi ra đâu.

## 1. Dữ liệu em xử lý

Em thấy có hai nhóm dữ liệu chính.

- Dữ liệu không tin cậy: các ticket Markdown trong `corpus/`. Ticket có thể
  chứa nội dung bình thường, mã khách hàng `KH-xxxxxx`, hoặc prompt injection
  do attacker cài vào.
- Dữ liệu riêng tư: `data/customers.json`, gồm `customer_id`, tên, CCCD, số
  điện thoại, số tài khoản, email và `related_tickets`.

Em đã viết `agent/pii.py` để nhận diện và redact CCCD, SĐT, STK và email. Tuy
nhiên, dữ liệu khách hàng vẫn là `restricted`; không vì đã nhận diện PII mà em
cho phép nó được gửi ra ngoài.

## 2. Mục đích và cách em giới hạn xử lý

Mục đích chính của agent là tổng hợp ticket hỗ trợ. Phần red-team của lab giúp
em kiểm tra trường hợp một ticket cố biến agent thành công cụ lấy dữ liệu khách
hàng và gửi đi.

Để giảm quyền của agent, em chia luồng làm hai phần:

- Run A chỉ đọc ticket để lấy ticket ID từ tên file.
- Run B dùng `related_tickets` trong kho khách hàng để tìm customer ID phù hợp,
  rồi mới đọc hồ sơ khách. Run B không dùng customer ID xuất hiện trong text của
  ticket.
- Nếu có ý định egress dữ liệu `restricted`, policy sẽ deny trước khi
  `http_post` chạy.

## 3. Dữ liệu có thể chảy đi đâu

Trong chế độ lab, `search_docs` đọc `corpus/*.md` và `read_customer` đọc
`data/customers.json`. Các quyết định gọi tool được ghi vào
`reports/ledger.jsonl`, trong đó có allow/deny, reason và hash chain.

Đích HTTP duy nhất của lab là `http://localhost:9999/*`. Trước khi contain,
baseline có thể gửi PII tới sink cục bộ; em lưu lại kết quả ở
`reports/attack-before.log`. Sau khi contain, sink rỗng và evidence nằm ở
`reports/attack-after.log` cùng dòng deny trong ledger.

Khi chạy `--mock`, em không gọi API bên ngoài. Nếu đổi sang
`--model claude-...`, nội dung ticket gửi cho model provider có thể trở thành
luồng dữ liệu xuyên biên giới. Khi dùng chế độ đó, em cần ghi nhận nhà cung cấp,
loại dữ liệu gửi đi, thời gian lưu và căn cứ xử lý trước khi vận hành thật.
