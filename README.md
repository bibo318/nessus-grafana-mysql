# nessus-grafana-mysql

Giải pháp thu thập và trực quan hóa kết quả quét lỗ hổng Nessus với MySQL và Grafana.

## Kiến trúc tổng quan
- **app/**: dịch vụ Python kết nối Nessus bằng REST API, đồng bộ dữ liệu lịch sử vào MySQL.
- **MySQL**: lưu trữ thông tin phiên quét, máy chủ, plugin, CVE và chi tiết phát hiện.
- **Grafana**: đọc dữ liệu từ MySQL thông qua dashboard được cung cấp trong repo để trình bày trực quan.
- **Docker Compose**: khởi chạy trọn bộ (Nessus sync + MySQL + Grafana) bằng cấu hình sẵn.

## Quy trình hoạt động
1. `app/main.py` khởi tạo schema MySQL từ `schema.sql`, tạo kết nối Nessus (`nessus_client.py`) và bắt đầu vòng lặp.
2. Ở chế độ backfill, tất cả các scan/histories đã hoàn thành sẽ được tải và ghi xuống MySQL thông qua các hàm trong `db.py`.
3. Vòng lặp định kỳ (`POLL_INTERVAL_SECONDS`) kiểm tra scan mới, lấy chi tiết host, plugin output, CVE và cập nhật vào cơ sở dữ liệu.
4. Grafana dùng datasource MySQL để đọc các bảng `processed_history`, `hosts`, `findings`, `host_findings`, `cves`… phục vụ dashboard.

## Thành phần mã nguồn
### `app/main.py`
- Điều phối toàn bộ luồng đồng bộ: backfill lịch sử, vòng lặp polling.
- Xử lý từng history: lưu metadata, host, plugin, CVE, chi tiết host level.
- Có xử lý ngoại lệ chi tiết và ghi log tiếng Việt giúp dễ theo dõi.

### `app/db.py`
- Định nghĩa hằng kết nối MySQL thông qua biến môi trường (`MYSQL_HOST`, `MYSQL_USER`...).
- Cung cấp hàm `db_conn()` dùng context manager.
- Hàm *upsert* cho scan, history, host, plugin, finding, CVE, host finding giúp tránh trùng lặp.
- Hàm tiện ích chuẩn hóa dữ liệu (ép kiểu, trích hostname, tính toán hash plugin output).

### `app/nessus_client.py`
- Bao bọc REST API Nessus: danh sách scan, lịch sử, host, plugin output…
- Hàm `_get_paginated` xử lý phân trang tự động.
- Hàm `extract_cves_from_vuln` cố gắng suy ra CVE từ nhiều trường khác nhau.

### `app/schema.sql`
- Tạo database `nessus_data` và toàn bộ bảng cần thiết.
- Quan hệ khóa ngoại giữa `findings` ↔ `plugins`, `finding_cves`, `host_findings` đảm bảo toàn vẹn dữ liệu.

## Dashboard Grafana
- File `Nessus Vulnerability Professional (MySQL).json` cung cấp dashboard chuyên sâu với:
  - Khu vực tổng quan (trạng thái, thời điểm, số máy chủ, tổng phát hiện).
  - Phân bố mức độ nghiêm trọng, xu hướng theo lịch sử, biểu đồ top máy chủ.
  - Bảng lịch chạy, phân tích theo máy chủ, plugin rủi ro, CVE trọng yếu, chi tiết lỗ hổng.
- Tất cả tiêu đề, ghi chú hiển thị tiếng Việt, màu sắc nổi bật.
- Import dashboard trong Grafana và gán datasource MySQL tương ứng (`mysql_nessus`).

## Triển khai nhanh với Docker Compose
1. Cài Docker & Docker Compose.
2. Thiết lập biến môi trường Nessus (`NESSUS_URL`, `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`).
3. Chạy `docker-compose up -d` trong thư mục dự án.
4. Grafana mặc định tại `http://localhost:3000` (user/pass `admin`/`admin`).
5. Import dashboard JSON và ánh xạ datasource `mysql_nessus`.

## Tuỳ chỉnh & mở rộng
- Điều chỉnh chu kỳ polling thông qua `POLL_INTERVAL_SECONDS`.
- Bật/tắt backfill lần đầu bằng `BACKFILL_ON_START`.
- Có thể bổ sung bảng phụ hoặc chỉ số riêng trong `schema.sql`, sau đó mở rộng dashboard tương ứng.
