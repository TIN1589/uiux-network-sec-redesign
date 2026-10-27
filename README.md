# Network Security Monitor – SOC Command Center

> Phiên bản thiết kế & giao diện chuẩn cho Trung tâm điều hành an toàn thông tin (SOC Command Center v2.4 / VNPT N4.2).
> Dự án được tối ưu hóa cho hai mục đích: **Tham khảo quy chuẩn UI/UX** cho các thành viên và **Bản trình duyệt Frontend thực nghiệm** hoàn chỉnh phục vụ thẩm định phê duyệt.

---

## Quick Preview (Dành cho người thẩm định & Thành viên)

Bạn có thể chạy dự án bằng **1 trong 2 cách** tùy vào nhu cầu:

### Cách 1: Xem nhanh giao diện tĩnh (Zero Setup - Standalone Preview)
*Phù hợp cho người thẩm định hoặc thành viên muốn xem nhanh UI/UX mà không cần cài đặt Python:*
- Mở trực tiếp file [`index.html`](file:///d:/AllCourse/Học%20Kì%20Doanh%20Nghiệp_10-1(26-27)/UIUX-NetWorkSec/redesign/index.html) bằng trình duyệt (Chrome, Edge, Firefox), hoặc sử dụng extension **Live Server** trên VS Code.
- Đầy đủ layout 4 trang, Chart.js tương tác, slide-over drawer, modal sign-in và responsive 3 breakpoint.

### Cách 2: Chạy đầy đủ tính năng với Backend FastAPI (Full Dynamic App)
*Phù hợp cho lập trình viên cần kiểm tra HTMX partial swapping, API tìm kiếm/lọc real-time, thêm kịch bản tấn công và export CSV:*

1. **Yêu cầu môi trường**: Python 3.10+
2. **Cài đặt thư viện**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Khởi chạy ứng dụng**:
   ```bash
   python run.py
   ```
   *(Hoặc chạy lệnh: `uvicorn app:app --host 127.0.0.1 --port 8000 --reload`)*
4. **Truy cập**: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## Tech Stack & Kiến trúc

Dự án sử dụng kiến trúc Hypermedia-Driven hiệu năng cao, giảm thiểu phụ thuộc framework cồng kềnh:

- **[Jinja2](https://jinja.palletsprojects.com/)**: Server-side template engine dạng module hóa (Master layout, Components, Pages, HTMX Partials).
- **[HTMX 2.0](https://htmx.org/)**: Điều hướng không tải lại trang (`hx-get`), tìm kiếm debounce thời gian thực (`hx-trigger="input changed delay:200ms"`), slide-over drawer và cập nhật trạng thái alert linh hoạt.
- **Modern Vanilla CSS3**: 
  - Toàn bộ Design Tokens được định nghĩa tập trung qua CSS Custom Properties (màu sắc, spacing, typography, shadow).
  - Không phụ thuộc Tailwind, tối ưu hóa kích thước stylesheet và kiểm soát 100% cascade.
  - Sử dụng CSS Grid, Flexbox, `@container` queries và fluid typography (`clamp()`).
- **Vanilla JavaScript ES6+**: Kiến trúc module rõ ràng ([`app.js`](file:///d:/AllCourse/Học%20Kì%20Doanh%20Nghiệp_10-1(26-27)/UIUX-NetWorkSec/redesign/static/js/app.js), [`charts.js`](file:///d:/AllCourse/Học%20Kì%20Doanh%20Nghiệp_10-1(26-27)/UIUX-NetWorkSec/redesign/static/js/charts.js), [`toast.js`](file:///d:/AllCourse/Học%20Kì%20Doanh%20Nghiệp_10-1(26-27)/UIUX-NetWorkSec/redesign/static/js/toast.js)), hook trực tiếp vào vòng đời của HTMX và Chart.js.
- **[Chart.js 4.x](https://www.chartjs.org/)**: Biểu đồ phân tích thị giác (Severity Mix Doughnut, 24-Hour Stacked Bar, Sparkline KPI).
- **FastAPI (Python 3.10+)**: Backend bất đồng bộ hiệu năng cao, in-memory state store, CSV streaming export có bảo vệ chống Formula Injection.

---

## Project Structure

```
redesign/
├── static/
│   ├── css/
│   │   ├── variables.css       # Design tokens (màu nền ấm #f3f1ec, dark sidebar, text, border)
│   │   ├── reset.css           # CSS Reset chuẩn, tùy biến scrollbar, focus ring
│   │   ├── layout.css          # Responsive shell (Desktop 248px, Tablet 72px rail, Mobile drawer)
│   │   ├── components.css      # Cards, badges, bảng dữ liệu, nút bấm, drawer, modal
│   │   ├── charts.css          # Kích thước khung vẽ biểu đồ & custom legend
│   │   └── style.css           # Master stylesheet tổng hợp
│   └── js/
│       ├── app.js              # Coordinator chính, điều phối drawer, dropdown & HTMX events
│       ├── charts.js           # Quản lý khởi tạo & vòng đời biểu đồ Chart.js
│       └── toast.js            # Hệ thống thông báo nổi (Accessible Toasts)
├── templates/
│   ├── base.html               # Layout khung ứng dụng chung
│   ├── components/             # Các thành phần tái sử dụng
│   │   ├── sidebar.html        # Responsive 3-state navigation sidebar
│   │   ├── topbar.html         # Sticky topbar với live heartbeat & analyst profile
│   │   ├── drawer.html         # Slide-over alert detail drawer host
│   │   └── signin_modal.html   # Split-screen sign-in modal
│   ├── pages/                  # Các trang đầy đủ (kèm master layout)
│   │   ├── index.html          # Trang 1: SOC Command Center Overview
│   │   ├── alerts.html         # Trang 2: Alert Queue & Detections
│   │   ├── devices.html        # Trang 3: Monitored Devices Inventory
│   │   └── scenarios.html      # Trang 4: MITRE ATT&CK Scenarios Lab
│   └── partials/               # Các fragment HTML phục vụ HTMX swapping
│       ├── overview_content.html
│       ├── alerts_content.html
│       ├── alerts_table.html
│       ├── devices_content.html
│       ├── scenarios_content.html
│       ├── scenarios_table.html
│       └── drawer_content.html
├── app.py                      # FastAPI app, API endpoints & in-memory state store
├── run.py                      # Script khởi chạy server một chạm
├── index.html                  # Bản preview tĩnh độc lập (Standalone Preview)
├── requirements.txt            # Danh sách dependencies
└── README.md                   # Tài liệu hướng dẫn & quy chuẩn
```

---

## Quy chuẩn UI/UX & Thiết kế (Design Guidelines)

Hệ thống quy chuẩn thiết kế được định nghĩa tập trung qua các Design Tokens trong file [`static/css/variables.css`](file:///d:/AllCourse/Học%20Kì%20Doanh%20Nghiệp_10-1(26-27)/UIUX-NetWorkSec/redesign/static/css/variables.css):

1. **Bảng màu chủ đạo (Tone & Mood)**:
   - Nền trang ấm thanh lịch: `#f3f1ec` (không gây chói mắt cho analyst trực ca dài).
   - Card bề mặt: `#ffffff` với viền mềm `#e7e4dc`.
   - Sidebar công nghệ cao: `#121212` với accent lime `#c6f135`.
   - Bảng màu mức độ cảnh báo chuẩn quốc tế:
     - **Critical**: `#d92d20` (Nền chip: `#fde8e6`, Chữ: `#b42318`)
     - **High**: `#dc6803` (Nền chip: `#fef0c7`, Chữ: `#93370d`)
     - **Medium**: `#eab308`
     - **Low**: `#2f6fe4`
2. **Typography**:
   - Chữ thông thường: `Inter` (rõ nét ở mọi cỡ chữ).
   - Mã định danh, IP, Syslog, Payload: `JetBrains Mono` (dễ phân biệt ký tự đặc biệt).
3. **Đáp ứng đa thiết bị (Responsive Breakpoints)**:
   - **Desktop (>= 1280px)**: Sidebar mở rộng 248px hiển thị đầy đủ nhãn và badge.
   - **Tablet (1024px – 1279px)**: Sidebar tự động co lại thành icon rail 72px với floating tooltip.
   - **Mobile (< 1024px)**: Sidebar chuyển thành off-canvas drawer có lớp backdrop làm mờ.

---

## Các tính năng cốt lõi

1. **Trải nghiệm không tải lại trang**: HTMX hoán đổi nội dung `#main-content` đồng thời cập nhật đúng URL trình duyệt (`hx-push-url="true"`), hỗ trợ F5 refresh và nút Back/Forward tự nhiên.
2. **Bộ lọc tìm kiếm tức thì**: Lọc theo từ khóa, mức độ nghiêm trọng (Severity), khung thời gian và bộ lọc nâng cao (Rule ID, Source IP, Asset, Status).
3. **Slide-over Drawer chi tiết cảnh báo**: Xem chi tiết log thô, MITRE ATT&CK technique, sao chép 1-click clipboard và thao tác nhanh trạng thái (Acknowledge / In Progress / Resolved).
4. **Lab kiểm thử kịch bản tấn công**: Đo lường SLA delta độ trễ phát hiện so với ngưỡng 5.0 giây, hỗ trợ lưu trữ và xuất file CSV.
5. **Biểu đồ phân tích trực quan**: Tích hợp Chart.js theo dõi tỷ lệ phân bổ nguy cơ và chu kỳ phát hiện 24 giờ.
