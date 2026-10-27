# AGENTS.md — Network Security Monitor · SOC Command Center

Bộ quy tắc cho mọi agent (và người) chỉnh giao diện dự án này. Đọc hết trước khi sửa bất kỳ file nào.
Mục "Cần bổ sung" ở cuối là các thông tin kỹ thuật chưa có; **không tự đoán**, hãy hỏi hoặc đọc repo.

## 1. Dự án là gì

- Giao diện web cho SOC: giám sát cảnh báo mạng từ Wazuh, Suricata và NetFlow (nhãn trên sidebar: `VNPT SOC v2.4 · E2E`).
- Bốn trang: **Overview**, **Alerts** (Alert queue), **Devices**, **Attack scenarios**.
- Người dùng chính là analyst. Họ quét nhanh, cần số liệu đúng và ưu tiên rõ. Giao diện phải gọn, dễ đọc, không trang trí thừa.
- Ngôn ngữ giao diện: **tiếng Anh**. Dữ liệu người dùng nhập (ví dụ Notes) có thể là tiếng Việt; không dịch, không sửa.

## 2. Phạm vi được và không được làm

**Được làm** (khi được giao nhiệm vụ UI): bố cục, spacing, kích thước control, màu, chữ, tương phản, trạng thái hover/focus, responsive, nhãn hiển thị, đặt tên layer/component.

**Không được làm khi chưa có yêu cầu rõ:**
- Đổi dữ liệu, schema, API, route, logic lọc, logic ghi test, cách tính (Delta, detection rate, phần trăm).
- Thêm hoặc nâng cấp dependency, thêm font ngoài Inter và JetBrains Mono.
- Đổi thứ tự hay tên mục điều hướng.
- Xóa tính năng; nếu thấy thừa, hãy đề xuất thay vì xóa.

## 3. Design tokens (nguồn sự thật duy nhất)

Tạo biến CSS (hoặc token của hệ thống hiện có) cho các giá trị dưới đây; không viết màu cứng rải rác.

| Token | Giá trị | Dùng cho |
|---|---|---|
| `bg/page` | `#f3f1ec` | Nền trang, nền topbar |
| `bg/surface` | `#ffffff` | Card |
| `bg/inset` | `#f3f1ec` | Panel lồng trong card |
| `border/default` | `#e7e4dc` | Viền card, đường chia |
| `border/row` | `#efece5` | Đường chia hàng bảng |
| `border/input` | `#d9d5ca` | Viền ô nhập |
| `text/primary` | `#141413` | Chữ chính |
| `text/muted` | `#5f5b53` | Chữ phụ (không nhạt hơn) |
| `side/bg` | `#121212` | Sidebar |
| `side/active` | `#262626` | Mục đang chọn |
| `side/muted` | `#a8a49b` | Chữ phụ trên sidebar (không tối hơn) |
| `accent` | `#c6f135` | Logo, avatar, điểm nhấn nhỏ. Không dùng làm nền nút |

**Màu mức độ** (một nguồn, dùng ở mọi trang):

| Mức | Chấm / biểu đồ | Chip nền | Chip chữ |
|---|---|---|---|
| Critical | `#d92d20` | `#fde8e6` | `#b42318` |
| High | `#dc6803` | `#fef0c7` | `#93370d` |
| Medium | `#eab308` | — | — |
| Low | `#2f6fe4` | — | — |

**Chip trạng thái:** New `#dbeafe`/`#1d4ed8`; Investigating nền trắng, viền `#141413`; Reporting/Detected/Within target `#dcfce7`/`#166534`; Silent `#fef3c7`/`#92400e`.

**Chữ:** Inter cho UI; JetBrains Mono cho ID sự kiện, mã rule, IP, hostname, timestamp, meta. Cỡ tối thiểu 11px.
H1 36px/700 (letter-spacing −.02em) · H2 card 16px/600 · thân 14px · chú thích 12px · nhãn 11px/600 uppercase, letter-spacing .06em · số KPI 40px/700, line-height 1.

**Spacing:** 4 / 8 / 12 / 16 / 24 / 32 / 40.
**Radius:** 6 (chip), 10 (ô nhập), 12 (hàng danh sách, panel), 16 (card), 999 (pill, nút).

## 4. Khung trang (áp dụng cả 4 trang)

- Sidebar rộng 248px. Chân sidebar có mã phiên bản dạng mono 11px.
- Nút X đóng sidebar **chỉ hiện dưới 1024px** (drawer); trên desktop phải ẩn.
- Topbar `position: sticky; top: 0`, nền đặc `bg/page`, `border-bottom` chạy suốt chiều ngang, padding ngang 40px. Bên trái chip "Live · updated Ns ago · GMT+7"; bên phải nút Auto-refresh và avatar.
- Vùng nội dung: padding `32px 40px 40px`, `max-width: 1320px`, gap dọc 24px.
- H1 cách topbar ít nhất 32px. Nút hành động của trang (Export CSV) căn đáy với dòng phụ đề.
- Card: nền `bg/surface`, viền 1px `border/default`, radius 16, padding 24, **không đổ bóng**.
- Hàng hai cột luôn dùng `grid-template-columns: 2fr 1fr; gap: 24px` để cạnh cột phải thẳng nhau giữa các hàng.

## 5. Quy tắc từng thành phần

**Hàng KPI.** Một card liền, N cột bằng nhau, chia bằng `border-left` 1px, padding mỗi ô `20px 24px`. Cấu trúc ô: nhãn → số → chú thích, giống hệt nhau ở mọi ô để số thẳng baseline. Chấm màu chỉ dùng khi nhãn mang mức độ hoặc trạng thái; chọn một quy tắc và dùng đồng nhất cho mọi trang. Không đặt sparkline hay biểu tượng ở một ô riêng lẻ.

**Nút.** Chỉ ba kiểu:
1. Chính: nền `#121212`, chữ trắng, pill, cao 40px.
2. Phụ: nền trắng, viền 1px `#141413`, pill, cao tối thiểu 34px.
3. Icon-only: 36×36, bắt buộc có `aria-label`.

Cấm nút cam, nút có bóng cứng, nút đổi phong cách theo trang.

**Control form.** Cao đúng 40px, radius 10, viền `border/input`, chữ 14px. Nhãn 12px/600 nằm trên ô; chú thích 11px `text/muted` nằm **dưới** ô, không chung dòng với nhãn. Checkbox/radio dùng `accent-color: #121212`, 16px. Select phải hiển thị đủ giá trị (đừng cắt "Port scan det…"; nới cột hoặc dùng ellipsis kèm tooltip).

**Bảng.** Dùng lưới cột cố định (grid hoặc `table-layout: fixed`), gap 16px, padding dọc hàng 14px, căn giữa theo chiều dọc. Tiêu đề cột luôn một dòng. ID, IP, hostname, mã rule: mono, `white-space: nowrap`, **không bao giờ ngắt tại dấu gạch**. Cột số căn phải. Thao tác mỗi hàng gộp thành nút "⋯" (menu); không đặt hai nút chữ cạnh nhau ở mỗi hàng.

**Thanh tiến độ.** Cao 6px (panel thời gian 8px), radius 3, nền `#ebe8e0`, phần đầy `#141413`. Độ rộng tính theo giá trị thật; **giá trị 0 là thanh rỗng**. Cột giá trị bên phải cố định 64px, nowrap, số cùng độ rộng (`tabular-nums`), ví dụ `1 · 33%` luôn một dòng.

**Biểu đồ cột (Alerts per hour).** Cao 200px, có đường lưới ngang và nhãn trục Y ≥ 11px. Xếp chồng Critical dưới cùng, rồi High, Medium, Low. Legend gồm đủ 4 mức, đặt bên phải tiêu đề. Phụ đề theo bộ lọc thời gian: 1h → per 5 min, 24h → per hour, 7d → per day. Cấm để nhãn cố định "24-hour" khi đang chọn 7d.

**Donut (Severity mix).** Số tổng ở giữa kèm chữ "ALERTS"; legend ngay dưới donut, không đẩy xuống đáy card. Tổng các cung phải bằng tổng cảnh báo.

**Panel Detection time.** Ba giá trị Test started / Alert observed / Delta cùng cỡ chữ mono 20px, Delta đậm hơn. Vạch target đặt đúng tỉ lệ trên thang (5 s trên 6 s = 83,3%). Chip "Within target" ở góc phải tiêu đề panel.

**Thẻ thiết bị.** Ba vùng: danh tính (icon, chip, tên mono, loại) → TELEMETRY (nền `#f7f5ef`; thẻ Silent `#fbf6e6`) → SECURITY ALERTS. Các thẻ cùng chiều cao. Tên máy dài dùng ellipsis, không xuống dòng.

## 6. Quy tắc nội dung và dữ liệu hiển thị

- Mọi số, tên, ID, timestamp lấy từ dữ liệu thật; mockup chỉ dùng dữ liệu mẫu đã có trong thiết kế.
- Nhãn phụ thuộc bộ lọc (1h / 24h / 7d) phải đổi theo bộ lọc: chú thích KPI ("last 24 hours"), phụ đề biểu đồ, "none in 24h".
- Timestamp hiển thị theo GMT+7 và ghi rõ múi giờ ở chỗ có giờ tuyệt đối.
- Không lặp một thông tin ở hai chỗ gần nhau (ví dụ chip Live ở topbar và "Live ingestion" trong card).
- Văn bản UI tiếng Anh nhất quán; không trộn tiếng Việt vào nhãn nút.

## 7. Truy cập và tương phản

- Chữ phụ trên nền sáng không nhạt hơn `#5f5b53`; trên sidebar tối không tối hơn `#a8a49b`. Đạt WCAG AA (4.5:1) cho chữ thường.
- Mọi phần tử bấm được có trạng thái hover (nền `#f3f1ec`) và `:focus-visible` (outline 2px `#141413`, offset 2px). Vùng bấm tối thiểu 34px.
- Không dùng màu làm tín hiệu duy nhất: mức độ luôn kèm chữ (Critical, High…).
- Biểu đồ và donut có `role="img"` và `aria-label` mô tả số liệu.
- Điều hướng bằng bàn phím được toàn bộ; thứ tự Tab theo thứ tự đọc.

## 8. Responsive

| Viewport | Quy tắc |
|---|---|
| ≥ 1280px | Bố cục đầy đủ như mục 4–5 |
| 1024–1279px | Hàng hai cột chuyển một cột; KPI giữ 5 cột hoặc 3+2 |
| 768–1023px | Sidebar thành drawer (hiện nút X); thẻ thiết bị 2 cột |
| < 768px | KPI 2 cột; hàng đợi dạng thẻ dọc; thanh tab dưới cố định, chừa padding đáy cho nội dung; bảng cuộn ngang trong container riêng |

Frame mobile cao theo nội dung (hug), thanh tab dưới đặt tuyệt đối bám đáy; nội dung không được tràn ra ngoài frame hay bị thanh tab che.

## 9. Quy ước đặt tên (Figma / canvas / component)

Dùng dạng `Nhóm/Tên/Trạng thái`:

- Màn hình: `Screen/Overview – 1440`, `Screen/Overview – 390`, `Screen/Alerts – 1440`, `Screen/Devices – 1440`, `Screen/Attack scenarios – 1440`.
- Khối: `Sidebar/Nav`, `Topbar/Status`, `Header/Title`, `Section/KPI-Row`, `Section/Investigation-Queue`, `Section/Top-Rules-Table`.
- Thành phần: `Card/KPI`, `Card/Severity-Mix`, `Card/Alerts-Per-Hour`, `Card/Top-Sources`, `Row/Alert`, `Row/Rule`, `Chip/Live`, `Button/Auto-refresh`, `User/Profile`, `TabBar/Bottom`.
- Biến thể: `Button/Primary/Hover`, `Card/KPI/Critical`.
- Không để tên mặc định (`div`, `Frame 123`). Tên layer tiếng Anh, viết thường có dấu gạch ngang cho class CSS.

## 10. Quy trình làm việc của agent

1. **Đọc trước.** Mở trang và component liên quan, xác định token nào đã có, không tạo trùng.
2. **Thay đổi nhỏ, từng phần.** Một nhiệm vụ một nhóm thay đổi; không refactor ngoài phạm vi.
3. **Dùng lại.** Nếu một kiểu (chip, nút, hàng bảng) đã tồn tại, dùng lại; chỉ tạo mới khi thật sự cần và đặt vào hệ token.
4. **Kiểm tra bằng ảnh.** Chụp trang ở 1440px, 1024px và 390px, so với thiết kế; đính kèm ảnh khi báo cáo.
5. **Báo cáo.** Nêu: đã đổi gì, đổi ở file nào, điều gì chưa kiểm tra được, điều gì cần người xác nhận. Không tuyên bố "đã xong" khi chưa chạy hoặc chưa xem kết quả.
6. **Không đoán.** Thiếu thông tin (stack, lệnh, dữ liệu) thì hỏi một câu cụ thể thay vì tự bịa.
7. **Commit.** Thông điệp ngắn, dạng `ui(alerts): fix control heights in filter bar`; mỗi commit một ý.

## 11. Definition of Done (đánh dấu đủ mới coi là xong)

- [ ] H1 cách topbar ≥ 32px ở cả 4 trang
- [ ] Mọi control trong một hàng cùng cao 40px; nhãn cùng dòng
- [ ] Không có tên máy / ID / IP / mã rule bị ngắt dòng
- [ ] Giá trị 0 hiển thị thanh rỗng; phần trăm một dòng
- [ ] Select hiển thị đủ chữ
- [ ] Chỉ còn ba kiểu nút; không còn nút cam hay bóng cứng
- [ ] Nhãn biểu đồ và KPI đổi theo bộ lọc 1h / 24h / 7d
- [ ] Hai hàng hai cột có cạnh cột phải thẳng nhau
- [ ] Topbar sticky không để lộ nội dung phía dưới khi cuộn
- [ ] Tương phản chữ phụ đạt AA; hover và focus-visible có mặt
- [ ] Đã kiểm tra ở 1440 / 1024 / 390 và đính ảnh
- [ ] Dữ liệu, API và route không đổi

## 12. Cần bổ sung (điền trước khi giao cho agent)

> Những mục dưới đây tôi không có thông tin; hãy điền hoặc để agent đọc từ repo.

- Stack front-end (framework, CSS approach, thư viện biểu đồ): `[điền]`
- Đường dẫn code các trang và component: `[điền]`
- Lệnh chạy dev / build / lint / test: `[điền]`
- Quy ước test E2E (Playwright) và cách chạy kịch bản nghiệm thu VNPT N4.2: `[điền]`
- Nguồn dữ liệu (endpoint, polling interval của Auto-refresh): `[điền]`
- Quy tắc nhánh và review: `[điền]`