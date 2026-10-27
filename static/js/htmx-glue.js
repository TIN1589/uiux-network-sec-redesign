/**
 * Điều phối vòng đời và xử lý hoán đổi phân mảnh HTMX cho trang đăng nhập VNPT SOC.
 *
 * Mặc định HTMX từ chối hoán đổi DOM đối với các mã lỗi HTTP 4xx.
 * Bộ lắng nghe này can thiệp vào sự kiện htmx:beforeSwap, cho phép hoán đổi
 * fragment lỗi auth/_feedback.html khi nhận mã 401 hoặc 422.
 */
document.addEventListener('htmx:beforeSwap', (evt) => {
  const status = evt.detail.xhr ? evt.detail.xhr.status : 0;
  if (status === 401 || status === 422) {
    evt.detail.shouldSwap = true;
    evt.detail.isError = false;
  }
});

/**
 * Quản lý tiêu điểm (Focus Management) theo chuẩn Accessibility WCAG 2.1 AA.
 * Tự động đưa con trỏ chuột về ô nhập Username sau khi hoán đổi thông báo lỗi.
 */
document.addEventListener('htmx:afterSwap', (evt) => {
  const target = evt.detail.target;
  if (target && target.id === 'auth-feedback') {
    const focusMarker = target.querySelector('[data-focus="username"]');
    if (focusMarker) {
      const userInput = document.getElementById('field-username') || document.querySelector('input[name="username"]');
      if (userInput) {
        userInput.focus();
        userInput.select();
      }
    }
  }
});
