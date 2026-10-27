/**
 * Module quản lý ẩn/hiện mật khẩu sử dụng cơ chế Event Delegation (Không gắn ID cứng).
 *
 * Cập nhật thuộc tính ARIA (aria-label, aria-pressed) và hoán đổi SVG icon
 * nhằm đảm bảo khả năng tương thích toàn diện với thiết bị đọc màn hình (Screen Reader).
 */

const EYE_SVG = `
<svg class="auth-field__eye-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
  <circle cx="12" cy="12" r="3" />
</svg>
`.trim();

const EYE_OFF_SVG = `
<svg class="auth-field__eye-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
  <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
  <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
  <line x1="2" y1="2" x2="22" y2="22" />
</svg>
`.trim();

/**
 * Khởi tạo bộ bắt sự kiện ẩn/hiện mật khẩu gắn trên phạm vi root.
 *
 * @param {HTMLElement|Document} root - Phạm vi phần tử DOM cần theo dõi sự kiện click.
 */
export function initPasswordToggle(root = document) {
  root.addEventListener('click', (evt) => {
    const btn = evt.target.closest('[data-toggle-password]');
    if (!btn) return;

    const control = btn.closest('.auth-field__control') || btn.parentElement;
    if (!control) return;

    const input = control.querySelector('input');
    if (!input) return;

    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';

    btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    btn.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
    btn.innerHTML = isPassword ? EYE_OFF_SVG : EYE_SVG;

    // Giữ tiêu điểm trên ô nhập mật khẩu sau khi bấm toggle
    input.focus();
  });
}
