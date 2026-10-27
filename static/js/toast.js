/**
 * TOAST NOTIFICATION ENGINE
 * Lightweight, accessible Vanilla ES6+ toast system
 */

/**
 * Hiển thị thông báo nổi (Accessible Toast Notification) ở góc màn hình.
 * 
 * Tự động khởi tạo container stack nếu chưa tồn tại trong DOM với thuộc tính
 * role="status" và aria-live="polite" để hỗ trợ trình đọc màn hình (Screen Readers).
 *
 * @param {'dark'|'light'|'error'|'success'} style - Phong cách hiển thị của toast item.
 * @param {string} message - Nội dung thông báo cần hiển thị đến người dùng.
 * @returns {void}
 */
export function showToast(style = 'dark', message = '') {
  let stack = document.getElementById('toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toast-stack';
    stack.className = 'toast-stack';
    stack.setAttribute('role', 'status');
    stack.setAttribute('aria-live', 'polite');
    document.body.appendChild(stack);
  }

  const toast = document.createElement('div');
  const safeMsg = escapeHtml(message);
  
  let dotClass = 'dot-lime';
  let toastClass = 'toast-dark';

  if (style === 'error') {
    toastClass = 'toast-error';
    dotClass = 'dot-critical';
  } else if (style === 'light') {
    toastClass = 'toast-light';
    dotClass = 'dot-dark';
  } else if (style === 'success') {
    toastClass = 'toast-dark';
    dotClass = 'dot-lime';
  }

  toast.className = `toast-item ${toastClass}`;
  toast.innerHTML = `<span class="status-dot ${dotClass}" aria-hidden="true"></span><span>${safeMsg}</span>`;

  stack.appendChild(toast);

  // Auto-dismiss after 3.2 seconds
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(12px) scale(0.96)';
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

window.showToast = showToast;
