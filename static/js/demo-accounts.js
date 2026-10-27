/**
 * Module hỗ trợ điền nhanh thông tin tài khoản demo cho kiểm thử viên.
 * Hoạt động thông qua thuộc tính data-demo-user và data-demo-pwd.
 */

/**
 * Khởi tạo bộ lắng nghe sự kiện bấm chọn tài khoản mẫu (Admin, Tier-2, Tier-1).
 *
 * @param {HTMLElement|Document} root - Phạm vi DOM chứa khối demo accounts.
 */
export function initDemoAccounts(root = document) {
  root.addEventListener('click', (evt) => {
    const chip = evt.target.closest('[data-demo-user]');
    if (!chip) return;

    const user = chip.getAttribute('data-demo-user');
    const pwd = chip.getAttribute('data-demo-pwd');

    const form = document.querySelector('.auth-form');
    if (!form) return;

    const userInput = form.querySelector('input[name="username"]');
    const pwdInput = form.querySelector('input[name="password"]');

    if (userInput && user) {
      userInput.value = user;
    }
    if (pwdInput && pwd) {
      pwdInput.value = pwd;
    }

    // Cập nhật trạng thái lựa chọn trực quan và khả năng truy cập ARIA
    const allChips = root.querySelectorAll('[data-demo-user]');
    allChips.forEach((c) => c.setAttribute('aria-pressed', 'false'));
    chip.setAttribute('aria-pressed', 'true');

    // Xóa phản hồi lỗi cũ khi người dùng chọn tài khoản mới
    const feedback = document.getElementById('auth-feedback');
    if (feedback) {
      feedback.innerHTML = '';
    }

    if (pwdInput) {
      pwdInput.focus();
    }
  });
}
