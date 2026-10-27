/**
 * Module nhận diện trạng thái phím Caps Lock trên ô nhập mật khẩu.
 * Sử dụng event delegation theo data-attribute data-capslock-hint.
 */

/**
 * Khởi tạo bộ lắng nghe trạng thái Caps Lock.
 *
 * @param {HTMLElement|Document} root - Phạm vi lắng nghe sự kiện nhập phím.
 */
export function initCapsLockHint(root = document) {
  const updateHint = (input, isCapsLockOn) => {
    const field = input.closest('.auth-field');
    if (!field) return;
    const hint = field.querySelector('[data-capslock-hint]');
    if (!hint) return;

    if (isCapsLockOn) {
      hint.removeAttribute('hidden');
    } else {
      hint.setAttribute('hidden', '');
    }
  };

  const handleKey = (evt) => {
    const input = evt.target;
    if (!input || input.tagName !== 'INPUT' || (input.type !== 'password' && input.type !== 'text')) {
      return;
    }
    if (typeof evt.getModifierState === 'function') {
      const isCaps = evt.getModifierState('CapsLock');
      updateHint(input, isCaps);
    }
  };

  root.addEventListener('keydown', handleKey);
  root.addEventListener('keyup', handleKey);

  // Ẩn cảnh báo khi người dùng chuyển tiêu điểm ra ngoài
  root.addEventListener('focusout', (evt) => {
    const input = evt.target;
    if (input && input.tagName === 'INPUT') {
      updateHint(input, false);
    }
  });
}
