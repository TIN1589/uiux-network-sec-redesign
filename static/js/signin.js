/**
 * Điểm khởi nhập JavaScript chính (Entry Module) cho màn hình đăng nhập VNPT SOC.
 * Tuân thủ tiêu chuẩn ES Modules, không sử dụng bundler hay thư viện bên thứ ba.
 */

import './htmx-glue.js';
import { initPasswordToggle } from './password-toggle.js';
import { initCapsLockHint } from './caps-lock.js';
import { initDemoAccounts } from './demo-accounts.js';
import { startFeeds } from './feed-scheduler.js';
import { authenticateWithPasskey, isWebAuthnAvailable } from './webauthn-client.js';

function showPasskeyFeedback(message) {
  const feedback = document.getElementById('auth-feedback');
  if (!feedback) return;
  const alert = document.createElement('div');
  alert.className = 'auth-alert';
  alert.setAttribute('role', 'alert');
  alert.textContent = message;
  feedback.replaceChildren(alert);
}

function setPasskeyRequestState(isPending) {
  const button = document.getElementById('passkey-signin-btn');
  const status = document.getElementById('passkey-status');

  if (button) {
    button.disabled = isPending || button.dataset.passkeyUnavailable === 'true';
    if (isPending) {
      button.setAttribute('aria-busy', 'true');
    } else {
      button.removeAttribute('aria-busy');
    }
  }

  if (status) status.hidden = !isPending;
}

async function signInWithPasskey() {
  const button = document.getElementById('passkey-signin-btn');
  if (!button || button.disabled) return;
  setPasskeyRequestState(true);
  document.getElementById('auth-feedback')?.replaceChildren();
  try {
    const remember = document.getElementById('remember-session')?.checked ?? true;
    await authenticateWithPasskey(remember);
    window.location.assign('/');
  } catch (error) {
    showPasskeyFeedback(error.message || 'Passkey sign-in failed');
    setPasskeyRequestState(false);
  }
}

function initPasskeySignIn() {
  const button = document.getElementById('passkey-signin-btn');
  if (!button) return;
  if (!isWebAuthnAvailable()) {
    button.dataset.passkeyUnavailable = 'true';
    button.disabled = true;
    button.title = 'Passkeys are not supported by this browser';
    return;
  }
  button.addEventListener('click', () => void signInWithPasskey());
}

/**
 * Khôi phục trạng thái tương tác của form sau khi trình duyệt phục hồi trang từ BFCache.
 *
 * @returns {void}
 */
function resetSignInRequestState() {
  const form = document.querySelector('.auth-form');
  const button = document.getElementById('signin-btn');

  form?.classList.remove('htmx-request');
  button?.classList.remove('htmx-request');

  if (button) {
    button.disabled = false;
    button.removeAttribute('disabled');
    button.removeAttribute('aria-disabled');
    button.removeAttribute('aria-busy');
  }

  setPasskeyRequestState(false);
}

/**
 * Kiểm tra sự kiện pageshow có bắt nguồn từ thao tác Back/Forward hay không.
 *
 * @param {PageTransitionEvent} event - Sự kiện pageshow của trình duyệt.
 * @returns {boolean} True khi trang được phục hồi từ lịch sử điều hướng.
 */
function isHistoryRestore(event) {
  if (event.persisted) return true;

  const [navigationEntry] = performance.getEntriesByType?.('navigation') || [];
  return navigationEntry?.type === 'back_forward';
}

/**
 * Đồng bộ trang đăng nhập với phiên hiện tại sau khi Back/Forward khôi phục DOM cũ.
 *
 * @param {PageTransitionEvent} event - Sự kiện pageshow của trình duyệt.
 * @returns {Promise<void>}
 */
async function reconcileHistoryRestore(event) {
  // BFCache có thể giữ nguyên class HTMX và thuộc tính disabled từ lúc request đang chạy.
  resetSignInRequestState();
  if (!isHistoryRestore(event)) return;

  try {
    const response = await fetch('/api/auth/me', {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return;

    const session = await response.json();
    if (session.authenticated) {
      window.location.replace('/');
    }
  } catch (_error) {
    // Khi offline, giữ form ở trạng thái idle để người dùng có thể thử lại.
  }
}

// Khởi chạy các tương tác giao diện sau khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', () => {
  initPasswordToggle();
  initCapsLockHint();
  initDemoAccounts();
  startFeeds();
  initPasskeySignIn();
});

window.addEventListener('pageshow', (event) => {
  void reconcileHistoryRestore(event);
});
