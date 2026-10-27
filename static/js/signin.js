/**
 * Điểm khởi nhập JavaScript chính (Entry Module) cho màn hình đăng nhập VNPT SOC.
 * Tuân thủ tiêu chuẩn ES Modules, không sử dụng bundler hay thư viện bên thứ ba.
 */

import './htmx-glue.js';
import { initPasswordToggle } from './password-toggle.js';
import { initCapsLockHint } from './caps-lock.js';
import { initDemoAccounts } from './demo-accounts.js';
import { startFeeds } from './feed-scheduler.js';

// Khởi chạy các tương tác giao diện sau khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', () => {
  initPasswordToggle();
  initCapsLockHint();
  initDemoAccounts();
  startFeeds();
});
