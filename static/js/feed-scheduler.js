/**
 * Điều phối lịch trình cập nhật dòng log SOC trực tiếp (Feed Scheduler).
 *
 * Tách biệt rõ ràng: HTMX đảm nhiệm kết nối mạng và hoán đổi DOM fragment;
 * Module JavaScript thuần này chỉ duy trì một đồng hồ setInterval duy nhất,
 * tự động thích ứng với Reduced Motion (6000ms vs 2400ms) và tạm dừng khi tab ẩn.
 */

const FAST = 2400;
const SLOW = 6000;

/**
 * Xác định chu kỳ làm mới dựa trên tùy chọn giảm chuyển động của người dùng.
 *
 * @param {boolean} reduced - Người dùng có bật prefers-reduced-motion hay không.
 * @returns {number} Thời gian chu kỳ tính bằng mili-giây (6000ms nếu reduced, ngược lại 2400ms).
 */
export const intervalFor = (reduced) => (reduced ? SLOW : FAST);

/**
 * Kiểm tra phần tử feed có đang hiển thị thực tế trên màn hình hay không.
 * Ngăn chặn việc đồng thời kích hoạt poll cho cả container Desktop và Mobile.
 *
 * @param {HTMLElement} el - Phần tử container feed cần kiểm tra.
 * @param {Document} doc - Đối tượng Document.
 * @returns {boolean} True nếu tab đang hiển thị và phần tử không bị display: none.
 */
export const isActive = (el, doc = document) =>
  doc.visibilityState === 'visible' && el.offsetParent !== null;

/**
 * Khởi động bộ điều phối phát sự kiện 'feed-tick' tới các phần tử [data-feed].
 *
 * @param {object} options - Cấu hình tùy chọn môi trường (root, htmx, mq).
 */
export function startFeeds({
  root = document,
  htmx = window.htmx,
  mq = (typeof window !== 'undefined' && typeof window.matchMedia === 'function')
    ? window.matchMedia('(prefers-reduced-motion: reduce)')
    : { matches: false, addEventListener: () => {} },
} = {}) {
  let timer;

  const tick = () => {
    root.querySelectorAll('[data-feed]').forEach((el) => {
      if (isActive(el, root.ownerDocument || root)) {
        if (htmx && typeof htmx.trigger === 'function') {
          htmx.trigger(el, 'feed-tick');
        }
      }
    });
  };

  const arm = () => {
    if (timer) clearInterval(timer);
    timer = setInterval(tick, intervalFor(mq.matches));
  };

  arm();

  if (mq.addEventListener) {
    mq.addEventListener('change', arm);
  }

  if (typeof window !== 'undefined' && window.addEventListener) {
    window.addEventListener('pagehide', () => {
      if (timer) clearInterval(timer);
    });
  }
}
