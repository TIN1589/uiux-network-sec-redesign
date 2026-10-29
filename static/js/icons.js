/**
 * Local SVG icon renderer.
 *
 * Keeps the existing Font Awesome-compatible class names used throughout the
 * templates, while rendering every icon from a small, local SVG path set.
 * This removes the dashboard's runtime dependency on the Font Awesome CDN and
 * also covers icons inserted later by HTMX or changed by theme controls.
 */
(function localIconRenderer() {
  'use strict';

  const ICONS = Object.freeze({
    'arrow-up-from-bracket': '<path d="M12 15V3m0 0L7 8m5-5 5 5"/><path d="M4 12v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6"/>',
    'arrow-up-right-from-square': '<path d="M15 3h6v6m0-6-10 10"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    'bars': '<path d="M4 6h16M4 12h16M4 18h16"/>',
    'border-all': '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    'caret-right': '<path d="m9 6 6 6-6 6"/>',
    'check': '<path d="m5 12 4 4L19 6"/>',
    'chevron-down': '<path d="m6 9 6 6 6-6"/>',
    'circle-exclamation': '<circle cx="12" cy="12" r="9"/><path d="M12 8v4m0 4h.01"/>',
    'database': '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>',
    'desktop': '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    'file-arrow-down': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M12 18v-6m-3 3 3 3 3-3"/>',
    'key': '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m11 12 9-9 3 3-2 2 2 2-3 3"/>',
    'magnifying-glass': '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.35-4.35"/>',
    'magnifying-glass-chart': '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.35-4.35M8 12l2-3 2 2 2-4"/>',
    'moon': '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
    'network-wired': '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5 16v-4h14v4"/>',
    'pen-to-square': '<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>',
    'plus-circle': '<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
    'right-from-bracket': '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    'right-to-bracket': '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/>',
    'route': '<circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M8.5 19h3a4 4 0 0 0 4-4V9a4 4 0 0 1 4-4h-1"/>',
    'server': '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
    'shield-halved': '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 2v20"/>',
    'sitemap': '<rect x="9" y="3" width="6" height="4" rx="1"/><rect x="2" y="17" width="6" height="4" rx="1"/><rect x="9" y="17" width="6" height="4" rx="1"/><rect x="16" y="17" width="6" height="4" rx="1"/><path d="M12 7v5M5 17v-5h14v5M12 12v5"/>',
    'sliders': '<path d="M4 7h6m4 0h6M4 17h10m4 0h2"/><circle cx="12" cy="7" r="2"/><circle cx="16" cy="17" r="2"/>',
    'square-plus': '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M12 8v8M8 12h8"/>',
    'sun': '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
    'trash': '<path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m-6 5v6m4-6v6"/>',
    'triangle-exclamation': '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4m0 4h.01"/>',
    'user': '<circle cx="12" cy="8" r="4"/><path d="M6 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/>',
    'user-shield': '<circle cx="9" cy="7" r="3"/><path d="M3 19v-1.5a4 4 0 0 1 4-4h3"/><path d="M17 12c0 3-2 4.5-4 5.5-2-1-4-2.5-4-5.5V9.5l4-1.5 4 1.5z"/>',
    'xmark': '<path d="m18 6-12 12M6 6l12 12"/>'
  });

  function getIconName(host) {
    return Array.from(host.classList).find((name) =>
      name.startsWith('fa-') && name !== 'fa-solid' && name !== 'fa-regular' && name !== 'fa-brands'
    )?.slice(3);
  }

  function renderIcon(host) {
    if (!(host instanceof Element)) return;
    const name = getIconName(host);
    const paths = ICONS[name];
    if (!paths) return;
    if (host.dataset.localIcon === name && host.querySelector('svg.local-icon')) return;

    host.dataset.localIcon = name;
    if (!host.classList.contains('local-icon-host')) {
      host.classList.add('local-icon-host');
    }
    host.innerHTML = `<svg class="local-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${paths}</svg>`;
  }

  function scan(root) {
    if (!(root instanceof Element || root instanceof Document)) return;
    if (root instanceof Element && root.matches('i.fa-solid, i.fa-regular')) renderIcon(root);
    root.querySelectorAll('i.fa-solid, i.fa-regular').forEach(renderIcon);
  }

  function start() {
    scan(document);
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes') {
          renderIcon(mutation.target);
          return;
        }
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) scan(node);
        });
      });
    });
    observer.observe(document.documentElement, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['class']
    });

    // HTMX hoán đổi nội dung fragment động (như #main-content, #alerts-table-container) mà không tải lại toàn trang.
    // Bắt buộc quét lại cây DOM mới được hoán đổi để chuyển hóa thẻ placeholder <i> thành SVG nội tuyến,
    // ngăn ngừa hiện tượng icon hiển thị trắng hoặc lệch layout khi không có roundtrip tới CDN FontAwesome.
    document.addEventListener('htmx:afterSwap', function(e) {
      scan(e.target);
    });

    // Khi HTMX nạp và kích hoạt các phần tử con mới (e.detail.elt),
    // kích hoạt quét đồng bộ để bảo đảm mọi icon trong partial template đều được hydrat hóa.
    document.addEventListener('htmx:load', function(e) {
      scan(e.detail && e.detail.elt ? e.detail.elt : e.target);
    });
  }

  /**
   * Quét và chuyển đổi các phần tử placeholder icon thành SVG nội tuyến.
   *
   * Cung cấp API toàn cục để các script khác (như bộ lọc HTMX, drawer chi tiết, modal,
   * hoặc bộ điều khiển theme Standalone) chủ động yêu cầu hydrat hóa lại icon
   * sau khi cập nhật cây DOM mà không phụ thuộc hoàn toàn vào MutationObserver.
   *
   * @param {Element|Document} [root=document] - Nút gốc DOM cần quét tìm các thẻ <i> chứa class icon.
   * @returns {void}
   */
  window.refreshLocalIcons = (root) => scan(root || document);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();
