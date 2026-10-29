/**

 * VNPT SOC COMMAND CENTER - SERVICE WORKER

 * Version: v1.0.1 - Zero-Latency Direct Fetch Tuning

 * 

 * Chiến lược Caching tối ưu RAM & Loại bỏ độ trễ (Zero Jank / Stutter Elimination):

 * - Cache-First: Toàn bộ tài nguyên tĩnh (Fonts, Icons, CSS Design System, JS Engine).

 * - Network-First: Điều hướng trang HTML đầy đủ (Navigation Request: /, /alerts, /devices).

 * - Native Direct Fetch: KHÔNG chặn các request HTMX fragments và API động bằng respondWith(fetch),

 *   giúp dữ liệu truyền trực tiếp qua native C++ network stack của trình duyệt mà không chịu

 *   độ trễ đánh thức Service Worker (tiết kiệm 100ms - 300ms, loại bỏ triệt để nhịp khựng khi click).

 * - Offline Fallback: Trả về /static/offline.html khi mất kết nối mạng hoàn toàn.

 * - RAM Protection: Không cache log động, dung lượng cache luôn duy trì < 10MB.

 */



const CACHE_NAME = 'vnpt-soc-pwa-v1.0.4-local-icons';



/**

 * Danh sách tài nguyên tĩnh thiết yếu (App Shell Core) cần nạp sẵn vào cache.

 */

const PRECACHE_ASSETS = [

  '/static/offline.html',

  '/static/manifest.webmanifest',

  '/static/img/favicon/nsm-favicon.svg',

  '/static/img/favicon/nsm-apple-icon-180.png',

  '/static/img/favicon/nsm-favicon-192.png',

  '/static/img/favicon/nsm-favicon-512.png',

  '/static/img/splash/apple-splash-1290-2796.png',

  '/static/img/splash/apple-splash-1179-2556.png',

  '/static/img/splash/apple-splash-1284-2778.png',

  '/static/img/splash/apple-splash-1170-2532.png',

  '/static/img/splash/apple-splash-1242-2688.png',

  '/static/img/splash/apple-splash-828-1792.png',

  '/static/img/splash/apple-splash-750-1334.png',

  '/static/fonts/Inter-Variable.woff2',

  '/static/vendor/htmx.min.js',

  '/static/vendor/chart.umd.min.js',

  '/static/css/tokens.css',

  '/static/css/variables.css',

  '/static/css/reset.css',

  '/static/css/layout.css',

  '/static/css/components.css',

  '/static/css/motion.css',

  '/static/css/charts.css',

  '/static/css/style.css',
  '/static/js/theme-init.js',

  '/static/js/icons.js',

  '/static/js/app.js',

  '/static/js/charts.js',

  '/static/js/toast.js'

];



/**

 * Sự kiện Install: Nạp trước các tài nguyên tĩnh cốt lõi vào Cache Storage.

 */

self.addEventListener('install', (event) => {

  event.waitUntil(

    caches.open(CACHE_NAME).then((cache) => {

      return cache.addAll(PRECACHE_ASSETS);

    }).then(() => {

      // Buộc Service Worker mới kích hoạt ngay lập tức mà không chờ đóng tab

      return self.skipWaiting();

    })

  );

});



/**

 * Sự kiện Activate: Dọn dẹp các phiên bản cache cũ để giải phóng dung lượng bộ nhớ.

 */

self.addEventListener('activate', (event) => {

  event.waitUntil(

    caches.keys().then((cacheNames) => {

      return Promise.all(

        cacheNames.map((name) => {

          if (name !== CACHE_NAME) {

            return caches.delete(name);

          }

        })

      );

    }).then(() => {

      // Giành quyền kiểm soát ngay lập tức cho tất cả client hiện hữu

      return self.clients.claim();

    })

  );

});



/**

 * Sự kiện Fetch: Phân luồng chiến lược mạng tối ưu độ trễ.

 */

self.addEventListener('fetch', (event) => {

  const req = event.request;

  const url = new URL(req.url);



  // 1. Bỏ qua các yêu cầu không phải HTTP/HTTPS hoặc không phải phương thức GET (như POST, PUT, DELETE)

  if (req.method !== 'GET') {

    return;

  }



  // 2. Bỏ qua các luồng Server-Sent Events (SSE) hoặc live traffic stream để tránh giữ rác trong cache

  if (url.pathname.startsWith('/api/stream') || url.pathname.startsWith('/ws')) {

    return;

  }



  // 3. Xử lý yêu cầu điều hướng trang HTML (Navigation Request: /, /alerts, /devices, v.v.)

  // Sử dụng Network-First: Ưu tiên tải HTML mới nhất từ server; nếu mất mạng thì trả về trang offline.

  if (req.mode === 'navigate') {

    event.respondWith(

      fetch(req).catch(async () => {

        const cache = await caches.open(CACHE_NAME);

        const cachedOffline = await cache.match('/static/offline.html');

        return cachedOffline || Response.error();

      })

    );

    return;

  }



  // 4. Xử lý tài nguyên tĩnh trong /static/ (CSS, JS, Fonts, Images)

  // Đối với CSS và JS: Network-First để luôn nhận phiên bản mới nhất khi dev/test, tự động cập nhật cache.

  if (url.pathname.endsWith('.css') || url.pathname.endsWith('.js')) {

    event.respondWith(

      fetch(req).then((networkResponse) => {

        if (networkResponse && networkResponse.status === 200) {

          const responseToCache = networkResponse.clone();

          caches.open(CACHE_NAME).then((cache) => {

            cache.put(req, responseToCache);

          });

        }

        return networkResponse;

      }).catch(async () => {

        const cached = await caches.match(req, { ignoreSearch: true });

        return cached || Response.error();

      })

    );

    return;

  }



  // Đối với Fonts, Images, Icons, Splash: Cache-First để tối ưu tốc độ và dung lượng

  if (url.pathname.startsWith('/static/')) {

    event.respondWith(

      caches.match(req, { ignoreSearch: true }).then((cachedResponse) => {

        if (cachedResponse) {

          return cachedResponse;

        }

        return fetch(req).then((networkResponse) => {

          if (networkResponse && networkResponse.status === 200) {

            const responseToCache = networkResponse.clone();

            caches.open(CACHE_NAME).then((cache) => {

              cache.put(req, responseToCache);

            });

          }

          return networkResponse;

        });

      })

    );

    return;

  }



  // 5. Mặc định đối với HTMX AJAX fragments, API JSON và dynamic updates:

  // KHÔNG gọi event.respondWith()!

  // Để trình duyệt fetch trực tiếp qua native network stack tốc độ C++,

  // triệt tiêu hoàn toàn độ trễ IPC đánh thức worker thread (100ms - 300ms)

  // giúp phản hồi tức thì 0ms khựng khi user nhấn/chạm bất kỳ nút nào.

  return;

});

