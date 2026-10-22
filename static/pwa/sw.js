// Service Worker cho RC4 Lab (PWA)
const CACHE_NAME = 'rc4-lab-v1';
const STATIC_ASSETS = [
  '/',
  '/manifest.webmanifest',
  '/static/pwa/icon-192.png',
  '/static/pwa/icon-512.png',
  '/static/pwa/icon-maskable.png',
  '/static/pwa/favicon.ico',
  'https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css',
  'https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.js',
  'https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/contrib/auto-render.min.js',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap'
];

// Cài đặt Service Worker và lưu cache tĩnh
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Cố gắng cache các static assets cơ bản, bỏ qua lỗi nếu một số tài nguyên ngoại mạng chưa sẵn sàng
      return Promise.allSettled(
        STATIC_ASSETS.map((url) => cache.add(url).catch((err) => console.log('SW cache skip:', url, err)))
      );
    })
  );
  self.skipWaiting();
});

// Kích hoạt Service Worker và xóa cache cũ nếu có
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cache) => {
          if (cache !== CACHE_NAME) {
            return caches.delete(cache);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Xử lý fetch request
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // BỎ QUA WebSocket của NiceGUI và các phương thức không phải GET
  if (
    event.request.method !== 'GET' ||
    url.pathname.includes('/_nicegui_ws') ||
    url.pathname.startsWith('/_nicegui') ||
    url.protocol.startsWith('ws')
  ) {
    return;
  }

  // Đối với tài nguyên static (ảnh, fonts, css, js) -> Cache First, fallback Network
  if (
    url.pathname.startsWith('/static/') ||
    url.hostname.includes('cdn.jsdelivr.net') ||
    url.hostname.includes('fonts.googleapis.com') ||
    url.hostname.includes('fonts.gstatic.com')
  ) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
          return networkResponse;
        });
      })
    );
    return;
  }

  // Đối với điều hướng trang HTML chính -> Network First, fallback Cache
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        return response;
      })
      .catch(() => {
        return caches.match(event.request).then((cached) => {
          if (cached) return cached;
          return caches.match('/');
        });
      })
  );
});
