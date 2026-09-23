// Renta Service Worker — minimal offline cache
const CACHE_NAME = 'renta-v1';
const PRECACHE = ['/', '/static/index.html', '/static/equips-renta.png', '/static/icon-192.png', '/static/icon-512.png'];

self.addEventListener('install', (event) => {
    event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE)).catch(() => {}));
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (url.pathname.startsWith('/api/')) return;
    event.respondWith(
        caches.match(event.request).then(cached => cached || fetch(event.request).then(res => {
            if (event.request.method === 'GET' && res.status === 200) {
                const clone = res.clone();
                caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone)).catch(() => {});
            }
            return res;
        }).catch(() => cached))
    );
});