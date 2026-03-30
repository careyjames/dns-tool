const CACHE_VERSION = 'SW_VERSION_PLACEHOLDER';
const CACHE_NAME = 'dnstool-' + CACHE_VERSION;
const PAGES_CACHE = 'dnstool-pages-' + CACHE_VERSION;
const MAX_CACHED_PAGES = 20;

const IMMUTABLE_ASSETS = [
  '/static/css/foundation.min.css',
  '/static/css/custom.min.css',
  '/static/js/foundation.min.js',
  '/static/js/main.min.js',
  '/static/favicon.svg'
];

const OFFLINE_PAGE = '<!DOCTYPE html><html lang="en"><head>' +
  '<meta charset="UTF-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
  '<meta name="theme-color" content="#0d1117">' +
  '<meta name="apple-mobile-web-app-capable" content="yes">' +
  '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">' +
  '<title>Offline \u2014 DNS Tool</title>' +
  '<style>' +
  '*{box-sizing:border-box;margin:0;padding:0}' +
  'body{background:#0d1117;color:#dee2e6;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;min-height:100dvh;text-align:center;padding:env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left)}' +
  '.offline-card{background:#21262d;border:1px solid #30363d;border-radius:12px;padding:2.5rem 2rem;max-width:420px;width:90%}' +
  '.offline-icon{width:64px;height:64px;margin:0 auto 1.5rem;opacity:0.7}' +
  '.offline-icon svg{width:100%;height:100%}' +
  'h1{font-size:1.35rem;font-weight:600;margin-bottom:0.5rem;color:#e6edf3}' +
  'p{color:#8b949e;font-size:0.9rem;line-height:1.6;margin-bottom:1rem}' +
  '.retry-btn{display:inline-block;background:#238636;color:#fff;border:1px solid rgba(240,246,252,0.1);border-radius:6px;padding:0.5rem 1.5rem;font-size:0.875rem;font-weight:500;cursor:pointer;text-decoration:none;transition:background 0.15s}' +
  '.retry-btn:hover{background:#2ea043}' +
  '.brand{color:#8b949e;font-size:0.75rem;margin-top:1.5rem;letter-spacing:0.03em}' +
  '</style></head><body><div class="offline-card">' +
  '<div class="offline-icon"><svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">' +
  '<circle cx="32" cy="32" r="30" stroke="#30363d" stroke-width="2"/>' +
  '<path d="M20 38c0-6.627 5.373-12 12-12s12 5.373 12 12" stroke="#8b949e" stroke-width="2" stroke-linecap="round" fill="none"/>' +
  '<path d="M26 38c0-3.314 2.686-6 6-6s6 2.686 6 6" stroke="#8b949e" stroke-width="2" stroke-linecap="round" fill="none"/>' +
  '<circle cx="32" cy="40" r="2.5" fill="#8b949e"/>' +
  '<line x1="18" y1="18" x2="46" y2="46" stroke="#da3633" stroke-width="2.5" stroke-linecap="round"/>' +
  '</svg></div>' +
  '<h1>You Are Offline</h1>' +
  '<p>DNS Tool requires an internet connection to query live DNS records and perform domain analysis.</p>' +
  '<p>Check your connection and try again.</p>' +
  '<button class="retry-btn" onclick="location.reload()">Retry Connection</button>' +
  '<div class="brand">DNS Tool \u2014 Domain Security Intelligence</div>' +
  '</div></body></html>';

const CACHEABLE_PAGES = [
  /^\/analysis\/\d+/,
  /^\/stats$/,
  /^\/changelog$/,
  /^\/approach$/,
  /^\/roe$/
];

function isPageCacheable(pathname) {
  for (const pattern of CACHEABLE_PAGES) {
    if (pattern.test(pathname)) return true;
  }
  return false;
}

function trimPageCache() {
  return caches.open(PAGES_CACHE).then(function(cache) {
    return cache.keys().then(function(keys) {
      if (keys.length <= MAX_CACHED_PAGES) return;
      const toDelete = keys.slice(0, keys.length - MAX_CACHED_PAGES);
      return Promise.all(toDelete.map(function(key) { return cache.delete(key); }));
    });
  });
}

globalThis.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return Promise.all(IMMUTABLE_ASSETS.map(function(asset) {
        return cache.add(asset).catch(function() { /* asset unavailable — skip */ });
      }));
    })
  );
  globalThis.skipWaiting();
});

globalThis.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(names) {
      return Promise.all(
        names.filter(function(name) {
          return name !== CACHE_NAME && name !== PAGES_CACHE;
        }).map(function(name) { return caches.delete(name); })
      );
    })
  );
  event.waitUntil(globalThis.clients.claim());
});

globalThis.addEventListener('fetch', function(event) {
  const url = new URL(event.request.url);

  if (event.request.method !== 'GET') return;

  if (url.pathname === '/' || url.pathname === '') return;

  if (!url.pathname.startsWith('/static/')) {
    if (event.request.mode === 'navigate') {
      event.respondWith(
        fetch(event.request).then(function(response) {
          if (response.ok && isPageCacheable(url.pathname)) {
            const clone = response.clone();
            caches.open(PAGES_CACHE).then(function(cache) {
              cache.put(event.request, clone);
              trimPageCache();
            });
          }
          return response;
        }).catch(function() {
          return caches.open(PAGES_CACHE).then(function(cache) {
            return cache.match(event.request);
          }).then(function(cached) {
            if (cached) return cached;
            return new Response(OFFLINE_PAGE, {
              headers: {'Content-Type': 'text/html'}
            });
          });
        })
      );
    } else {
      event.respondWith(
        fetch(event.request).catch(function() {
          return caches.match(event.request).then(function(cached) {
            return cached || new Response('', {status: 408, statusText: 'Offline'});
          });
        })
      );
    }
    return;
  }

  const isVersioned = url.search.includes('v=');

  if (isVersioned) {
    event.respondWith(
      fetch(event.request).then(function(response) {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(function(cache) {
            cache.put(event.request, clone);
          });
        }
        return response;
      }).catch(function() {
        return caches.match(event.request);
      })
    );
  } else {
    event.respondWith(
      caches.match(event.request).then(function(cached) {
        if (cached) return cached;
        return fetch(event.request).then(function(response) {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(function(cache) {
              cache.put(event.request, clone);
            });
          }
          return response;
        }).catch(function() {
          return new Response('', {status: 408, statusText: 'Offline'});
        });
      })
    );
  }
});
