// Threat Z Lens (Service Worker Part)
const CACHE_NAME = "threat-z-lens-1.2.0";
// Section: Static UI Assets to Pre-Cache on Install
const STATIC_ASSETS = [
  "./index.html",
  "./style.css",
  "./script.js",
  "./manifest.json",
  "./icon192.png",
  "./icon512.png"
];
// Method to Install Service Worker and Pre-Cache Application Shell
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});
// Method to Activate Service Worker and Purge Outdated Caches
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        // Loop to Delete Outdated Cache Entries
        cacheNames.map((name) => {
          // Check if Cache Name Differs from Current Version
          if (name !== CACHE_NAME) {
            return caches.delete(name);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});
// Method to Intercept Network Requests and Handle Offline Caching
self.addEventListener("fetch", (event) => {
  const requestUrl = new URL(event.request.url);
  // Check if Request Is Dynamic API Endpoint or External Lookup
  if (requestUrl.pathname.startsWith("/api/") || requestUrl.origin !== self.location.origin) {
    event.respondWith(
      fetch(event.request).catch(() => {
        return new Response(
          JSON.stringify({
            error: "Offline mode active. Live intelligence lookups require internet connectivity.",
            offline: true
          }),
          {
            status: 503,
            headers: { "Content-Type": "application/json" }
          }
        );
      })
    );
    return;
  }
  // Network-First Strategy for Static Application Shell
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        // Check if Network Response Is Valid 200 Basic Asset
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === "basic") {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request).then((cachedResponse) => {
          // Check if Requested Asset Exists in Cache
          if (cachedResponse) {
            return cachedResponse;
          }
          // Check if Request Is Navigation Mode for Offline Fallback
          if (event.request.mode === "navigate") {
            return caches.match("./index.html");
          }
        });
      })
  );
});
// End of Program (Program by Zidaan)