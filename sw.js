const CACHE = "vba-v3";
const FILES = ["./", "./manifest.json", "./icon.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)));
  self.skipWaiting();
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

// Network-first: a fresh deploy is picked up immediately whenever the device
// is online. The cache is only a fallback for offline PWA use, and is kept
// warm with whatever was last successfully fetched.
self.addEventListener("fetch", e => {
  if (new URL(e.request.url).pathname.startsWith("/api/")) {
    e.respondWith(fetch(e.request));
    return;
  }
  e.respondWith(
    fetch(e.request)
      .then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
