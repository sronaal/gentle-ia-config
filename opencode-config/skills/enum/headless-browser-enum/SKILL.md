---
name: headless-browser-enum
description: Headless browser automation for recon — SPAs, JavaScript-heavy apps, postMessage, DOM events, API calls, and client-side attack surface enumeration
version: 1.0.0
phase: enum
category: enumeration
tags: [headless, browser, spa, javascript, dom]
tools: [playwright, puppeteer, selenium, python3, node]
difficulty: advanced
opsec_level: medium
time_estimate: 60m
severity_if_found: medium
mitre_attack:
  - T1040
  - T1082
---

## When to Use

- Target is a SPA (React, Vue, Angular, Svelte) returning minimal static HTML — traditional curl/grep misses everything
- Application depends heavily on client-side JavaScript for state management and API calls
- postMessage, DOM-based XSS, or client-side prototype pollution assessment in scope
- Service worker abuse or offline cache enumeration planned
- Need to capture XHR/fetch API calls that only fire after JS execution and user interaction

## What It Does

Launches instrumented headless browsers to enumerate the dynamic client-side attack surface:

- **Stealth browser setup** — configures Playwright/Puppeteer with patches for `navigator.webdriver`, Chrome runtime, and WebGL fingerprint evasion
- **SPA route enumeration** — extracts JavaScript route tables via React Fiber tree walking or Vue/Angular router introspection
- **API call interception** — logs every XHR/fetch/WebSocket request and response during navigation
- **postMessage listener enumeration** — discovers `window.addEventListener('message', ...)` handlers and checks for origin validation
- **Client-side storage extraction** — dumps localStorage, sessionStorage, and IndexedDB after authentication
- **DOM event listener discovery** — enumerates inline handlers and framework-bound events (ng-, v-on, @)
- **Service worker enumeration** — detects registered workers, their scope, and cache contents
- **Prototype pollution surface** — tests `__proto__` and `constructor.prototype` assignment sinks
- **Anti-bot fingerprint evasion** — patches webdriver, canvas, font, and WebGL fingerprinting surfaces

## Methodology

### Step 1: Stealth Browser Setup
```javascript
import { chromium } from 'playwright';
const browser = await chromium.launch({
  headless: true,
  args: ['--disable-blink-features=AutomationControlled','--no-sandbox','--window-size=1920,1080']
});
const context = await browser.newContext({
  userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
  viewport: { width: 1920, height: 1080 }
});
// Stealth patches — mask automation indicators
await context.addInitScript(() => {
  Object.defineProperty(navigator, 'webdriver', { get: () => false });
  window.chrome = { runtime: {} };
});
const page = await context.newPage();
// Speed optimization — block images/fonts/CSS during recon
await page.route('**/*.{png,jpg,jpeg,gif,svg,ico,css,woff,woff2}', r => r.abort());
```
**Key insight**: Blocking images/CSS speeds enumeration 3-5x. The JS execution is what matters — visual rendering is irrelevant for recon.

### Step 2: API Call Interception
```javascript
await page.route('**/*', async (route, request) => {
  const url = request.url();
  if (url.match(/\.(js|css|png|jpg|svg|woff2?)$/)) return route.continue();
  const response = await route.fetch();
  console.log(`[${request.method()}] ${url} → ${response.status()} (${(await response.text()).length}b)`);
});
await page.goto('https://TARGET.COM', { waitUntil: 'networkidle' });
// Trigger API calls through interaction
await page.click('a[href*="profile"]'); await page.waitForTimeout(2000);
await page.click('button[data-testid="submit"]'); await page.waitForTimeout(2000);
```
**Pro tip**: Look for internal API endpoints, GraphQL mutations in POST bodies, undocumented parameters, and JWTs in Authorization headers.

### Step 3: SPA Route Enumeration
```javascript
const routes = await page.evaluate(() => {
  // React Fiber walk — extract route configuration
  const root = document.getElementById('root');
  const fiberKey = Object.keys(root).find(k => k.startsWith('__reactFiber$'));
  if (fiberKey) {
    let fiber = root[fiberKey], found = [];
    const walk = (n) => {
      if (n?.memoizedState?.queue?.lastRenderedState?.routes)
        found.push(n.memoizedState.queue.lastRenderedState.routes);
      if (n?.child) walk(n.child); if (n?.sibling) walk(n.sibling);
    };
    walk(fiber); return found;
  }
  // Fallback: extract all hrefs from rendered DOM
  return [...new Set([...document.querySelectorAll('a[href]')]
    .map(a => a.getAttribute('href')).filter(h => h.startsWith('/')))];
});
// Test common SPA routes for 404 vs real content
const commonRoutes = ['/dashboard','/admin','/api','/settings','/profile','/users','/config'];
for (const route of commonRoutes) {
  await page.goto(`https://TARGET.COM${route}`, { waitUntil: 'networkidle' });
  const content = await page.content();
  const is404 = content.includes('404') || content.length < 500;
  console.log(`${route}: ${is404 ? '⛔ 404' : '✅ ' + content.length + ' bytes'}`);
}
```

### Step 4: postMessage Listener Enumeration
```javascript
const listeners = await page.evaluate(() => {
  const handlers = [];
  const orig = window.addEventListener;
  window.addEventListener = function(t, h, ...a) {
    if (t === 'message') handlers.push({
      handler: h.toString().slice(0, 300),
      usesOriginCheck: h.toString().includes('event.origin'),
      source: document.currentScript?.src || 'inline'
    });
    return orig.call(this, t, h, ...a);
  };
  return handlers;
});
```
**Critical finding**: Any postMessage handler WITHOUT `event.origin` validation is exploitable for DOM XSS. Any handler using `eval()` or `innerHTML` with the received data is an RCE vector.

### Step 5: Client Storage & Service Worker Enumeration
```javascript
// Storage dump after authentication flow
const storage = await page.evaluate(() => {
  const ls = {}; for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i); ls[k] = localStorage.getItem(k); }
  const ss = {}; for (let i = 0; i < sessionStorage.length; i++) {
    const k = sessionStorage.key(i); ss[k] = sessionStorage.getItem(k); }
  return { localStorage: ls, sessionStorage: ss };
});
// Scan for sensitive patterns in storage
const sensitive = /(token|jwt|api.?key|secret|password|credential|auth|session|access.?token|refresh)/i;

// Service worker enumeration
const swInfo = await page.evaluate(async () => {
  if (!('serviceWorker' in navigator)) return null;
  const regs = await navigator.serviceWorker.getRegistrations();
  return Promise.all(regs.map(async (r) => ({
    scope: r.scope, scriptURL: r.active?.scriptURL, state: r.active?.state,
    caches: await caches.keys()
  })));
});
```
SW scope without host validation in `fetch` handler is exploitable for cache poisoning.

### Step 6: Prototype Pollution Surface & DOM Events
```javascript
const pollution = await page.evaluate(() => {
  const sinks = {};
  try { ({})['__proto__'].test = true; sinks.__proto__ = ({}).test === true; delete Object.prototype.test; } catch(e) {}
  try { ({}).constructor.prototype.test = true; sinks.constructor = ({}).test === true; delete Object.prototype.test; } catch(e) {}
  return sinks;
});

// Common framework gadgets: lodash _.merge, jQuery $.extend, Vue.set, immer produce
```

## Detection & OPSEC

**Triggers**: Headless Chrome User-Agent patterns (even patched), instant page loads without render delay, missing CSS/font/image requests, sequential navigation without hover/mouse events, `navigator.webdriver === false` override detection (some anti-bot scripts detect the patch), Canvas/WebGL anomalies from virtualized GPUs, WebSocket connections from non-browser envs.

**Countermeasures**: Use `playwright-extra` with `puppeteer-extra-plugin-stealth` for better evasion. Humanize navigation: add random delays (500-1500ms), mouse movements, and scroll events. Use authenticated session cookies instead of login flows to reduce fingerprintable steps. Consider mobile emulation — less scrutinized. Rotate residential proxies between targets.

**Humanization snippet**:
```javascript
// Add realistic scroll behavior and timing
await page.evaluate(() => {
  const s = () => {
    window.scrollBy(0, Math.random()*200+50);
    if (window.scrollY < document.body.scrollHeight*0.7)
      setTimeout(s, Math.random()*800+400);
  }; s();
});
await page.waitForTimeout(Math.random()*1000+500);
```

**Evidence**: Full HAR export of all intercepted API calls. Screenshots per SPA route after JS rendering. Console logs saved to file. Storage dump exported as JSON. postMessage handler source text. Event listener list with element selectors. Service worker scope and cache contents. Prototype pollution test results.

## References

- [Playwright Documentation](https://playwright.dev/docs/intro)
- [Puppeteer Extra Stealth](https://github.com/berstend/puppeteer-extra)
- [OWASP DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN postMessage API](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [PortSwigger Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [Service Worker Security](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)
- [MITRE T1040 — Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [MITRE T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)
