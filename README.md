# Room relay (phone -> laptop clipboard)

Cloudflare Worker + Durable Objects relay, static website, and the Android integration guide.

```
public/     website (index.html, app.js, proto.js shared crypto, style.css, _headers = CSP)
src/        Worker: index.js (REST + routing), room.js (one Durable Object per room), limiter.js (per-IP limits)
tools/      phone-sim.mjs  fake phone for testing
test/       e2e.mjs (14 protocol checks), vectors.mjs (cross-platform crypto vectors)
docs/       API.md (endpoints + Android guide), android/ProtocolCrypto.java, test-vectors.json
```

## Run locally
```
npm install
npm run dev        # http://localhost:8787
npm test           # in a second terminal, with the dev server running
npm run sim        # fake phone; enter the printed code on the website
```
Requires Node 20+.

## Deploy
```
npx wrangler login
npm run deploy     # -> https://room-relay.<your-subdomain>.workers.dev
```
1. Open that workers.dev address **from your work laptop first**. If your company filter blocks it, a custom domain may be blocked too.
2. Custom domain later: add the domain to Cloudflare (change nameservers), then Workers & Pages -> room-relay -> Settings -> Domains -> Add custom domain.
3. No database or secrets are needed. Rooms live in Durable Object storage for 12 hours and are deleted.

## Tuning for public use
- Limits are in `src/index.js` (`LIMITS`) and `src/room.js` (`MAX_DENIALS`, `SEND_LIMIT`). Limits are per IP, so raise `join` if many colleagues share one office IP.
- Add Cloudflare Turnstile on the join step and Cloudflare rate-limiting rules before opening to the public.
- Keep `public/` free of third-party scripts; the CSP in `public/_headers` blocks them.
- Never log request bodies or WebSocket messages.

## Known limits
- The website cannot write to the clipboard from a background tab: the user clicks once in the relay window per password (see API.md and the page text).
- The browser keeps its key in memory only. Reloading the page means pairing again (the phone approves again).
