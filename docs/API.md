# Relay API + Android integration guide

Base URL: `https://getbeamkey.com` (local: `http://localhost:8787`, WebSocket scheme `ws://`).
All bodies are JSON. All binary values are **base64url without padding**.

## 1. How a session works

```
Phone                          Server (Room)                       Browser
 | POST /api/rooms {phonePub} ->|                                      |
 |<- {code, phoneToken, ...}    |                                      |
 | WS /ws/phone/{code} + Bearer |                                      |
 |<- ready                      |       user types code on website     |
 |                              |<-- WS /ws/browser/{code}, hello{pub} |
 |<- join_request{browserPub}   |--> waiting{phonePub}                 |
 |  derive key + check code  <-----------------------------> derive key + check code (user compares)
 | approve{reqId} ------------->|--> approved                          |
 | (tap button + biometric)     |                                      |
 | send{id,iv,ct} ------------->|--> secret{id,iv,ct}  (never stored)  |
 |<- delivered{id}              |                                      | decrypt, copy to clipboard
 |<- copied{id}                 |<-- copied{id}                        |
```

The server only ever sees ciphertext. A room lives 12 hours, then it is deleted automatically.

## 2. REST endpoints (phone only)

### `POST /api/rooms` - create a room (once per shift/day)
Request: `{ "phonePub": "<65-byte uncompressed P-256 point, base64url>" }`

Response `201`:
```json
{ "code": "D73R5GTV", "phoneToken": "<43 chars>", "expiresAt": 1767225600000, "ttlSeconds": 43200 }
```
- `code`: 8 chars, show it to the user as `D73R-5GTV`. The website accepts it with or without the hyphen, in any case.
- `phoneToken`: secret that proves you own the room. **Store it encrypted** (Keystore). Never show or log it.
- Errors: `400 bad_phone_pub`, `429 rate_limited` (10 rooms/hour/IP), `503 no_code_available`.

### `DELETE /api/rooms/{code}` - destroy a room early
Header: `Authorization: Bearer <phoneToken>` -> `204`. Errors: `401 unauthorized`, `404 not_found`.
Call this before creating a new room ("New pairing code" button, or after 12 h).

### `GET /api/health` -> `{"ok":true}`

## 3. Phone WebSocket

`GET /ws/phone/{code}` with header `Authorization: Bearer <phoneToken>` (OkHttp supports headers on WebSockets).
`401` = wrong token, `404` = room expired/deleted -> create a new room. Only one phone socket per room; a new one replaces the old.
Send `{"t":"ping"}` every ~25 s; the server answers `{"t":"pong"}`.

### Server -> phone
| `t` | Fields | Meaning / what to do |
|---|---|---|
| `ready` | `expiresAt`, `browserConnected` | Socket is live. Update status text. |
| `join_request` | `reqId`, `browserPub` | A browser entered your code. Derive the session (section 5), show a dialog with the check code and **Approve / Deny**. Also re-sent if you connect while one is waiting (valid 2 min). |
| `join_cancelled` | | The browser gave up. Dismiss the dialog. |
| `paired` | | Approval accepted. Enable the 3 password buttons. |
| `denied_ok` | `locked` | Deny recorded. After 3 denials `locked:true` and the room refuses new joins until you send `unlock`. |
| `unlocked` | | Room accepts joins again. |
| `delivered` | `id` | Server forwarded your message to the browser. |
| `undeliverable` | `id`, `reason:"no_browser"` | No browser is paired right now. Tell the user to enter the code on the website. |
| `copied` | `id` | The website copied it to the laptop clipboard. Show "Copied on laptop". |
| `browser_left` | | Browser tab closed. Disable buttons; the user must pair again. |
| `closed` | `reason` (`expired`, `destroyed_by_phone`) | Room is gone. Create a new one. |
| `error` | `reason` (`bad_send`, `no_pending`, `rate_limited`) | Show a short message. Max 20 sends per minute. |

### Phone -> server
| Message | When |
|---|---|
| `{"t":"approve","reqId":"..."}` | User taps Approve after comparing the check code |
| `{"t":"deny","reqId":"..."}` | User taps Deny |
| `{"t":"unlock"}` | "Unlock room" button after 3 denials |
| `{"t":"send","id":"...","iv":"...","ct":"..."}` | After biometric success (values from `ProtocolCrypto.encrypt`) |
| `{"t":"destroy"}` | Same effect as DELETE, over the open socket |
| `{"t":"ping"}` | Keep-alive |

## 4. Browser WebSocket (for reference; the website already does this)
`GET /ws/browser/{code}` -> `connected`; client sends `hello{pub}`; server replies `waiting{phonePub}`, then `approved` / `denied` / `error{reason: busy|locked|timeout}`; later `secret{id,iv,ct}`, `phone_online`, `phone_offline`, `closed`. Rate limit: 20 connection attempts per 10 min per IP.

## 5. Crypto (use `docs/android/ProtocolCrypto.java` as is)

| Step | Spec |
|---|---|
| Keys | Ephemeral ECDH P-256. Public key on the wire = 65-byte uncompressed point `04‖X‖Y` |
| Shared secret | ECDH, 32 bytes |
| Key | HKDF-SHA256, `salt = SHA256(phonePub‖browserPub)`, `info = "rcvpass-v1 aes-gcm"`, 32 bytes |
| Check code | `SHA256("rcvpass-v1 sas"‖phonePub‖browserPub)`, first 5 bytes -> 8 Crockford-base32 symbols, shown `XXXX-XXXX` |
| Plaintext | 128 bytes: `[len_hi][len_lo][password UTF-8][zero padding]` (max 126 bytes; hides the length) |
| Encryption | AES-256-GCM, random 12-byte IV, tag 128 bits, **AAD = `code + "|" + id`** (code = 8 chars, no hyphen) |
| `id` | 12 random bytes, base64url. Unique per message. |
| `ct` | ciphertext ‖ 16-byte tag, base64url |

`docs/test-vectors.json` holds fixed keys and the expected check code, AES key and ciphertext. The Java class was run against it and matches byte for byte; run the same check in your project if you change anything.

## 6. Where to call what in the Android app

| App event | Do this |
|---|---|
| **First launch / "New pairing code"** | `KeyPair kp = ProtocolCrypto.generateKeyPair()` -> `POST /api/rooms {phonePub: b64(publicRaw(kp.getPublic()))}` -> save `code`, `phoneToken`, `expiresAt`, and the private key (all encrypted with Android Keystore). If a room already exists, `DELETE` it first. |
| **App opens (onStart) and every 12 h** | If no room or `expiresAt - now < 5 min` -> create a new room (row above). Otherwise open the phone WebSocket for the saved code. Show the code as `XXXX-XXXX`. |
| **WebSocket `join_request`** | `Session s = ProtocolCrypto.derive(myPriv, browserPubRaw, myPubRaw, browserPubRaw)`. Dialog: "Browser wants to connect. Check code **s.sas**. Does the website show the same?" Approve -> send `approve`, keep `s.aesKey` and the approved `browserPub` (encrypted storage). Deny -> send `deny`. |
| **WebSocket `paired`** | Enable the 3 buttons. |
| **Tap "Type Password N"** | `BiometricPrompt` (fingerprint, face or device PIN). On success: decrypt password N from your own vault, `ProtocolCrypto.encrypt(aesKey, code, password)`, send `{"t":"send",id,iv,ct}`, clear the password from memory. |
| **`delivered` / `copied` / `undeliverable`** | Toast: "Sent" / "Copied on laptop" / "Open the website and enter the code". |
| **`browser_left`** | Disable buttons, show "Enter the code on the website again". |
| **`closed`, 401 or 404 on connect** | Room is gone: create a new one. |
| **Socket drops (network)** | Reconnect with the same code and token (back-off 1, 2, 4... up to 30 s). If you persisted the session key and the approved `browserPub`, sending works again immediately; the server never re-reveals the browser key. |
| **onStop** | Close the socket after about 60 s in the background. A foreground service is not needed because the app is in front when you tap a button. |

Persist across process death: `phoneToken`, `code`, `expiresAt`, private key, approved `browserPub` and `aesKey`, encrypted with a Keystore AES key. Your 3 stored passwords go in the same kind of encrypted vault, with the key requiring user authentication (`setUserAuthenticationRequired(true)`).

### OkHttp skeleton
```java
OkHttpClient http = new OkHttpClient.Builder().pingInterval(25, TimeUnit.SECONDS).build();

// Create room
JSONObject body = new JSONObject().put("phonePub", ProtocolCrypto.b64(pubRaw));
Request req = new Request.Builder().url(BASE + "/api/rooms")
        .post(RequestBody.create(body.toString(), MediaType.get("application/json"))).build();
// run on a background thread; parse code, phoneToken, expiresAt from the JSON response

// Open socket
Request ws = new Request.Builder().url(BASE.replaceFirst("^http", "ws") + "/ws/phone/" + code)
        .header("Authorization", "Bearer " + phoneToken).build();
WebSocket socket = http.newWebSocket(ws, new WebSocketListener() {
    @Override public void onMessage(WebSocket s, String text) { /* switch on JSONObject.getString("t") */ }
    @Override public void onFailure(WebSocket s, Throwable t, Response r) {
        if (r != null && (r.code() == 401 || r.code() == 404)) { /* room gone -> new room */ }
        else { /* schedule reconnect with back-off */ }
    }
});

// Send
socket.send(new JSONObject().put("t", "send").put("id", e.id).put("iv", e.iv).put("ct", e.ct).toString());
```
Dependencies: `com.squareup.okhttp3:okhttp:4.12.0`, `androidx.biometric:biometric:1.1.0`. Permission: `INTERNET`. Use `https://` / `wss://` in production (Android blocks cleartext by default).

## 7. Test without the Android app
```
npm run dev      # terminal 1
npm run sim      # terminal 2: fake phone, prints a code
```
Open http://localhost:8787, enter the code, compare the check codes in the terminal, then type a password into the terminal. `npm test` runs 14 automated protocol checks.
