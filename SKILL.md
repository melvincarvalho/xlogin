# xlogin

## Purpose
Universal drop-in login widget for browsers that supports both **Nostr** (NIP-07 + NIP-98) and **Solid** (OIDC + DPoP) authentication in a single script.

## Installation

### CDN (recommended)
```html
<script src="https://unpkg.com/xlogin"></script>
```

### CDN with options
```html
<script src="https://unpkg.com/xlogin" data-idp="https://solidcommunity.net" data-guest="<64-char-hex>"></script>
```

### npm
```bash
npm install xlogin
```
```html
<script src="node_modules/xlogin/xlogin.js"></script>
```

## Key Concepts

- **Single script tag** adds a purple Login button fixed at bottom-right
- **Tabbed modal** with Nostr and Solid tabs
- **Shadow DOM** encapsulates all styles
- **Session persistence** across page reloads (localStorage for Nostr, IndexedDB for Solid)
- **Unified authFetch** delegates to NIP-98 or DPoP based on login type

## API Reference

### Globals (after login)

| Global | Description |
|---|---|
| `window.xlogin.type` | `"nostr"` or `"solid"` or `null` |
| `window.xlogin.id` | pubkey (nostr) or webId (solid) or `null` |
| `window.xlogin.login()` | Open the login modal |
| `window.xlogin.logout()` | Log out and clear session |
| `window.xlogin.guestLogin(privkey)` | Log in directly with a 64-hex Nostr key, no modal (for key-in-a-link onboarding); persists as a guest session. Returns the pubkey. **⚠️ Stores the key in localStorage; a key in a link is a bearer credential — use the URL #fragment, low-stakes only.** |
| `window.xlogin.authFetch(url, options)` | Authenticated fetch (NIP-98 for Nostr, DPoP for Solid, plain fetch if not logged in) |

### Protocol-Specific Globals

**Nostr** (NIP-07 compatible `window.nostr`):
| Method | Description |
|---|---|
| `window.nostr.getPublicKey()` | Returns hex pubkey |
| `window.nostr.signEvent(event)` | Signs a Nostr event |
| `window.nostr.nip04.encrypt(pubkey, plaintext)` | NIP-04 encrypt |
| `window.nostr.nip04.decrypt(pubkey, ciphertext)` | NIP-04 decrypt |

**Solid** (`window.solid`):
| Property/Method | Description |
|---|---|
| `window.solid.webId` | The user's WebID URI |
| `window.solid.session` | solid-oidc Session instance |
| `window.solid.session.authFetch(url, options)` | DPoP-authenticated fetch |
| `window.solid.session.isActive` | Boolean session status |

### Events (on `document`)

| Event | Detail | When |
|---|---|---|
| `xlogin` | `{ type: "nostr"\|"solid", id: string }` | After successful login |
| `xlogout` | `{ type: "logout" }` | After logout |

## Data Attributes

| Attribute | Description |
|---|---|
| `data-idp` | Default Solid identity provider URL |
| `data-guest` | 64-char hex Nostr private key for guest mode |

## Built-in Solid Providers

- solidcommunity.net
- solidweb.me
- solidweb.org
- solid.social

Custom provider URLs are also supported via the input field.

## Usage Patterns

### Basic: Just add login
```html
<script src="https://unpkg.com/xlogin"></script>
```

### Listen for login events
```html
<script>
  document.addEventListener('xlogin', (e) => {
    console.log('Logged in via', e.detail.type, 'as', e.detail.id)
  })
  document.addEventListener('xlogout', () => {
    console.log('Logged out')
  })
</script>
<script src="https://unpkg.com/xlogin"></script>
```

### Unified authenticated fetch
```js
// Works with both Nostr (NIP-98) and Solid (DPoP) — no branching needed
const res = await window.xlogin.authFetch('https://example.com/api/data')
const data = await res.json()
```

### Check login status
```js
if (window.xlogin.id) {
  console.log('Logged in as', window.xlogin.type, window.xlogin.id)
} else {
  console.log('Not logged in')
}
```

### Nostr-specific: sign an event
```js
const signed = await window.nostr.signEvent({
  kind: 1,
  content: 'Hello world',
  tags: [],
  created_at: Math.floor(Date.now() / 1000)
})
```

### Solid-specific: fetch a protected resource
```js
const res = await window.solid.session.authFetch('https://alice.solidweb.me/private/notes.ttl')
const turtle = await res.text()
```

## Dependencies (loaded dynamically from CDN)

- `solid-oidc` — Solid-OIDC authentication (PKCE + DPoP)
- `nip98` — NIP-98 HTTP Auth for Nostr
- `@noble/secp256k1` — Nostr Schnorr signatures

## Architecture

- Single IIFE, no build step
- All UI in a closed Shadow DOM (no style leaks)
- Libraries loaded lazily via dynamic `import()` from esm.sh
- Nostr sessions stored in localStorage (compatible with nip07/Jumble)
- Solid sessions stored in IndexedDB (via solid-oidc SessionDatabase)
- Auto-detects Solid OIDC redirect callbacks on page load
- Auto-restores previous sessions on page load
