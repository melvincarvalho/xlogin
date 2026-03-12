# xlogin

Universal login widget for **Nostr** and **Solid**. One script tag gives you a login button (bottom-right corner) with a tabbed modal supporting both identity systems.

## Quick Start

### CDN (recommended)

```html
<script src="https://unpkg.com/xlogin"></script>
```

That's it. A purple **Login** button appears at the bottom-right of your page.

### CDN with options

```html
<script src="https://unpkg.com/xlogin"
  data-idp="https://solidcommunity.net"
  data-guest="<64-char-hex-privkey>">
</script>
```

### npm

```bash
npm install xlogin
```

```html
<script src="node_modules/xlogin/xlogin.js"></script>
```

## How It Works

1. User clicks the **Login** button
2. A tabbed modal appears with **Nostr** and **Solid** tabs
3. **Nostr tab**: browser extension, guest key, or paste a private key
4. **Solid tab**: quick-select providers (solidcommunity.net, solidweb.me, solidweb.org, solid.social) or custom IDP
5. After login, the button shows the user's identity
6. Click the button again to **logout**

## API

```js
// Unified identity — works regardless of login method
window.xlogin.type   // "nostr" or "solid"
window.xlogin.id     // pubkey (nostr) or webId (solid)

// Unified authenticated fetch — works with both protocols
// Nostr: sends NIP-98 Authorization header
// Solid: sends DPoP Authorization header
const res = await window.xlogin.authFetch('https://example.com/api/data')

// Programmatic
window.xlogin.login()   // open modal
window.xlogin.logout()  // log out
```

### Nostr (NIP-07 compatible)

After Nostr login, `window.nostr` is fully functional:

```js
const pubkey = await window.nostr.getPublicKey()
const signed = await window.nostr.signEvent({ kind: 1, content: 'Hello', tags: [], created_at: Math.floor(Date.now() / 1000) })
const cipher = await window.nostr.nip04.encrypt(pubkey, 'secret')
const plain  = await window.nostr.nip04.decrypt(pubkey, cipher)
```

### Solid

After Solid login, `window.solid.session` provides authenticated fetch:

```js
window.solid.webId   // "https://alice.solidcommunity.net/profile/card#me"
const res = await window.solid.session.authFetch('https://alice.solidcommunity.net/private/data.ttl')
```

## Events

```js
document.addEventListener('xlogin', (e) => {
  console.log('Logged in:', e.detail.type, e.detail.id)
})

document.addEventListener('xlogout', () => {
  console.log('Logged out')
})
```

## Full Example

```html
<!DOCTYPE html>
<html>
<head><title>My App</title></head>
<body>
  <h1>My App</h1>
  <p id="status">Not logged in</p>

  <script>
    document.addEventListener('xlogin', (e) => {
      document.getElementById('status').textContent =
        'Logged in via ' + e.detail.type + ': ' + e.detail.id
    })
    document.addEventListener('xlogout', () => {
      document.getElementById('status').textContent = 'Not logged in'
    })
  </script>
  <script src="https://unpkg.com/xlogin"></script>
</body>
</html>
```

## Configuration

| Attribute     | Description                          | Example                                  |
| ------------- | ------------------------------------ | ---------------------------------------- |
| `data-idp`    | Default Solid identity provider URL  | `data-idp="https://solidcommunity.net"`  |
| `data-guest`  | Nostr guest private key (64 hex)     | `data-guest="abcd...1234"`               |

## Built-in Solid Providers

- [solidcommunity.net](https://solidcommunity.net)
- [solidweb.me](https://solidweb.me)
- [solidweb.org](https://solidweb.org)
- [solid.social](https://solid.social)

## Features

- **Zero build** — single script, no bundler required
- **Two protocols** — Nostr (NIP-07 + NIP-98) and Solid (OIDC + DPoP) in one widget
- **Unified authFetch** — one API for authenticated requests, regardless of protocol
- **Shadow DOM** — styles are fully encapsulated
- **Session persistence** — Nostr via localStorage, Solid via IndexedDB
- **Auto restore** — sessions survive page reloads
- **NIP-07 compatible** — `window.nostr` works with any Nostr app
- **DPoP + PKCE** — secure Solid authentication
- **Tabbed UI** — clean separation between login methods

## Dependencies

Loaded dynamically from CDN at runtime (zero install required):

- [solid-oidc](https://www.npmjs.com/package/solid-oidc) — Solid-OIDC authentication
- [nip98](https://www.npmjs.com/package/nip98) — NIP-98 HTTP Auth for Nostr
- [@noble/secp256k1](https://www.npmjs.com/package/@noble/secp256k1) — Nostr cryptography

## License

AGPL-3.0-or-later — Copyright (C) 2026 Melvin Carvalho
