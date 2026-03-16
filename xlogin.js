/**
 * xlogin.js - Universal login widget for Nostr and Solid
 *
 * A single-script login button (bottom-right) with a tabbed modal dialog
 * supporting both Nostr (NIP-07) and Solid (OIDC) authentication.
 *
 * Usage: <script src="xlogin.js"></script>
 *
 * Data attributes:
 *   data-idp="https://solidcommunity.net"  — default Solid identity provider
 *   data-guest="<64-char-hex>"             — enable Nostr guest key
 *
 * After login:
 *   window.xlogin.type   — "nostr" or "solid"
 *   window.xlogin.id     — pubkey (nostr) or webId (solid)
 *   window.nostr          — NIP-07 API (when logged in via Nostr)
 *   window.solid.session  — solid-oidc Session (when logged in via Solid)
 *
 * Events on document:
 *   "xlogin"  → detail: { type, id }
 *   "xlogout" → detail: { type: "logout" }
 *
 * @license AGPL-3.0-or-later
 * @author Melvin Carvalho
 */
(function () {
  'use strict'
  if (window.__xloginLoaded) return
  window.__xloginLoaded = true

  // --- Config ---
  var _script = document.currentScript
  var _defaultIdp = (_script && _script.dataset.idp) || ''
  var _guestKey = _script && _script.dataset.guest
  if (_guestKey && !/^[0-9a-f]{64}$/.test(_guestKey)) _guestKey = null

  // --- State ---
  var _type = null // "nostr" or "solid"
  var _id = null
  var _ui = null

  // Nostr state
  var _ext = null // captured browser extension
  var _nostrProvider = null
  var _nostrPrivKey = null
  var _nostrPubKey = null
  var _secp = null
  var _keyResolvers = []

  // Solid state
  var _solidSession = null

  // --- Capture existing NIP-07 extension ---
  _ext = window.nostr || null

  // --- Dynamic imports ---
  var _secpReady = import('https://esm.sh/@noble/secp256k1@1.7.1').then(function (mod) {
    _secp = mod
  })

  var _SolidSession = null
  var _solidReady = import('https://esm.sh/solid-oidc@0.0.8').then(function (mod) {
    _SolidSession = mod.Session || mod.default
  })

  var _nip98AuthFetch = null
  var _nip98Ready = import('https://esm.sh/nip98').then(function (mod) {
    _nip98AuthFetch = mod.authFetch
  })

  // --- localStorage (Nostr accounts, compatible with nip07/Jumble) ---
  function loadAccounts() {
    try { return JSON.parse(localStorage.getItem('accounts')) || [] } catch (e) { return [] }
  }
  function saveAccounts(accounts) { localStorage.setItem('accounts', JSON.stringify(accounts)) }
  function loadCurrentAccount() {
    try { return JSON.parse(localStorage.getItem('currentAccount')) } catch (e) { return null }
  }
  function saveCurrentAccount(account) {
    if (account) localStorage.setItem('currentAccount', JSON.stringify(account))
    else localStorage.removeItem('currentAccount')
  }

  // --- Hex utilities ---
  function hexToBytes(hex) {
    if (_secp) return _secp.utils.hexToBytes(hex)
    var b = new Uint8Array(hex.length / 2)
    for (var i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16)
    return b
  }
  function bytesToHex(bytes) {
    if (_secp) return _secp.utils.bytesToHex(bytes)
    return Array.from(bytes, function (b) { return b.toString(16).padStart(2, '0') }).join('')
  }
  async function sha256(msg) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', msg))
  }

  // --- NIP-01 ---
  async function computeEventId(ev) {
    var ser = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])
    return bytesToHex(await sha256(new TextEncoder().encode(ser)))
  }
  async function nostrSignEvent(event) {
    await _secpReady
    var ev = Object.assign({}, event, { pubkey: _nostrPubKey })
    ev.id = await computeEventId(ev)
    var sig = await _secp.schnorr.sign(ev.id, _nostrPrivKey)
    ev.sig = bytesToHex(sig)
    return ev
  }

  // --- NIP-04 ---
  async function getSharedSecret(theirPubkey) {
    await _secpReady
    var shared = _secp.getSharedSecret(_nostrPrivKey, '02' + theirPubkey)
    return shared.slice(1, 33)
  }
  async function nip04Encrypt(pubkey, plaintext) {
    var secret = await getSharedSecret(pubkey)
    var key = await crypto.subtle.importKey('raw', secret, { name: 'AES-CBC' }, false, ['encrypt'])
    var iv = crypto.getRandomValues(new Uint8Array(16))
    var cipher = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, new TextEncoder().encode(plaintext))
    return btoa(String.fromCharCode.apply(null, new Uint8Array(cipher))) + '?iv=' + btoa(String.fromCharCode.apply(null, iv))
  }
  async function nip04Decrypt(pubkey, ciphertext) {
    var parts = ciphertext.split('?iv=')
    var secret = await getSharedSecret(pubkey)
    var key = await crypto.subtle.importKey('raw', secret, { name: 'AES-CBC' }, false, ['decrypt'])
    var iv = Uint8Array.from(atob(parts[1]), function (c) { return c.charCodeAt(0) })
    var cipher = Uint8Array.from(atob(parts[0]), function (c) { return c.charCodeAt(0) })
    var plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, cipher)
    return new TextDecoder().decode(plain)
  }

  // --- Display helpers ---
  function shortNostr(pubkey) {
    return pubkey.slice(0, 8) + '\u2026' + pubkey.slice(-4)
  }
  function shortSolid(uri) {
    if (!uri) return ''
    try {
      var u = new URL(uri)
      var path = u.pathname
      if (path === '/' || path === '/profile/card#me') return u.hostname
      if (path.length > 20) return u.hostname + path.slice(0, 17) + '\u2026'
      return u.hostname + path
    } catch (e) {
      if (uri.length > 24) return uri.slice(0, 10) + '\u2026' + uri.slice(-10)
      return uri
    }
  }

  // --- Unified login success ---
  function onLogin(type, id, btn) {
    _type = type
    _id = id
    if (btn) {
      btn.textContent = type === 'nostr' ? shortNostr(id) : shortSolid(id)
      btn.title = id
    }
    window.xlogin = window.xlogin || {}
    window.xlogin.type = type
    window.xlogin.id = id
    document.dispatchEvent(new CustomEvent('xlogin', { detail: { type: type, id: id } }))
  }

  // --- Unified logout ---
  function onLogout(btn) {
    if (_type === 'nostr') {
      _nostrProvider = null
      _nostrPrivKey = null
      _nostrPubKey = null
      saveCurrentAccount(null)
    } else if (_type === 'solid') {
      if (_solidSession) _solidSession.logout()
      _solidSession = null
      window.solid = window.solid || {}
      window.solid.session = null
      window.solid.webId = null
    }
    _type = null
    _id = null
    if (btn) {
      btn.textContent = 'Login'
      btn.title = ''
    }
    window.xlogin = window.xlogin || {}
    window.xlogin.type = null
    window.xlogin.id = null
    document.dispatchEvent(new CustomEvent('xlogout', { detail: { type: 'logout' } }))
  }

  // --- Nostr login success ---
  function nostrLoginSuccess(btn, pubkey, method) {
    _nostrPubKey = pubkey
    _nostrProvider = method

    // Persist
    var signerType = method === 'extension' ? 'nip-07' : method
    var account = { '@id': 'did:nostr:' + pubkey, pubkey: pubkey, signerType: signerType }
    if ((method === 'key' || method === 'guest') && _nostrPrivKey) account.privkey = _nostrPrivKey
    var accounts = loadAccounts()
    var idx = accounts.findIndex(function (a) { return a.pubkey === pubkey })
    if (idx >= 0) accounts[idx] = account; else accounts.push(account)
    saveAccounts(accounts)
    saveCurrentAccount(account)

    _keyResolvers.forEach(function (r) { r.resolve() })
    _keyResolvers = []

    onLogin('nostr', pubkey, btn)
  }

  // --- NIP-07 API ---
  function ensureNostrProvider() {
    if (_nostrProvider) return Promise.resolve()
    return new Promise(function (resolve, reject) {
      _keyResolvers.push({ resolve: resolve, reject: reject })
      showModal()
    })
  }

  window.nostr = {
    getPublicKey: async function () {
      await ensureNostrProvider()
      if (_nostrProvider === 'extension') return _ext.getPublicKey()
      return _nostrPubKey
    },
    signEvent: async function (event) {
      await ensureNostrProvider()
      if (_nostrProvider === 'extension') return _ext.signEvent(event)
      return nostrSignEvent(event)
    },
    nip04: {
      encrypt: async function (pubkey, plaintext) {
        await ensureNostrProvider()
        if (_nostrProvider === 'extension' && _ext.nip04) return _ext.nip04.encrypt(pubkey, plaintext)
        return nip04Encrypt(pubkey, plaintext)
      },
      decrypt: async function (pubkey, ciphertext) {
        await ensureNostrProvider()
        if (_nostrProvider === 'extension' && _ext.nip04) return _ext.nip04.decrypt(pubkey, ciphertext)
        return nip04Decrypt(pubkey, ciphertext)
      }
    }
  }

  // =========================================================================
  // UI
  // =========================================================================

  var CSS = [
    '.xl-btn{position:fixed;bottom:16px;right:16px;z-index:999999;background:#8B5CF6;color:#fff;border:none;border-radius:20px;padding:8px 16px;font:14px/1.4 system-ui,sans-serif;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.2);transition:background .2s}',
    '.xl-btn:hover{background:#7C3AED}',
    '.xl-overlay{display:none;position:fixed;inset:0;z-index:1000000;background:rgba(0,0,0,.5);align-items:center;justify-content:center}',
    '.xl-overlay.active{display:flex}',
    '.xl-modal{background:#1a1a2e;color:#e0e0e0;border-radius:12px;padding:24px;width:380px;max-width:90vw;font:14px/1.4 system-ui,sans-serif;box-shadow:0 8px 32px rgba(0,0,0,.4)}',
    '.xl-modal h2{margin:0 0 16px;font-size:18px;color:#fff}',
    // Tabs
    '.xl-tabs{display:flex;gap:0;margin-bottom:16px;border-bottom:1px solid #333}',
    '.xl-tab{flex:1;padding:10px 0;border:none;background:transparent;color:#888;font:14px/1.4 system-ui,sans-serif;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s}',
    '.xl-tab:hover{color:#ccc}',
    '.xl-tab.active{color:#8B5CF6;border-bottom-color:#8B5CF6}',
    // Panels
    '.xl-panel{display:none}',
    '.xl-panel.active{display:block}',
    // Buttons
    '.xl-provider{width:100%;box-sizing:border-box;padding:10px 16px;border:1px solid #8B5CF6;border-radius:8px;background:transparent;color:#8B5CF6;font-size:14px;cursor:pointer;transition:background .2s;text-align:left;margin-bottom:8px}',
    '.xl-provider:hover{background:#8B5CF620}',
    '.xl-guest{width:100%;box-sizing:border-box;padding:10px 16px;border:1px solid #666;border-radius:8px;background:transparent;color:#aaa;font-size:14px;cursor:pointer;margin-bottom:8px;transition:background .2s}',
    '.xl-guest:hover{background:#66666620}',
    '.xl-sep{text-align:center;color:#666;font-size:12px;margin:12px 0}',
    '.xl-modal input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #333;border-radius:8px;background:#0d0d1a;color:#e0e0e0;font:13px system-ui,sans-serif;margin-bottom:8px}',
    '.xl-modal input[type=password]{font:13px monospace}',
    '.xl-modal input:focus{outline:none;border-color:#8B5CF6}',
    '.xl-error{color:#ef4444;font-size:12px;margin-bottom:8px;min-height:16px}',
    '.xl-actions{display:flex;gap:8px;justify-content:flex-end}',
    '.xl-actions button{padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-size:14px}',
    '.xl-cancel{background:#333;color:#aaa}',
    '.xl-cancel:hover{background:#444}',
    '.xl-submit{background:#8B5CF6;color:#fff}',
    '.xl-submit:hover{background:#7C3AED}',
    '.xl-submit:disabled{opacity:.5;cursor:not-allowed}'
  ].join('')

  function createWidget() {
    var host = document.createElement('div')
    host.id = 'xlogin-widget'
    document.body.appendChild(host)
    var shadow = host.attachShadow({ mode: 'closed' })

    var style = document.createElement('style')
    style.textContent = CSS
    shadow.appendChild(style)

    // --- Button ---
    var btn = document.createElement('button')
    btn.className = 'xl-btn'
    btn.textContent = 'Login'
    btn.onclick = function () {
      if (_type) onLogout(btn)
      else showModal()
    }
    shadow.appendChild(btn)

    // --- Overlay ---
    var overlay = document.createElement('div')
    overlay.className = 'xl-overlay'

    // --- Modal ---
    var nostrExtBtn = _ext
      ? '<button class="xl-provider xl-nostr-ext">Use Browser Extension</button>'
      : ''
    var nostrGuestBtn = _guestKey
      ? '<button class="xl-guest xl-nostr-guest">Continue as Guest</button>'
      : ''
    var nostrSep = (_ext || _guestKey) ? '<div class="xl-sep">or paste a private key</div>' : ''

    var solidProviders = [
      { name: window.location.host, url: window.location.origin },
      { name: 'solidcommunity.net', url: 'https://solidcommunity.net' },
      { name: 'solidweb.me', url: 'https://solidweb.me' },
      { name: 'solidweb.org', url: 'https://solidweb.org' },
      { name: 'solid.social', url: 'https://solid.social' }
    ]
    var solidBtns = solidProviders.map(function (p) {
      return '<button class="xl-provider xl-solid-provider" data-idp="' + p.url + '">' + p.name + '</button>'
    }).join('')

    overlay.innerHTML =
      '<div class="xl-modal">' +
        '<h2>Login</h2>' +
        '<div class="xl-tabs">' +
          '<button class="xl-tab active" data-tab="nostr">Nostr</button>' +
          '<button class="xl-tab" data-tab="solid">Solid</button>' +
        '</div>' +
        // Nostr panel
        '<div class="xl-panel active" data-panel="nostr">' +
          nostrExtBtn +
          nostrGuestBtn +
          nostrSep +
          '<input type="password" class="xl-nostr-key" placeholder="64-char hex private key" maxlength="64" spellcheck="false" autocomplete="off">' +
          '<div class="xl-error xl-nostr-error"></div>' +
          '<div class="xl-actions">' +
            '<button class="xl-cancel">Cancel</button>' +
            '<button class="xl-submit xl-nostr-submit">Login</button>' +
          '</div>' +
        '</div>' +
        // Solid panel
        '<div class="xl-panel" data-panel="solid">' +
          solidBtns +
          '<div class="xl-sep">or enter your identity provider</div>' +
          '<input type="url" class="xl-solid-idp" placeholder="https://your-pod-provider.example" spellcheck="false" autocomplete="off" value="' + _defaultIdp + '">' +
          '<div class="xl-error xl-solid-error"></div>' +
          '<div class="xl-actions">' +
            '<button class="xl-cancel">Cancel</button>' +
            '<button class="xl-submit xl-solid-submit">Login</button>' +
          '</div>' +
        '</div>' +
      '</div>'
    shadow.appendChild(overlay)

    // --- Wire up tabs ---
    var tabs = overlay.querySelectorAll('.xl-tab')
    var panels = overlay.querySelectorAll('.xl-panel')
    tabs.forEach(function (tab) {
      tab.onclick = function () {
        tabs.forEach(function (t) { t.classList.remove('active') })
        panels.forEach(function (p) { p.classList.remove('active') })
        tab.classList.add('active')
        overlay.querySelector('[data-panel="' + tab.dataset.tab + '"]').classList.add('active')
      }
    })

    // --- Cancel ---
    var cancelBtns = overlay.querySelectorAll('.xl-cancel')
    function cancel() {
      hideModal()
      _keyResolvers.forEach(function (r) { r.reject(new Error('User cancelled login')) })
      _keyResolvers = []
    }
    cancelBtns.forEach(function (b) { b.onclick = cancel })
    overlay.onclick = function (e) { if (e.target === overlay) cancel() }

    // --- Nostr: Extension ---
    var extBtn = overlay.querySelector('.xl-nostr-ext')
    var nostrError = overlay.querySelector('.xl-nostr-error')
    if (extBtn) {
      extBtn.onclick = async function () {
        try {
          var pubkey = await _ext.getPublicKey()
          hideModal()
          nostrLoginSuccess(btn, pubkey, 'extension')
        } catch (e) {
          nostrError.textContent = 'Extension error: ' + e.message
        }
      }
    }

    // --- Nostr: Guest ---
    var guestBtn = overlay.querySelector('.xl-nostr-guest')
    if (guestBtn) {
      guestBtn.onclick = async function () {
        await _secpReady
        _nostrPrivKey = _guestKey
        var pubkey = bytesToHex(_secp.schnorr.getPublicKey(_guestKey))
        hideModal()
        nostrLoginSuccess(btn, pubkey, 'guest')
      }
    }

    // --- Nostr: Key ---
    var nostrKeyInput = overlay.querySelector('.xl-nostr-key')
    var nostrSubmit = overlay.querySelector('.xl-nostr-submit')
    nostrSubmit.onclick = async function () {
      var val = nostrKeyInput.value.trim().toLowerCase()
      if (!/^[0-9a-f]{64}$/.test(val)) {
        nostrError.textContent = 'Must be exactly 64 hex characters'
        return
      }
      await _secpReady
      _nostrPrivKey = val
      var pubkey = bytesToHex(_secp.schnorr.getPublicKey(val))
      hideModal()
      nostrKeyInput.value = ''
      nostrError.textContent = ''
      nostrLoginSuccess(btn, pubkey, 'key')
    }
    nostrKeyInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') nostrSubmit.onclick()
    })
    nostrKeyInput.addEventListener('input', function () {
      if (/^[0-9a-fA-F]{64}$/.test(nostrKeyInput.value.trim())) nostrSubmit.onclick()
    })

    // --- Solid: Provider buttons ---
    var solidError = overlay.querySelector('.xl-solid-error')
    overlay.querySelectorAll('.xl-solid-provider').forEach(function (b) {
      b.onclick = function () { doSolidLogin(b.dataset.idp, btn, solidError) }
    })

    // --- Solid: Custom IDP ---
    var solidIdpInput = overlay.querySelector('.xl-solid-idp')
    var solidSubmit = overlay.querySelector('.xl-solid-submit')
    solidSubmit.onclick = function () {
      var val = solidIdpInput.value.trim()
      if (!val) {
        solidError.textContent = 'Enter an identity provider URL'
        return
      }
      if (!/^https?:\/\//.test(val)) val = 'https://' + val
      doSolidLogin(val, btn, solidError)
    }
    solidIdpInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') solidSubmit.onclick()
    })

    return { btn: btn, overlay: overlay }
  }

  // --- Solid login ---
  async function doSolidLogin(idp, btn, errorEl) {
    try {
      errorEl.textContent = ''
      await _solidReady
      _solidSession = new _SolidSession()
      _solidSession.addEventListener('sessionStateChange', function (e) {
        if (e.detail.isActive) {
          var webId = e.detail.webId
          window.solid = window.solid || {}
          window.solid.session = _solidSession
          window.solid.webId = webId
          onLogin('solid', webId, btn)
        }
      })
      hideModal()
      await _solidSession.login(idp, window.location.href)
    } catch (e) {
      if (errorEl) errorEl.textContent = e.message || 'Login failed'
    }
  }

  // --- Solid redirect callback ---
  async function handleSolidRedirect() {
    var url = new URL(window.location.href)
    if (!url.searchParams.get('code')) return false
    await _solidReady
    _solidSession = new _SolidSession()
    var ui = getUI()
    _solidSession.addEventListener('sessionStateChange', function (e) {
      if (e.detail.isActive) {
        var webId = e.detail.webId
        window.solid = window.solid || {}
        window.solid.session = _solidSession
        window.solid.webId = webId
        if (ui && ui.btn) onLogin('solid', webId, ui.btn)
      }
    })
    await _solidSession.handleRedirectFromLogin()
    return true
  }

  // --- Solid session restore ---
  async function trySolidRestore() {
    await _solidReady
    _solidSession = new _SolidSession()
    var ui = getUI()
    _solidSession.addEventListener('sessionStateChange', function (e) {
      if (e.detail.isActive) {
        var webId = e.detail.webId
        window.solid = window.solid || {}
        window.solid.session = _solidSession
        window.solid.webId = webId
        if (ui && ui.btn) onLogin('solid', webId, ui.btn)
      }
    })
    await _solidSession.restore()
  }

  // --- Nostr session restore ---
  function tryNostrRestore() {
    var restored = loadCurrentAccount()
    if (!restored) return
    if ((restored.signerType === 'key' || restored.signerType === 'guest') && restored.privkey) {
      _nostrPrivKey = restored.privkey
      _nostrPubKey = restored.pubkey
      _nostrProvider = restored.signerType
      var ui = getUI()
      if (ui && ui.btn) onLogin('nostr', restored.pubkey, ui.btn)
    } else if (restored.signerType === 'nip-07') {
      _nostrPubKey = restored.pubkey
      ;(async function () {
        for (var i = 0; i < 50; i++) {
          if (_ext) {
            _nostrProvider = 'extension'
            var ui = getUI()
            if (ui && ui.btn) onLogin('nostr', _nostrPubKey, ui.btn)
            return
          }
          await new Promise(function (r) { setTimeout(r, 100) })
        }
        _nostrPubKey = null
        saveCurrentAccount(null)
      })()
    }
  }

  function getUI() {
    if (!_ui && document.body) _ui = createWidget()
    return _ui
  }

  function showModal() {
    var ui = getUI()
    if (ui) ui.overlay.classList.add('active')
  }

  function hideModal() {
    var ui = getUI()
    if (ui) ui.overlay.classList.remove('active')
  }

  // --- Global API ---
  window.xlogin = window.xlogin || {}
  window.xlogin.type = null
  window.xlogin.id = null
  window.xlogin.login = function () { showModal() }
  window.xlogin.logout = function () { onLogout(getUI().btn) }

  /**
   * Unified authenticated fetch.
   * - Nostr login  → NIP-98 Authorization header via nip98
   * - Solid login  → DPoP Authorization header via solid-oidc
   * - Not logged in → plain fetch
   */
  window.xlogin.authFetch = async function (url, options) {
    if (_type === 'nostr') {
      await _nip98Ready
      return _nip98AuthFetch(url, options)
    }
    if (_type === 'solid' && _solidSession) {
      return _solidSession.authFetch(url, options)
    }
    return fetch(url, options)
  }

  // --- Init ---
  async function init() {
    getUI()

    // 1. Solid redirect callback
    var wasRedirect = await handleSolidRedirect().catch(function () { return false })

    if (!wasRedirect) {
      // 2. Try Nostr restore (synchronous / fast)
      tryNostrRestore()

      // 3. Try Solid restore if not already logged in via Nostr
      if (!_type) {
        trySolidRestore().catch(function () {})
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init)
  } else {
    init()
  }
})()
