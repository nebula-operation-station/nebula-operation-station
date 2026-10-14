// SPDX-License-Identifier: AGPL-3.0-or-later
// WebAuthn helpers for the login and setup pages. The executor produces
// the options and verifies the responses; this file only converts between
// base64url JSON and the browser's ArrayBuffers.
'use strict';

const nebulaWebAuthn = (() => {
  function decode(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function encode(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function requestOptions(o) {
    const p = Object.assign({}, o.publicKey);
    p.challenge = decode(p.challenge);
    p.allowCredentials = (p.allowCredentials || []).map((c) => Object.assign({}, c, { id: decode(c.id) }));
    return { publicKey: p };
  }

  function creationOptions(o) {
    const p = Object.assign({}, o.publicKey);
    p.challenge = decode(p.challenge);
    p.user = Object.assign({}, p.user, { id: decode(p.user.id) });
    p.excludeCredentials = (p.excludeCredentials || []).map((c) => Object.assign({}, c, { id: decode(c.id) }));
    return { publicKey: p };
  }

  function assertionJSON(c) {
    return {
      id: c.id,
      rawId: encode(c.rawId),
      type: c.type,
      response: {
        clientDataJSON: encode(c.response.clientDataJSON),
        authenticatorData: encode(c.response.authenticatorData),
        signature: encode(c.response.signature),
        userHandle: c.response.userHandle ? encode(c.response.userHandle) : null,
      },
      clientExtensionResults: c.getClientExtensionResults(),
    };
  }

  function attestationJSON(c) {
    const r = {
      clientDataJSON: encode(c.response.clientDataJSON),
      attestationObject: encode(c.response.attestationObject),
    };
    if (typeof c.response.getTransports === 'function') r.transports = c.response.getTransports();
    return { id: c.id, rawId: encode(c.rawId), type: c.type, response: r, clientExtensionResults: c.getClientExtensionResults() };
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    if (!res.ok) {
      const err = new Error(data.error || ('request failed (' + res.status + ')'));
      err.data = data;
      throw err;
    }
    return data;
  }

  function show(text, isError) {
    const m = document.getElementById('message');
    m.textContent = text; // never innerHTML: messages may echo server text
    m.classList.toggle('message--error', !!isError);
  }

  return { requestOptions, creationOptions, assertionJSON, attestationJSON, post, show };
})();
