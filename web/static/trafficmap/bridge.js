// SPDX-License-Identifier: AGPL-3.0-or-later
//
// postMessage bridge between the renderer iframe and its parent page
// (ADR 0009 D4). This is the renderer's only input: there is no fetch, no
// XHR and no other network use. The iframe is sandboxed without
// allow-same-origin, so its own origin is opaque; it is served by the NOS
// server, so location.origin (the URL's origin) is the parent's origin.
// Messages are accepted only from window.parent with exactly that origin,
// and replies are sent only to that origin, never to "*".

import { MSG_MODEL, MSG_ICONS, MSG_FOCUS, validateModel, validateIcons, validateFocus, ValidationError } from "./model.js";

/** Outgoing message types. */
export const OUT = Object.freeze({
  ready: "nos.trafficmap.ready",
  backend: "nos.trafficmap.backend",
  select: "nos.trafficmap.select",
  open: "nos.trafficmap.open",
  error: "nos.trafficmap.error",
});

/**
 * acceptMessage checks one MessageEvent. It returns null for messages that
 * are not for us (wrong source or origin), { kind, value } for valid ones
 * and { kind: "error", errors } for rejected ones. isBitmap decides whether
 * a value is a decoded ImageBitmap. The bitmaps of a rejected icons message
 * are closed, so the parent's decoded images are not leaked in the sandbox.
 */
export function acceptMessage(ev, win, isBitmap) {
  if (!ev || ev.source !== win.parent || ev.origin !== win.location.origin) return null;
  const data = ev.data;
  const type = data !== null && typeof data === "object" ? data.type : undefined;
  try {
    switch (type) {
      case MSG_MODEL:
        return { kind: "model", value: validateModel(data) };
      case MSG_ICONS:
        return { kind: "icons", value: validateIcons(data, isBitmap) };
      case MSG_FOCUS:
        return { kind: "focus", value: validateFocus(data) };
      default:
        return { kind: "error", errors: ["message: unsupported type"] };
    }
  } catch (err) {
    if (type === MSG_ICONS) closeRejectedIcons(data, isBitmap);
    if (err instanceof ValidationError) return { kind: "error", errors: err.errors };
    return { kind: "error", errors: ["message: could not be processed"] };
  }
}

// closeRejectedIcons releases the ImageBitmaps of a rejected icons message.
// The parent decoded real images for them and they stay alive until closed,
// so a message that is rejected (bad key, oversized, too many entries) must
// not leak its bitmaps.
function closeRejectedIcons(data, isBitmap) {
  const icons = data !== null && typeof data === "object" ? data.icons : undefined;
  if (icons === null || typeof icons !== "object" || Array.isArray(icons)) return;
  for (const v of Object.values(icons)) {
    if (isBitmap(v)) v.close();
  }
}

/** send posts a message to the parent page, restricted to our origin. */
export function send(win, type, fields) {
  if (win.parent === win) return;
  win.parent.postMessage({ type, ...fields }, win.location.origin);
}
