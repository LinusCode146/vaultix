// Background service worker: the only part of the extension that talks to the
// Vaultix app (through the native messaging host).
//
// Every page-facing request uses the URL the *browser* reports for the sender
// frame, never a URL supplied by the page or the content script.

import type {
  ContentMessage,
  Credentials,
  FillResult,
  LoginsState,
  LoginSummary,
  PasskeyCredential,
  PasskeyResult,
  PasskeySummary,
  PasskeysState,
  PasskeyTargets,
  PopupMessage,
  PopupState,
  SavePrompt,
  TabMessage,
  Unavailable,
  UnlockResult,
} from "./messages";

const HOST = "app.vaultix.native";
const REQUEST_TIMEOUT_MS = 10_000;
/** Touch ID waits for the user, who may take a while to reach the sensor. */
const UNLOCK_TIMEOUT_MS = 90_000;
/** How long a "save this login?" offer survives a page navigation. */
const PENDING_SAVE_TTL_MS = 2 * 60_000;
/** How long a username typed on a username-first page is remembered for the password step. */
const USERNAME_TTL_MS = 5 * 60_000;

class HostError extends Error {
  constructor(
    readonly reason: Unavailable | "locked" | "request",
    message: string,
  ) {
    super(message);
  }
}

// ---------- Native host connection ----------

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> };

let port: chrome.runtime.Port | null = null;
let ready: Promise<void> | null = null;
/** Whether the connection being set up may start the app if it isn't running. */
let readyLaunches = false;
let nextId = 1;
const pending = new Map<number, Pending>();

/**
 * Connect to the app. With `launch`, start it if it isn't running; without,
 * fail with "app-not-running" instead (for checks made on every page).
 */
function connect(launch = true): Promise<void> {
  // A connection attempt that won't launch the app doesn't serve one that should.
  if (ready && (readyLaunches || !launch)) return ready;
  readyLaunches = launch;
  ready = new Promise((resolve, reject) => {
    const p = chrome.runtime.connectNative(HOST);
    port = p;
    let handshakeDone = false;

    p.onMessage.addListener((msg: { type?: string; id?: number; ok?: boolean; result?: unknown; error?: string }) => {
      if (!handshakeDone) {
        if (msg.type === "not-running") {
          if (launch) {
            p.postMessage({ type: "launch" });
            return; // keep waiting for "ready"
          }
          handshakeDone = true;
          p.postMessage({ type: "stay-closed" });
          reject(new HostError("app-not-running", "Vaultix isn't running"));
          return;
        }
        handshakeDone = true;
        if (msg.type === "ready") {
          // A working connection serves every request, launching or not.
          if (port === p) readyLaunches = true;
          else p.disconnect(); // superseded while connecting
          resolve();
        }
        else if (msg.type === "error") reject(new HostError("app-not-running", "Vaultix isn't running"));
        else reject(new HostError("rejected", msg.error ?? "Vaultix refused the connection"));
        return;
      }
      const entry = msg.id !== undefined ? pending.get(msg.id) : undefined;
      if (!entry) return;
      pending.delete(msg.id!);
      clearTimeout(entry.timer);
      if (msg.ok) entry.resolve(msg.result);
      else if (msg.error === "locked") entry.reject(new HostError("locked", "locked"));
      else entry.reject(new HostError("request", msg.error ?? "request failed"));
    });

    p.onDisconnect.addListener(() => {
      const detail = chrome.runtime.lastError?.message ?? "disconnected";
      const error = /not found/i.test(detail)
        ? new HostError("not-installed", "The Vaultix app hasn't registered with this browser yet")
        : new HostError("error", detail);
      if (!handshakeDone) reject(error);
      // A newer connection may have replaced this one; its requests aren't ours to fail.
      if (port !== p) return;
      port = null;
      ready = null;
      for (const [id, entry] of pending) {
        clearTimeout(entry.timer);
        entry.reject(error);
        pending.delete(id);
      }
    });
  });
  // A failed handshake shouldn't be cached: try again on the next request.
  const attempt = ready;
  attempt.catch(() => {
    if (ready === attempt) ready = null;
  });
  return attempt;
}

async function request<T>(
  type: string,
  params: Record<string, unknown> = {},
  timeoutMs = REQUEST_TIMEOUT_MS,
  launch = true,
): Promise<T> {
  await connect(launch);
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new HostError("error", "Vaultix didn't answer"));
    }, timeoutMs);
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
    port!.postMessage({ id, type, ...params });
  });
}

async function loginsFor(url: string | undefined): Promise<LoginsState> {
  if (!url || !/^https?:/.test(url)) return { state: "ok", logins: [] };
  try {
    return { state: "ok", logins: await request<LoginSummary[]>("logins_for_page", { url }) };
  } catch (e) {
    const state = toState(e);
    if (state.state === "locked") {
      const status = await request<{ touchId?: boolean }>("status").catch(() => ({ touchId: false }));
      return { state: "locked", touchId: !!status.touchId };
    }
    return state;
  }
}

// One Touch ID prompt at a time, however many frames or tabs ask.
let unlocking: Promise<UnlockResult> | null = null;
function unlock(): Promise<UnlockResult> {
  unlocking ??= request("unlock_touch_id", {}, UNLOCK_TIMEOUT_MS)
    .then((): UnlockResult => ({ ok: true }))
    .catch((e): UnlockResult => ({ ok: false, error: e instanceof Error ? e.message : String(e) }))
    .finally(() => {
      unlocking = null;
    });
  return unlocking;
}

function toState(e: unknown): LoginsState {
  if (e instanceof HostError) {
    if (e.reason === "locked") return { state: "locked", touchId: false };
    if (e.reason !== "request") return { state: "unavailable", reason: e.reason, detail: e.message };
  }
  return { state: "unavailable", reason: "error", detail: String(e) };
}

async function fill(itemId: string, url: string | undefined): Promise<FillResult> {
  if (!url) return { ok: false, error: "no page URL" };
  try {
    return { ok: true, credentials: await request<Credentials>("fill", { item_id: itemId, url }) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

function siteOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

// ---------- Passkeys ----------

/**
 * Passkeys only for the top frame, or frames on the top frame's origin: the
 * app signs clientDataJSON with `crossOrigin: false`, which would be wrong for
 * a cross-origin iframe. Those get the browser's own handling.
 */
function passkeyFrameAllowed(sender: chrome.runtime.MessageSender): boolean {
  if (sender.tab === undefined || !sender.url || !/^https?:/.test(sender.url)) return false;
  if (sender.frameId === 0) return true;
  try {
    return new URL(sender.url).origin === new URL(sender.tab.url ?? "").origin;
  } catch {
    return false;
  }
}

/** Never starts the app: when it isn't running, the browser's own passkey dialog shows instead. */
async function passkeysFor(url: string, rpId: string, allow: string[]): Promise<PasskeysState> {
  try {
    const passkeys = await request<PasskeySummary[]>(
      "passkeys_for_page",
      { url, rp_id: rpId, allow },
      REQUEST_TIMEOUT_MS,
      false,
    );
    return { state: "ok", passkeys };
  } catch (e) {
    if (e instanceof HostError && e.reason === "locked") {
      const status = await request<{ touchId?: boolean }>("status", {}, REQUEST_TIMEOUT_MS, false).catch(() => ({ touchId: false }));
      return { state: "locked", touchId: !!status.touchId };
    }
    return { state: "unavailable" };
  }
}

async function passkeyRequest(type: string, params: Record<string, unknown>): Promise<PasskeyResult> {
  try {
    return { ok: true, credential: await request<PasskeyCredential>(type, params, REQUEST_TIMEOUT_MS, false) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ---------- Pending saves (kept in session storage: memory only, not visible to content scripts) ----------

interface PendingSave extends SavePrompt {
  url: string;
  password: string;
  expires: number;
}

const pendingKey = (tabId: number) => `pendingSave:${tabId}`;
const usernameKey = (tabId: number) => `username:${tabId}`;

async function getPendingSave(tabId: number): Promise<PendingSave | null> {
  const key = pendingKey(tabId);
  const value = (await chrome.storage.session.get(key))[key] as PendingSave | undefined;
  if (!value) return null;
  if (value.expires < Date.now()) {
    await chrome.storage.session.remove(key);
    return null;
  }
  return value;
}

/** `showNow`: show the prompt right away (a submit), rather than when the next page loads. */
async function onSubmitted(tabId: number, url: string, username: string, password: string, showNow = true) {
  if (!password) return;
  if (!username) {
    // Username-first sign-in: the username was typed on the previous page.
    const key = usernameKey(tabId);
    const remembered = (await chrome.storage.session.get(key))[key] as
      | { username: string; site: string; expires: number }
      | undefined;
    if (remembered && remembered.site === siteOf(url) && remembered.expires > Date.now()) username = remembered.username;
  }
  let status: string;
  try {
    status = (await request<{ status: string }>("check_login", { url, username, password })).status;
  } catch {
    return; // Locked or unavailable: nothing to offer.
  }
  if (status !== "new" && status !== "update") return;

  const save: PendingSave = {
    kind: status,
    site: siteOf(url),
    username,
    url,
    password,
    expires: Date.now() + PENDING_SAVE_TTL_MS,
  };
  await chrome.storage.session.set({ [pendingKey(tabId)]: save });
  if (!showNow) return;
  // Single-page apps don't navigate after login: prompt right away. If the
  // page does navigate, the new page asks for the prompt when it loads.
  const msg: TabMessage = { type: "showSavePrompt", prompt: { kind: save.kind, site: save.site, username } };
  chrome.tabs.sendMessage(tabId, msg, { frameId: 0 }).catch(() => {});
}

// ---------- Message routing ----------

chrome.runtime.onMessage.addListener((msg: ContentMessage | PopupMessage, sender, sendResponse) => {
  // Only our own extension pages and content scripts can send runtime messages,
  // but content scripts run inside web pages, so treat them as untrusted.
  if (sender.id !== chrome.runtime.id) return false;
  handleMessage(msg, sender).then(sendResponse, (e) => sendResponse({ error: String(e) }));
  return true; // async response
});

async function handleMessage(msg: ContentMessage | PopupMessage, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const tabId = sender.tab?.id;
  const fromPage = tabId !== undefined;
  // Popup-only messages act on whatever tab is active, so web pages may not send them.
  if (fromPage && (msg.type === "popupState" || msg.type === "popupFill")) return { error: "not allowed" };

  switch (msg.type) {
    case "getLogins":
      return loginsFor(sender.url);

    case "fill":
      return fill(msg.itemId, sender.url);

    case "submitted":
      if (fromPage && sender.url) await onSubmitted(tabId!, sender.url, msg.username, msg.password);
      return {};

    case "generatePassword":
      if (!fromPage) return { error: "not allowed" };
      try {
        return await request<{ password: string }>("generate_password", {}, REQUEST_TIMEOUT_MS, false);
      } catch (e) {
        return { error: String(e) };
      }

    case "filledGenerated":
      if (fromPage && sender.url) await onSubmitted(tabId!, sender.url, msg.username, msg.password, false);
      return {};

    case "rememberUsername":
      if (fromPage && sender.url && msg.username) {
        await chrome.storage.session.set({
          [usernameKey(tabId!)]: { username: msg.username, site: siteOf(sender.url), expires: Date.now() + USERNAME_TTL_MS },
        });
      }
      return {};

    case "getPendingSave": {
      if (!fromPage || sender.frameId !== 0) return null;
      const save = await getPendingSave(tabId!);
      // Only show the prompt on the same site it was offered for.
      if (!save || !sender.url || siteOf(sender.url) !== save.site) return null;
      return { kind: save.kind, site: save.site, username: save.username } satisfies SavePrompt;
    }

    case "resolvePendingSave": {
      if (!fromPage) return { saved: false };
      const save = await getPendingSave(tabId!);
      await chrome.storage.session.remove(pendingKey(tabId!));
      if (!save || !msg.save) return { saved: false };
      try {
        await request("save_login", { url: save.url, username: save.username, password: save.password });
        return { saved: true };
      } catch (e) {
        return { saved: false, error: String(e) };
      }
    }

    case "openApp":
      await request("show_app").catch(() => {});
      return {};

    case "unlock":
      return unlock();

    case "autoFill": {
      if (!fromPage || !sender.url || !/^https?:/.test(sender.url)) return null;
      // Usually null: only an "Open & Fill" started in the app is waiting.
      // Never starts the app: if it isn't running, nothing is waiting.
      return request<Credentials | null>(
        "pending_fill",
        { url: sender.url, password_step: msg.passwordStep },
        REQUEST_TIMEOUT_MS,
        false,
      ).catch(() => null);
    }

    case "getPasskeys":
      if (!passkeyFrameAllowed(sender)) return { state: "unavailable" } satisfies PasskeysState;
      return passkeysFor(sender.url!, msg.rpId, msg.allow);

    case "passkeyTargets": {
      if (!passkeyFrameAllowed(sender)) return null;
      const o = msg.options;
      return request<PasskeyTargets>(
        "passkey_targets",
        { url: sender.url, rp_id: o.rpId, user_id: o.userId, user_name: o.userName },
        REQUEST_TIMEOUT_MS,
        false,
      ).catch(() => null);
    }

    case "createPasskey": {
      if (!passkeyFrameAllowed(sender)) return { ok: false, error: "not allowed in this frame" } satisfies PasskeyResult;
      const o = msg.options;
      return passkeyRequest("create_passkey", {
        url: sender.url,
        rp_id: o.rpId,
        user_id: o.userId,
        user_name: o.userName,
        user_display_name: o.userDisplayName,
        challenge: o.challenge,
        algorithms: o.algorithms,
        exclude: o.exclude,
        item_id: msg.saveTo && msg.saveTo !== "new" ? msg.saveTo : undefined,
        new_login: msg.saveTo === "new",
      });
    }

    case "usePasskey":
      if (!passkeyFrameAllowed(sender)) return { ok: false, error: "not allowed in this frame" } satisfies PasskeyResult;
      return passkeyRequest("use_passkey", {
        url: sender.url,
        rp_id: msg.rpId,
        credential_id: msg.credentialId,
        challenge: msg.challenge,
      });

    case "popupState": {
      const tab = await activeTab();
      return { site: tab?.url ? siteOf(tab.url) : "", logins: await loginsFor(tab?.url) } satisfies PopupState;
    }

    case "popupFill": {
      const tab = await activeTab();
      if (!tab?.id || !tab.url) return { ok: false, error: "no active tab" };
      return fillTab(tab.id, tab.url, msg.itemId);
    }
  }
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/** Fill the top frame of a tab (popup and keyboard shortcut). */
async function fillTab(tabId: number, url: string, itemId: string): Promise<FillResult> {
  const result = await fill(itemId, url);
  if (!result.ok) return result;
  // The content script re-checks that it is still on `url`'s origin, in case
  // the tab navigated elsewhere in the meantime.
  const msg: TabMessage = { type: "fillCredentials", credentials: result.credentials, url };
  await chrome.tabs.sendMessage(tabId, msg, { frameId: 0 }).catch(() => {});
  return { ok: true, credentials: { username: result.credentials.username, password: "", totp: null } };
}

// ⌘⇧L: fill the only matching login, or open the popup to choose.
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const tab = await activeTab();
  if (!tab?.id || !tab.url) return;
  const state = await loginsFor(tab.url);
  if (state.state === "ok" && state.logins.length === 1) {
    await fillTab(tab.id, tab.url, state.logins[0].id);
  } else {
    await chrome.action.openPopup().catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([pendingKey(tabId), usernameKey(tabId)]);
});
