// Passkeys, content-script side. The page script (page.ts) forwards each
// navigator.credentials request here; this asks the user in a Vaultix prompt
// and the app through the background worker, then answers the page.
//
// Requests can come from any script on the page, so nothing happens without a
// trusted click in our closed shadow root, and the app only ever creates or
// uses passkeys for the frame's real origin.

import { avatar } from "./avatar";
import type { ContentMessage, PageRequest, PageResponse, PasskeyCreateOptions, PasskeyGetOptions, PasskeyResult, PasskeysState, PasskeySummary, PasskeyTargets, UnlockResult } from "./messages";

const send = <T>(msg: ContentMessage): Promise<T> => chrome.runtime.sendMessage(msg) as Promise<T>;

type Answer = PageResponse extends infer R ? (R extends unknown ? Omit<R, "vaultix" | "id"> : never) : never;

function answer(id: number, a: Answer) {
  window.postMessage({ vaultix: "response", id, ...a } as PageResponse, "*");
}

const cancelled: Answer = { action: "error", name: "NotAllowedError", message: "The operation either timed out or was not allowed." };

function getPasskeys(o: PasskeyGetOptions | PasskeyCreateOptions, allow: string[] = []): Promise<PasskeysState> {
  return send<PasskeysState>({ type: "getPasskeys", rpId: o.rpId, allow }).catch(() => ({ state: "unavailable" }) as const);
}

// ---------- Requests from the page ----------

export function startPasskeyBridge(iconUrl: string) {
  icon = iconUrl;
  window.addEventListener("message", (e) => {
    if (e.source !== window || (e.data as PageRequest | null)?.vaultix !== "request") return;
    const req = e.data as PageRequest;
    if (req.kind === "abort") {
      if (conditional?.id === req.id) conditional = null;
      if (prompt?.id === req.id) closePrompt();
    } else if (req.kind === "create") {
      create(req.id, req.options);
    } else if (req.conditional) {
      startConditional(req.id, req.options);
    } else {
      get(req.id, req.options);
    }
  });
  // page.ts waits for this before sending anything.
  window.postMessage({ vaultix: "ready" }, "*");
}

let icon = "";

// ---------- create() ----------

async function create(id: number, o: PasskeyCreateOptions) {
  let state = await getPasskeys(o);
  if (state.state === "unavailable") return answer(id, { action: "fallback" });

  const p = openPrompt(id, "Save passkey in Vaultix?");
  const who = document.createElement("p");
  const name = document.createElement("strong");
  name.textContent = o.userName || o.userDisplayName || "(no username)";
  who.append(name, ` on ${o.rpId}`);
  p.body.append(who);

  // "Save to": the site's logins and "New login". Known once unlocked.
  let saveTo: HTMLSelectElement | null = null;
  const showTargets = async () => {
    const targets = await send<PasskeyTargets | null>({ type: "passkeyTargets", options: o }).catch(() => null);
    if (!targets || targets.logins.length === 0 || prompt !== p) return;
    saveTo = document.createElement("select");
    saveTo.setAttribute("aria-label", "Save to");
    for (const l of targets.logins) saveTo.append(new Option(l.username ? `${l.title} — ${l.username}` : l.title, l.id));
    saveTo.append(new Option("New login", "new"));
    saveTo.value = targets.suggested ?? "new";
    const label = document.createElement("label");
    label.className = "save-to";
    label.append("Save to", saveTo);
    p.body.append(label);
  };
  if (state.state === "ok") await showTargets();

  const save = button(state.state === "locked" ? "Unlock & Save" : "Save", "primary", async () => {
    save.disabled = true;
    try {
      if (state.state === "locked") {
        if (!(await unlock(p, state.touchId))) return;
        state = await getPasskeys(o);
        save.textContent = "Save";
        await showTargets();
        // With logins to choose from, let the user check the choice first.
        if (saveTo) return;
      }
      const result = await send<PasskeyResult>({ type: "createPasskey", options: o, saveTo: saveTo?.value }).catch(() => null);
      if (prompt !== p) return; // aborted meanwhile
      if (result?.ok) {
        answer(id, { action: "ok", credential: result.credential });
        p.done = true;
        p.status.textContent = `Saved to “${result.credential.title}”.`;
        p.actions.remove();
        setTimeout(() => prompt === p && closePrompt(), 1600);
      } else if (result?.error === "excluded") {
        finish(p, { action: "error", name: "InvalidStateError", message: "This passkey is already saved in Vaultix." });
      } else if (result?.error === "locked") {
        state = { state: "locked", touchId: true };
        save.textContent = "Unlock & Save";
      } else {
        // The app can't make this one (e.g. an algorithm it doesn't support): let the browser try.
        finish(p, { action: "fallback" });
      }
    } finally {
      save.disabled = false;
    }
  });
  p.actions.append(otherOptions(p), spacer(), button("Cancel", "", () => finish(p, cancelled)), save);
}

// ---------- get(), from a "Sign in with a passkey" button ----------

async function get(id: number, o: PasskeyGetOptions) {
  const state = await getPasskeys(o, o.allow);
  if (state.state === "unavailable" || (state.state === "ok" && state.passkeys.length === 0)) {
    return answer(id, { action: "fallback" });
  }
  const p = openPrompt(id, "Sign in with a passkey");
  const show = (s: PasskeysState) => {
    p.list.replaceChildren();
    if (s.state === "ok") {
      if (s.passkeys.length === 0) return finish(p, { action: "fallback" });
      for (const pk of s.passkeys) p.list.append(passkeyRow(pk, () => use(p, o, pk)));
    } else if (s.state === "locked") {
      p.list.append(
        row(s.touchId ? "Unlock with Touch ID" : "Vaultix is locked", s.touchId ? "To use your passkeys" : "Click to open Vaultix and unlock", "🔒", async () => {
          if (await unlock(p, s.touchId)) show(await getPasskeys(o, o.allow));
        }),
      );
    }
  };
  show(state);
  p.actions.append(otherOptions(p), spacer(), button("Cancel", "", () => finish(p, cancelled)));
}

async function use(p: Prompt, o: PasskeyGetOptions, pk: PasskeySummary) {
  const result = await usePasskey(o, pk);
  if (prompt !== p) return;
  finish(p, result?.ok ? { action: "ok", credential: result.credential } : { action: "fallback" });
}

function usePasskey(o: PasskeyGetOptions, pk: PasskeySummary): Promise<PasskeyResult | null> {
  return send<PasskeyResult>({ type: "usePasskey", rpId: o.rpId, credentialId: pk.credentialId, challenge: o.challenge }).catch(() => null);
}

// ---------- get() with mediation "conditional": passkeys in the login field's menu ----------

let conditional: { id: number; options: PasskeyGetOptions } | null = null;

async function startConditional(id: number, o: PasskeyGetOptions) {
  if (conditional) answer(conditional.id, cancelled);
  const state = await getPasskeys(o, o.allow);
  // Locked: keep it, the menu offers to unlock and then shows the passkeys.
  if (state.state === "unavailable" || (state.state === "ok" && state.passkeys.length === 0)) {
    return answer(id, { action: "fallback" });
  }
  conditional = { id, options: o };
}

export interface MenuEntry {
  title: string;
  sub: string;
  pick: () => void;
}

/** Passkey choices for the inline menu, while the page waits for a conditional sign-in. */
export async function passkeyMenuEntries(): Promise<MenuEntry[]> {
  const c = conditional;
  if (!c) return [];
  const state = await getPasskeys(c.options, c.options.allow);
  if (state.state !== "ok") return [];
  return state.passkeys.map((pk) => ({
    title: pk.userName || pk.title,
    sub: `Passkey · ${pk.title}`,
    pick: async () => {
      const result = await usePasskey(c.options, pk);
      if (conditional !== c || !result?.ok) return;
      conditional = null;
      answer(c.id, { action: "ok", credential: result.credential });
    },
  }));
}

// ---------- Prompt ----------

const PROMPT_CSS = `
:host { all: initial; }
.card {
  position: fixed; top: 14px; right: 14px; z-index: 2147483647; width: 340px; box-sizing: border-box;
  font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif;
  color: #1d1d1f; background: #fff; border: 1px solid #d2d2d7; border-radius: 12px;
  box-shadow: 0 10px 32px rgb(0 0 0 / .2); padding: 14px 16px; animation: in .18s ease-out;
}
@keyframes in { from { opacity: 0; transform: translateY(-6px); } }
.head { display: flex; align-items: center; gap: 8px; font-weight: 600; }
.head img { width: 18px; height: 18px; }
p { margin: 6px 0 0; color: #6e6e76; overflow-wrap: anywhere; }
p strong { color: #1d1d1f; font-weight: 500; }
.save-to { display: flex; align-items: center; gap: 8px; margin-top: 10px; color: #6e6e76; }
.save-to select {
  flex: 1; min-width: 0; font: inherit; color: #1d1d1f; background: #fff;
  border: 1px solid #c7c7ce; border-radius: 6px; padding: 4px 6px;
}
.list { display: flex; flex-direction: column; margin: 8px -8px 0; }
.list:empty { display: none; }
.status { margin-top: 8px; color: #6e6e76; }
.status:empty { display: none; }
.actions { display: flex; align-items: center; gap: 8px; margin-top: 14px; }
.spacer { flex: 1; }
button { all: unset; cursor: pointer; padding: 5px 12px; border-radius: 6px; font-weight: 500; border: 1px solid #c7c7ce; }
button.primary { background: #3b5bdb; border-color: #3b5bdb; color: #fff; }
button.link { border: 0; padding: 5px 0; color: #3b5bdb; font-weight: 400; }
button[disabled] { opacity: .6; cursor: default; }
button.row {
  display: flex; align-items: center; gap: 10px; padding: 7px 8px; border: 0; border-radius: 7px; font-weight: 400;
}
button.row:hover, button.row:focus-visible { background: #3b5bdb; color: #fff; }
button.row:hover .sub, button.row:focus-visible .sub { color: rgb(255 255 255 / .8); }
.avatar { flex: none; width: 26px; height: 26px; border-radius: 6px; display: grid; place-items: center;
  font-size: 11px; font-weight: 600; color: #fff; background: linear-gradient(160deg, #5c7cfa, #364fc7); }
.text { display: flex; flex-direction: column; min-width: 0; }
.title, .sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.title { font-weight: 500; }
.sub { color: #6e6e76; font-size: 12px; }
@media (prefers-color-scheme: dark) {
  .card { color: #ececf0; background: #26262a; border-color: #3a3a40; }
  p, .status, .sub, .save-to { color: #9a9aa3; }
  .save-to select { color: #ececf0; background: #1e1e22; border-color: #46464d; }
  p strong { color: #ececf0; }
  button { border-color: #46464d; }
  button.link { color: #8ea2ff; }
}
`;

interface Prompt {
  id: number;
  host: HTMLElement;
  body: HTMLElement;
  list: HTMLElement;
  status: HTMLElement;
  actions: HTMLElement;
  /** Answered already; closing it mustn't answer again. */
  done: boolean;
}

let prompt: Prompt | null = null;

function onKey(e: KeyboardEvent) {
  if (e.key === "Escape" && prompt && e.isTrusted) {
    e.stopPropagation();
    finish(prompt, cancelled);
  }
}

function openPrompt(id: number, heading: string): Prompt {
  if (prompt) finish(prompt, cancelled); // one request at a time, like the browser's own dialog
  const host = document.createElement("vaultix-passkey");
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = PROMPT_CSS;
  const card = document.createElement("div");
  card.className = "card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-label", heading);
  const head = document.createElement("div");
  head.className = "head";
  const img = document.createElement("img");
  img.src = icon;
  img.alt = "";
  head.append(img, heading);
  const [body, list, status, actions] = ["body", "list", "status", "actions"].map((c) => {
    const el = document.createElement("div");
    el.className = c;
    return el;
  });
  status.setAttribute("role", "status");
  card.append(head, body, list, status, actions);
  root.append(style, card);
  document.documentElement.append(host);
  document.addEventListener("keydown", onKey, true);
  prompt = { id, host, body, list, status, actions, done: false };
  return prompt;
}

function closePrompt() {
  prompt?.host.remove();
  prompt = null;
  document.removeEventListener("keydown", onKey, true);
}

function finish(p: Prompt, a: Answer) {
  if (!p.done) answer(p.id, a);
  p.done = true;
  if (prompt === p) closePrompt();
}

/** Let the browser show its own dialog (iCloud Keychain, a phone, a security key). */
function otherOptions(p: Prompt) {
  return button("Other options", "link", () => finish(p, { action: "fallback" }));
}

/** Touch ID, or bring the app forward to type the master password. */
async function unlock(p: Prompt, touchId: boolean): Promise<boolean> {
  if (touchId) {
    p.status.textContent = "Waiting for Touch ID…";
    const result = await send<UnlockResult>({ type: "unlock" }).catch(() => ({ ok: false, error: "" }));
    if (result.ok) {
      p.status.textContent = "";
      return true;
    }
    if (result.error === "touch-id-cancelled") {
      p.status.textContent = "";
      return false;
    }
  }
  send({ type: "openApp" });
  p.status.textContent = "Unlock Vaultix, then try again.";
  return false;
}

function button(label: string, className: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  b.textContent = label;
  b.addEventListener("click", (e) => {
    if (!e.isTrusted) return; // a page script can't click for the user
    onClick();
  });
  return b;
}

function row(title: string, sub: string, text: string, onClick: () => void): HTMLButtonElement {
  const b = button("", "row", onClick);
  const t = document.createElement("span");
  t.className = "title";
  t.textContent = title;
  const s = document.createElement("span");
  s.className = "sub";
  s.textContent = sub;
  const words = document.createElement("span");
  words.className = "text";
  words.append(t, s);
  b.append(avatar(title, null, text), words);
  return b;
}

function passkeyRow(pk: PasskeySummary, onClick: () => void) {
  return row(pk.userName || pk.title, pk.title, "🔑", onClick);
}

function spacer() {
  const s = document.createElement("span");
  s.className = "spacer";
  return s;
}
