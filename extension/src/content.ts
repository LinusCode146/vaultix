// Content script: finds login fields, shows the inline login menu, fills
// credentials, and notices submitted logins so they can be saved.
//
// UI lives in closed shadow roots so page scripts and styles can't reach it.

import { avatar } from "./avatar";
import { findGroups, findSubmitButton, groupFor, isDisabled, kindIn, newPasswordFields, readSubmission, setValue, type LoginGroup } from "./forms";
import type { ContentMessage, Credentials, FillResult, GeneratedPassword, LoginsState, LoginSummary, SavePrompt, TabMessage, UnlockResult } from "./messages";
import { passkeyMenuEntries, startPasskeyBridge } from "./passkeys";

const send = <T>(msg: ContentMessage): Promise<T> => chrome.runtime.sendMessage(msg) as Promise<T>;
const isTop = window === window.top;

// ---------- Logins for this page (cached briefly) ----------

let cache: { at: number; value: Promise<LoginsState> } | null = null;
function getLogins(): Promise<LoginsState> {
  if (!cache || Date.now() - cache.at > 5000) cache = { at: Date.now(), value: send<LoginsState>({ type: "getLogins" }) };
  return cache.value;
}

// ---------- Filling ----------

/** True while we move focus between fields to fill them, so the menu stays shut. */
let filling = false;

function fillGroup(group: LoginGroup, creds: Credentials) {
  filling = true;
  try {
    // Fill the username first: some pages reveal or enable the password field on input.
    if (group.username && creds.username) setValue(group.username, creds.username);
    if (group.password && creds.password) setValue(group.password, creds.password);
    if (group.totp && creds.totp) setValue(group.totp, creds.totp);
  } finally {
    // Focus events from setValue are dispatched synchronously, but the menu
    // opens asynchronously; keep the flag until those have settled.
    setTimeout(() => (filling = false), 300);
  }
  closeMenu();
}

async function fillFromMenu(itemId: string, group: LoginGroup) {
  const result = await send<FillResult>({ type: "fill", itemId });
  if (!result.ok) return;
  fillGroup(group, result.credentials);
  submitAfterFill(group);
}

/**
 * Click the sign-in button after a fill from the inline menu, but only when
 * every field we know about holds a value and the button is unambiguous.
 */
async function submitAfterFill(group: LoginGroup) {
  const fields = [group.username, group.password, group.totp].filter((f): f is HTMLInputElement => !!f);
  const snapshot = fields.map((f) => [f, f.value] as const);
  if (fields.length === 0 || snapshot.some(([, v]) => !v)) return;

  // Give frameworks a moment to re-render (many enable the button only once
  // their state holds both values), then wait briefly for it to be enabled.
  await new Promise((r) => setTimeout(r, 150));
  for (let waited = 0; waited <= 1000; waited += 100) {
    // Stop if the page moved on or changed what we filled in.
    if (snapshot.some(([f, v]) => !f.isConnected || f.value !== v)) return;
    if (group.form && !group.form.checkValidity()) return;
    const button = findSubmitButton(group);
    if (!button) return;
    if (!isDisabled(button)) {
      button.click();
      return;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

/** The group the user most likely means: the focused one, else the first real login form. */
function bestGroup(): LoginGroup | undefined {
  const active = document.activeElement;
  const groups = findGroups();
  if (active instanceof HTMLInputElement) {
    const g = groups.find((g) => kindIn(g, active));
    if (g) return g;
  }
  return groups.find((g) => g.password) ?? groups.find((g) => g.username) ?? groups.find((g) => g.totp);
}

chrome.runtime.onMessage.addListener((msg: TabMessage) => {
  if (msg.type === "fillCredentials") {
    // Only fill if this frame is still on the page the credentials were matched for.
    let expected: string | null = null;
    try {
      expected = new URL(msg.url).origin;
    } catch {}
    const group = bestGroup();
    if (expected === location.origin && group) fillGroup(group, msg.credentials);
  } else if (msg.type === "showSavePrompt" && isTop) {
    showSavePrompt(msg.prompt);
  }
});

// ---------- Inline menu ----------

const MENU_CSS = `
:host { all: initial; }
.menu {
  position: fixed; z-index: 2147483647; min-width: 260px; max-width: 360px;
  font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif;
  color: #1d1d1f; background: #fff; border: 1px solid #d2d2d7; border-radius: 10px;
  box-shadow: 0 8px 28px rgb(0 0 0 / .18); padding: 5px; overflow: hidden;
}
.head { display: flex; align-items: center; gap: 6px; padding: 4px 8px 6px; color: #6e6e76; font-size: 11px; font-weight: 600; }
.head img { width: 14px; height: 14px; }
button.row {
  all: unset; box-sizing: border-box; display: flex; align-items: center; gap: 10px; width: 100%;
  padding: 7px 8px; border-radius: 7px; cursor: pointer;
}
button.row.active, button.row:hover { background: #3b5bdb; color: #fff; }
button.row.active .sub, button.row:hover .sub { color: rgb(255 255 255 / .8); }
.avatar { flex: none; width: 26px; height: 26px; border-radius: 6px; display: grid; place-items: center;
  font-size: 11px; font-weight: 600; color: #fff; background: linear-gradient(160deg, #5c7cfa, #364fc7); overflow: hidden; }
.avatar.logo { background: #fff; box-shadow: inset 0 0 0 1px rgb(0 0 0 / .08); }
.avatar.logo img { width: 100%; height: 100%; object-fit: contain; }
.text { display: flex; flex-direction: column; min-width: 0; }
.title, .sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.title { font-weight: 500; }
.sub { color: #6e6e76; font-size: 12px; }
.sub.mono { font: 12px ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: .02em; }
.again { all: unset; flex: none; margin-left: auto; width: 24px; height: 24px; border-radius: 6px; display: grid; place-items: center; font-size: 15px; }
.again:hover { background: rgb(255 255 255 / .22); }
@media (prefers-color-scheme: dark) {
  .menu { color: #ececf0; background: #26262a; border-color: #3a3a40; }
  .sub, .head { color: #9a9aa3; }
}
`;

interface MenuRow {
  el: HTMLButtonElement;
  pick: () => void;
}

interface MenuState {
  host: HTMLElement;
  field: HTMLInputElement;
  rows: MenuRow[];
  active: number;
  reposition: () => void;
}
let menu: MenuState | null = null;

function closeMenu() {
  if (!menu) return;
  window.removeEventListener("scroll", menu.reposition, true);
  window.removeEventListener("resize", menu.reposition);
  menu.host.remove();
  menu = null;
}

// Inlined rather than loaded from the extension, so pages can't probe for the
// extension by requesting its files.
const ICON =
  "data:image/svg+xml," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="bg" x1="0.1" y1="0" x2="0.9" y2="1"><stop offset="0" stop-color="#6d5cff"/><stop offset="1" stop-color="#211a7a"/></linearGradient></defs><rect x="2" y="2" width="60" height="60" rx="14" fill="url(#bg)"/><circle cx="32" cy="32" r="23" fill="#eef0fb"/><circle cx="32" cy="32" r="15" fill="#3b2fc9"/><path d="M32 32V20M32 32l10.4 6M32 32l-10.4 6" stroke="#eef0fb" stroke-width="4.2" stroke-linecap="round"/><circle cx="32" cy="32" r="4.5" fill="#41e8c8"/></svg>'
  );

function iconUrl() {
  return ICON;
}

function menuRow(title: string, sub: string, pick: () => void, opts: { icon?: string | null; text?: string } = {}): MenuRow {
  const b = document.createElement("button");
  b.className = "row";
  b.tabIndex = -1;
  const square = avatar(title, opts.icon, opts.text);
  const text = document.createElement("span");
  text.className = "text";
  const t = document.createElement("span");
  t.className = "title";
  t.textContent = title;
  const s = document.createElement("span");
  s.className = "sub";
  s.textContent = sub;
  text.append(t, s);
  b.append(square, text);
  // mousedown, not click: the field's blur would close the menu before click fires.
  b.addEventListener("mousedown", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!e.isTrusted) return; // ignore clicks synthesized by page scripts
    pick();
  });
  return { el: b, pick };
}

async function openMenu(field: HTMLInputElement) {
  if (filling) return;
  const group = groupFor(field);
  const kind = group && kindIn(group, field);
  if (!group || !kind) return;
  if (newPasswordFields(group).includes(field)) return openGeneratorMenu(field, group);
  if (kind === "new-password") return;
  // Sign-up form (new password, no current one): existing logins don't belong here.
  if (group.newPassword && !group.password) return;

  // Passkeys first: offered only while the page waits for a passkey sign-in.
  const [state, passkeys] = await Promise.all([getLogins(), kind === "totp" ? [] : passkeyMenuEntries()]);
  if (filling || document.activeElement !== field) return; // focus moved on while we waited
  closeMenu();

  const rows: MenuRow[] = passkeys.map((p) =>
    menuRow(p.title, p.sub, () => {
      closeMenu();
      p.pick();
    }, { text: "🔑" }),
  );
  if (state.state === "locked" && state.touchId) {
    rows.push(menuRow("Unlock with Touch ID", "Vaultix is locked", () => unlockFromMenu(field), { text: "🔒" }));
  } else if (state.state === "locked") {
    rows.push(menuRow("Vaultix is locked", "Click to open Vaultix and unlock", () => {
      send({ type: "openApp" });
      cache = null;
      closeMenu();
    }, { text: "🔒" }));
  } else if (state.state === "ok") {
    const logins: LoginSummary[] = kind === "totp" ? state.logins.filter((l) => l.hasTotp) : state.logins;
    for (const l of logins) {
      const sub = kind === "totp" ? "Fill one-time code" : l.username || "No username";
      rows.push(menuRow(l.title, sub, () => {
        closeMenu();
        fillFromMenu(l.id, group);
      }, { icon: l.icon }));
    }
  }
  showMenu(field, rows);
}

/** On a new-password field: suggest a strong password, and fill it into the field and its "confirm" twin. */
async function openGeneratorMenu(field: HTMLInputElement, group: LoginGroup) {
  const suggest = () => send<GeneratedPassword>({ type: "generatePassword" }).catch(() => ({ error: "unavailable" }));
  let generated = await suggest();
  if (!("password" in generated) || filling || document.activeElement !== field) return;
  closeMenu();
  const row = menuRow("Use a strong password", generated.password, () => {
    if (!("password" in generated)) return;
    closeMenu();
    filling = true;
    try {
      for (const input of newPasswordFields(group)) setValue(input, generated.password);
    } finally {
      filling = false;
    }
    send({ type: "filledGenerated", username: group.username?.value.trim() ?? "", password: generated.password });
  }, { text: "✦" });
  const sub = row.el.querySelector(".sub")!;
  sub.classList.add("mono");
  const again = document.createElement("span");
  again.className = "again";
  again.title = "Suggest another";
  again.textContent = "↻";
  again.addEventListener("mousedown", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!e.isTrusted) return;
    const next = await suggest();
    if ("password" in next) {
      generated = next;
      sub.textContent = next.password;
    }
  });
  row.el.append(again);
  showMenu(field, [row]);
}

function showMenu(field: HTMLInputElement, rows: MenuRow[]) {
  if (rows.length === 0) return;

  const host = document.createElement("vaultix-menu");
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = MENU_CSS;
  const box = document.createElement("div");
  box.className = "menu";
  box.setAttribute("role", "listbox");
  const head = document.createElement("div");
  head.className = "head";
  const icon = document.createElement("img");
  icon.src = iconUrl();
  icon.alt = "";
  head.append(icon, "Vaultix");
  box.append(head, ...rows.map((r) => r.el));
  root.append(style, box);

  const reposition = () => {
    const r = field.getBoundingClientRect();
    const below = r.bottom + 4;
    const height = box.offsetHeight || 60;
    box.style.top = `${below + height > window.innerHeight ? Math.max(4, r.top - height - 4) : below}px`;
    box.style.left = `${Math.max(4, Math.min(r.left, window.innerWidth - Math.max(260, r.width) - 4))}px`;
    box.style.width = `${Math.max(260, r.width)}px`;
  };
  document.documentElement.append(host);
  reposition();
  window.addEventListener("scroll", reposition, true);
  window.addEventListener("resize", reposition);
  menu = { host, field, rows, active: -1, reposition };
}

/** Touch ID prompt, then reopen the menu on the same field, now with logins. */
async function unlockFromMenu(field: HTMLInputElement) {
  closeMenu();
  const result = await send<UnlockResult>({ type: "unlock" });
  cache = null;
  if (result.ok) {
    field.focus({ preventScroll: true });
    openMenu(field);
  } else if (result.error === "password-required" || result.error === "touch-id-invalidated" || result.error === "touch-id-lockout") {
    // Needs the master password: bring the app forward.
    send({ type: "openApp" });
  }
}

function setActive(index: number) {
  if (!menu) return;
  menu.active = (index + menu.rows.length) % menu.rows.length;
  menu.rows.forEach((r, i) => r.el.classList.toggle("active", i === menu!.active));
}

// ---------- Wiring fields ----------

const wired = new WeakSet<HTMLInputElement>();

function wire(input: HTMLInputElement) {
  if (wired.has(input)) return;
  wired.add(input);
  // Open by itself only on empty fields, like the browser's own autofill, so
  // the menu never sits over a form the user is already completing. ↓ opens it on demand.
  input.addEventListener("focus", () => {
    if (!input.value) openMenu(input);
  });
  input.addEventListener("click", () => {
    if (!menu && !input.value) openMenu(input);
  });
  input.addEventListener("blur", () => setTimeout(() => menu?.field === input && closeMenu(), 150));
  input.addEventListener("input", (e) => {
    // Typing (not our own fill) hides the menu.
    if (e.isTrusted && menu?.field === input) closeMenu();
  });
  input.addEventListener("keydown", (e) => {
    if (!menu && e.key === "ArrowDown" && !e.altKey && !e.metaKey) {
      e.preventDefault();
      openMenu(input);
      return;
    }
    if (menu?.field === input) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActive(menu.active + 1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActive(menu.active - 1);
      } else if (e.key === "Enter" && menu.active >= 0) {
        e.preventDefault();
        e.stopPropagation();
        menu.rows[menu.active].pick();
      } else if (e.key === "Escape") {
        closeMenu();
      }
    }
    if (e.key === "Enter" && !menu) captureSubmission(input);
  });
}

function scan() {
  const groups = findGroups();
  for (const g of groups) {
    for (const input of [g.username, g.password, g.newPassword, g.totp]) if (input) wire(input);
  }
  autoFill(groups);
}

// ---------- "Open & Fill" from the app ----------

/** Fields already offered to the app, so each login step asks only once. */
const askedAutoFill = new WeakSet<HTMLInputElement>();

/**
 * When the app opened this site with "Open & Fill", sign in without being
 * asked: fill the login form and press its button. The app answers with
 * nothing unless that's the case, and only for the login's own site.
 */
async function autoFill(groups: LoginGroup[]) {
  const group = groups.find((g) => g.password && !g.newPassword) ?? groups.find((g) => g.username && !g.password && !g.newPassword);
  const anchor = group?.password ?? group?.username;
  if (!group || !anchor || askedAutoFill.has(anchor) || anchor.value) return;
  askedAutoFill.add(anchor);
  const credentials = await send<Credentials | null>({ type: "autoFill", passwordStep: !!group.password }).catch(() => null);
  if (!credentials || !anchor.isConnected) return;
  fillGroup(group, credentials);
  submitAfterFill(group);
}

// ---------- Noticing logins to save ----------

let lastSubmission = { key: "", at: 0 };

function captureSubmission(from: Element) {
  const groups = findGroups();
  const group =
    groups.find((g) => (g.form && g.form.contains(from)) || [g.username, g.password, g.newPassword].includes(from as HTMLInputElement)) ??
    (groups.length === 1 ? groups[0] : undefined);
  if (!group) return;

  const submission = readSubmission(group);
  if (!submission) {
    // Username-only step: remember the username for the password page.
    const username = group.username?.value.trim();
    if (username && !group.password && !group.newPassword) send({ type: "rememberUsername", username });
    return;
  }
  const key = `${submission.username}\u0000${submission.password}`;
  if (key === lastSubmission.key && Date.now() - lastSubmission.at < 3000) return;
  lastSubmission = { key, at: Date.now() };
  send({ type: "submitted", ...submission });
}

document.addEventListener("submit", (e) => captureSubmission(e.target as Element), true);
document.addEventListener(
  "click",
  (e) => {
    const target = (e.target as Element | null)?.closest?.('button, input[type="submit"], input[type="button"], [role="button"]');
    if (target) captureSubmission(target);
  },
  true,
);

// ---------- "Save this login?" prompt (top frame only) ----------

const BANNER_CSS = `
:host { all: initial; }
.card {
  position: fixed; top: 14px; right: 14px; z-index: 2147483647; width: 320px;
  font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif;
  color: #1d1d1f; background: #fff; border: 1px solid #d2d2d7; border-radius: 12px;
  box-shadow: 0 10px 32px rgb(0 0 0 / .2); padding: 14px 16px; animation: in .18s ease-out;
}
@keyframes in { from { opacity: 0; transform: translateY(-6px); } }
.head { display: flex; align-items: center; gap: 8px; font-weight: 600; }
.head img { width: 18px; height: 18px; }
p { margin: 6px 0 12px; color: #6e6e76; overflow-wrap: anywhere; }
p strong { color: inherit; font-weight: 500; }
.actions { display: flex; justify-content: flex-end; gap: 8px; }
button { all: unset; cursor: pointer; padding: 5px 12px; border-radius: 6px; font-weight: 500; border: 1px solid #c7c7ce; }
button.primary { background: #3b5bdb; border-color: #3b5bdb; color: #fff; }
@media (prefers-color-scheme: dark) {
  .card { color: #ececf0; background: #26262a; border-color: #3a3a40; }
  p { color: #9a9aa3; }
  button { border-color: #46464d; }
}
`;

let banner: HTMLElement | null = null;

function showSavePrompt(prompt: SavePrompt) {
  banner?.remove();
  const host = document.createElement("vaultix-save");
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = BANNER_CSS;
  const card = document.createElement("div");
  card.className = "card";
  card.setAttribute("role", "dialog");

  const head = document.createElement("div");
  head.className = "head";
  const icon = document.createElement("img");
  icon.src = iconUrl();
  icon.alt = "";
  head.append(icon, prompt.kind === "new" ? "Save login to Vaultix?" : "Update password in Vaultix?");

  const p = document.createElement("p");
  const who = document.createElement("strong");
  who.textContent = prompt.username || "(no username)";
  p.append(who, ` on ${prompt.site}`);

  const actions = document.createElement("div");
  actions.className = "actions";
  const later = document.createElement("button");
  later.textContent = "Not now";
  const save = document.createElement("button");
  save.className = "primary";
  save.textContent = prompt.kind === "new" ? "Save" : "Update";
  actions.append(later, save);

  const resolve = (doSave: boolean) => (e: MouseEvent) => {
    if (!e.isTrusted) return; // a page script can't click "Save" for the user
    send({ type: "resolvePendingSave", save: doSave });
    host.remove();
    banner = null;
  };
  later.addEventListener("click", resolve(false));
  save.addEventListener("click", resolve(true));

  card.append(head, p, actions);
  root.append(style, card);
  document.documentElement.append(host);
  banner = host;
}

// ---------- Start ----------

startPasskeyBridge(iconUrl());
scan();
let scanTimer: ReturnType<typeof setTimeout> | undefined;
new MutationObserver(() => {
  clearTimeout(scanTimer);
  scanTimer = setTimeout(scan, 300);
}).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["type", "style", "class", "hidden"] });

if (isTop) {
  send<SavePrompt | null>({ type: "getPendingSave" }).then((p) => p && showSavePrompt(p), () => {});
}

// If the page autofocused a login field before we were ready, show the menu now.
if (document.activeElement instanceof HTMLInputElement) {
  const el = document.activeElement;
  if (!el.value && groupFor(el)) openMenu(el);
}
