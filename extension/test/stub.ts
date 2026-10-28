// Fake `chrome` extension API for the fixture pages, so the real content
// script can run in an ordinary tab. Everything it sends is recorded in
// `window.__vaultix.log` for inspection.

import type { ContentMessage, Credentials, LoginSummary, PasskeyCredential, PasskeySummary, SavePrompt, TabMessage } from "../src/messages";

type Listener = (msg: TabMessage) => void;

const logins: LoginSummary[] = [
  {
    id: "1",
    title: "Example",
    username: "alice@example.com",
    hasTotp: true,
    // Stand-in for a cached website logo.
    icon: "data:image/svg+xml," + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" fill="#e8590c"/><circle cx="8" cy="8" r="4" fill="#fff"/></svg>'),
  },
  { id: "2", title: "Example (work)", username: "alice@work.example", hasTotp: false },
];
const credentials: Record<string, Credentials> = {
  "1": { username: "alice@example.com", password: "correct-horse-1", totp: "123456" },
  "2": { username: "alice@work.example", password: "work-pass-2", totp: null },
};

const state = {
  log: [] as ContentMessage[],
  listeners: [] as Listener[],
  locked: new URLSearchParams(location.search).has("locked"),
  /** `?touchid`: the locked app offers Touch ID. */
  touchId: new URLSearchParams(location.search).has("touchid"),
  /** `?openfill`: the app is waiting to "Open & Fill" login 1 here. */
  openFill: new URLSearchParams(location.search).has("openfill"),
  pending: null as SavePrompt | null,
  /** `?running=0`: Vaultix isn't running, so passkeys go to the browser. */
  running: new URLSearchParams(location.search).get("running") !== "0",
  /** `?haspasskey`: one passkey for this site is saved already. */
  /** Where the last passkey was saved: a login ID, "new" or "suggested". */
  savedTo: "",
  /** How many passwords were generated. */
  generated: 0,
  passkeys: (new URLSearchParams(location.search).has("haspasskey")
    ? [{ credentialId: b64("cred-0"), title: "Example", userName: "alice@example.com" }]
    : []) as PasskeySummary[],
};
(window as unknown as { __vaultix: typeof state }).__vaultix = state;

async function sendMessage(msg: ContentMessage): Promise<unknown> {
  state.log.push(msg);
  await new Promise((r) => setTimeout(r, 30));
  switch (msg.type) {
    case "getLogins":
      return state.locked ? { state: "locked", touchId: state.touchId } : { state: "ok", logins };
    case "unlock":
      await new Promise((r) => setTimeout(r, 300)); // the Touch ID prompt
      if (!state.touchId) return { ok: false, error: "password-required" };
      state.locked = false;
      return { ok: true };
    case "autoFill": {
      if (!state.openFill || state.locked) return null;
      if (msg.passwordStep) state.openFill = false;
      return credentials["1"];
    }
    case "fill":
      return credentials[msg.itemId] ? { ok: true, credentials: credentials[msg.itemId] } : { ok: false, error: "no match" };
    case "submitted": {
      const known = Object.values(credentials).find((c) => c.username === msg.username);
      if (known?.password === msg.password) return {};
      const prompt: SavePrompt = { kind: known ? "update" : "new", site: location.hostname, username: msg.username };
      state.pending = prompt;
      state.listeners.forEach((l) => l({ type: "showSavePrompt", prompt }));
      return {};
    }
    case "getPendingSave":
      return state.pending;
    case "getPasskeys":
      if (!state.running) return { state: "unavailable" };
      if (state.locked) return { state: "locked", touchId: state.touchId };
      return { state: "ok", passkeys: state.passkeys.filter((p) => msg.allow.length === 0 || msg.allow.includes(p.credentialId)) };
    case "passkeyTargets":
      if (state.locked) return null;
      return { logins: logins.map(({ id, title, username }) => ({ id, title, username })), suggested: "1" };
    case "createPasskey": {
      state.savedTo = msg.saveTo ?? "suggested";
      if (state.passkeys.some((p) => msg.options.exclude.includes(p.credentialId))) return { ok: false, error: "excluded" };
      const credentialId = b64(`cred-${state.passkeys.length + 1}`);
      state.passkeys.push({ credentialId, title: "Example", userName: msg.options.userName });
      const credential: PasskeyCredential = {
        credentialId,
        clientDataJSON: b64(JSON.stringify({ type: "webauthn.create", challenge: msg.options.challenge, origin: location.origin })),
        attestationObject: b64("attestation"),
        authenticatorData: b64("auth-data"),
        publicKey: b64("spki"),
        publicKeyAlgorithm: -7,
        title: logins.find((l) => l.id === msg.saveTo)?.title ?? "localhost",
      };
      return { ok: true, credential };
    }
    case "usePasskey": {
      const pk = state.passkeys.find((p) => p.credentialId === msg.credentialId);
      if (!pk) return { ok: false, error: "no such passkey" };
      const credential: PasskeyCredential = {
        credentialId: pk.credentialId,
        clientDataJSON: b64(JSON.stringify({ type: "webauthn.get", challenge: msg.challenge, origin: location.origin })),
        authenticatorData: b64("auth-data"),
        signature: b64("signature"),
        userHandle: b64(`user-${pk.userName}`),
      };
      return { ok: true, credential };
    }
    case "generatePassword":
      if (!state.running) return { error: "app-not-running" };
      state.generated += 1;
      return { password: `Gen-${state.generated}-x7#Qp9!vLm2@Rt4z` };
    case "filledGenerated":
      return {};
    case "resolvePendingSave":
      state.pending = null;
      return { saved: msg.save };
    default:
      return {};
  }
}

const w = window as unknown as { chrome?: Record<string, unknown> };
w.chrome = {
  ...(w.chrome ?? {}),
  runtime: {
    id: "test",
    sendMessage,
    onMessage: { addListener: (l: Listener) => state.listeners.push(l) },
  },
};

function b64(text: string): string {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
