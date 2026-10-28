// Messages between the content script, the popup and the background worker.
// Only the background worker talks to the native host.

export interface LoginSummary {
  id: string;
  title: string;
  username: string;
  hasTotp: boolean;
  /** The website's logo as a data: URI, if the app has it cached. */
  icon?: string | null;
}

export interface Credentials {
  username: string;
  password: string;
  totp: string | null;
}

/** Why the vault can't be reached. */
export type Unavailable = "not-installed" | "app-not-running" | "rejected" | "error";

export type LoginsState =
  | { state: "ok"; logins: LoginSummary[] }
  /** `touchId`: the app can be unlocked with Touch ID or Windows Hello from here. */
  | { state: "locked"; touchId: boolean }
  | { state: "unavailable"; reason: Unavailable; detail?: string };

export interface SavePrompt {
  kind: "new" | "update";
  site: string;
  username: string;
}

/** Content script → background. The page URL is never sent: the background uses the URL the browser reports for the sender. */
export type ContentMessage =
  | { type: "getLogins" }
  | { type: "fill"; itemId: string }
  | { type: "submitted"; username: string; password: string }
  | { type: "rememberUsername"; username: string }
  | { type: "getPendingSave" }
  | { type: "resolvePendingSave"; save: boolean }
  | { type: "openApp" }
  /** Unlock with Touch ID or Windows Hello (only sent from a trusted click in the inline menu). */
  | { type: "unlock" }
  /** The page shows a login form: fill it if the app is waiting to "Open & Fill" this site. */
  | { type: "autoFill"; passwordStep: boolean }
  | { type: "getPasskeys"; rpId: string; allow: string[] }
  /** Where a new passkey can be saved: this site's logins. */
  | { type: "passkeyTargets"; options: PasskeyCreateOptions }
  /** Only sent after a trusted click on "Save" in the passkey prompt. `saveTo`: a login's ID, or "new". */
  | { type: "createPasskey"; options: PasskeyCreateOptions; saveTo?: string }
  /** Only sent after a trusted click on a passkey. */
  | { type: "usePasskey"; rpId: string; credentialId: string; challenge: string }
  /** A strong password for a sign-up form. Works while Vaultix is locked; never launches it. */
  | { type: "generatePassword" }
  /** A generated password was filled in: offer to save it even if the page leaves without a normal submit. */
  | { type: "filledGenerated"; username: string; password: string };

export type GeneratedPassword = { password: string } | { error: string };

export type UnlockResult = { ok: true } | { ok: false; error: string };

/** Popup → background. */
export type PopupMessage =
  | { type: "popupState" }
  | { type: "popupFill"; itemId: string }
  | { type: "openApp" }
  | { type: "unlock" };

/** Background → content script. */
export type TabMessage =
  | { type: "fillCredentials"; credentials: Credentials; url: string }
  | { type: "showSavePrompt"; prompt: SavePrompt };

export interface PopupState {
  site: string;
  logins: LoginsState;
}

export type FillResult = { ok: true; credentials: Credentials } | { ok: false; error: string };

// ---------- Passkeys ----------
// Binary values are base64url (no padding), as in WebAuthn's JSON forms.

export interface PasskeySummary {
  credentialId: string;
  /** The login it belongs to. */
  title: string;
  userName: string;
}

export type PasskeysState =
  | { state: "ok"; passkeys: PasskeySummary[] }
  | { state: "locked"; touchId: boolean }
  | { state: "unavailable" };

export interface PasskeyTargets {
  logins: { id: string; title: string; username: string }[];
  /** The login it most likely belongs to; null: a new login. */
  suggested: string | null;
}

export interface PasskeyCreateOptions {
  rpId: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  challenge: string;
  algorithms: number[];
  exclude: string[];
}

export interface PasskeyGetOptions {
  rpId: string;
  challenge: string;
  allow: string[];
}

/** What the app returns for `create()` (`title`: the login it was saved to) or `get()`. */
export interface PasskeyCredential {
  credentialId: string;
  clientDataJSON: string;
  attestationObject?: string;
  authenticatorData: string;
  publicKey?: string;
  publicKeyAlgorithm?: number;
  signature?: string;
  userHandle?: string;
  title?: string;
}

export type PasskeyResult = { ok: true; credential: PasskeyCredential } | { ok: false; error: string };

/** Page script (main world) → content script, through window.postMessage. */
export type PageRequest =
  | { vaultix: "request"; id: number; kind: "create"; options: PasskeyCreateOptions }
  | { vaultix: "request"; id: number; kind: "get"; options: PasskeyGetOptions; conditional: boolean }
  /** The page aborted request `id` (its AbortSignal fired). */
  | { vaultix: "request"; id: number; kind: "abort" };

/** Content script → page script. "fallback": let the browser handle it as if Vaultix weren't there. */
export type PageResponse =
  | { vaultix: "response"; id: number; action: "ok"; credential: PasskeyCredential }
  | { vaultix: "response"; id: number; action: "fallback" }
  | { vaultix: "response"; id: number; action: "error"; name: "NotAllowedError" | "InvalidStateError"; message: string };
