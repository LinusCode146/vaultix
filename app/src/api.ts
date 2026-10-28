import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open, save } from "@tauri-apps/plugin-dialog";

export type Stage = "setup" | "locked" | "unlocked";

export interface Status {
  stage: Stage;
  vaultDir: string | null;
}

export type Category = "login" | "secureNote" | "creditCard" | "identity" | "apiCredential" | "document";

export type FieldKind = "text" | "concealed" | "email" | "phone" | "url" | "date" | "monthYear" | "multiline";

/** One labelled value of a non-login item. */
export interface FieldValue {
  id: string;
  label: string;
  kind: FieldKind;
  value: string;
}

/** A file stored encrypted in the vault folder. */
export interface FileRef {
  id: string;
  name: string;
  size: number;
}

export interface ItemSummary {
  id: string;
  category: Category;
  title: string;
  username: string;
  /** Second line in the list, e.g. "Visa •••• 4242". */
  subtitle: string;
  url: string | null;
  favorite: boolean;
  hasTotp: boolean;
  passkeyCount: number;
}

export interface PasskeyView {
  credentialId: string;
  rpId: string;
  userName: string;
  createdAt: number;
}

export type StrengthLabel = "terrible" | "weak" | "fair" | "good" | "veryGood" | "excellent" | "fantastic";

export interface StrengthView {
  label: StrengthLabel;
  /** "Very good", for display. */
  text: string;
  /** 0..1 */
  fraction: number;
}

export interface MasterPasswordCheck {
  strength: StrengthView;
  problem: string | null;
}

export interface WatchtowerIssue {
  itemId: string;
  detail: string;
  helpUrl: string | null;
}

export interface WatchtowerReport {
  score: number | null;
  scoreLabel: string;
  passwordCount: number;
  strengthCounts: { label: StrengthLabel; count: number }[];
  reused: WatchtowerIssue[];
  weak: WatchtowerIssue[];
  unsecured: WatchtowerIssue[];
  twoFactorAvailable: WatchtowerIssue[];
  passkeysAvailable: WatchtowerIssue[];
  siteListsLoaded: boolean;
}

export interface ItemView {
  id: string;
  category: Category;
  title: string;
  username: string;
  password: string;
  strength: StrengthView | null;
  urls: string[];
  notes: string;
  totpUri: string | null;
  passkeys: PasskeyView[];
  fields: FieldValue[];
  files: FileRef[];
  tags: string[];
  favorite: boolean;
  /** Previous passwords, newest first. */
  passwordHistory: PasswordChange[];
  createdAt: number;
  updatedAt: number;
}

export interface PasswordChange {
  password: string;
  /** When it stopped being the password (Unix ms). */
  changedAt: number;
}

/** Settings → This Mac. */
export interface AppSettings {
  lockOnSleep: boolean;
  quickSearch: boolean;
  /** `null`: the app's own folder on this Mac. */
  backupDir: string | null;
}

export interface BackupInfo {
  /** Folder name, e.g. "2026-10-28_091502". */
  id: string;
  createdAt: number;
}

export interface Backups {
  dir: string;
  /** Newest first. */
  backups: BackupInfo[];
}

export interface BackupItem {
  id: string;
  title: string;
  subtitle: string;
  category: Category;
  change: "deleted" | "changed";
  updatedAt: number;
}

export interface ImportPreview {
  source: string;
  fileName: string;
  /** New items per category. */
  counts: [Category, number][];
  /** Already in the vault: left out. */
  duplicates: number;
  files: number;
  warnings: string[];
}

export type QuickCopy = "password" | "username" | "totp";

export interface ItemInput {
  id: string | null;
  category: Category;
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  totp: string;
  passkeyIds: string[];
  fields: FieldValue[];
  files: FileRef[];
  tags: string[];
  favorite: boolean;
}

export interface TotpCode {
  code: string;
  remaining: number;
  period: number;
}

export interface SyncResult {
  devices: number;
  entries: number;
  skippedLines: number;
}

/** Field names match the Rust struct (snake_case). */
export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
}

export interface TouchIdStatus {
  /** This Mac has Touch ID with a finger enrolled. */
  available: boolean;
  enabled: boolean;
  /** Can unlock right now. */
  usable: boolean;
  /** Turned on, but the master password is needed first (every two weeks, or after fingers changed). */
  passwordRequired: boolean;
}

export interface Api {
  status(): Promise<Status>;
  createVault(parentDir: string, password: string): Promise<void>;
  joinVault(dir: string, password: string): Promise<void>;
  unlock(password: string): Promise<void>;
  lock(): Promise<void>;
  forgetVault(): Promise<void>;
  listItems(): Promise<ItemSummary[]>;
  getItem(id: string): Promise<ItemView>;
  saveItem(input: ItemInput): Promise<ItemView>;
  deleteItem(id: string): Promise<void>;
  syncVault(): Promise<SyncResult>;
  totpCode(id: string): Promise<TotpCode | null>;
  checkTotp(input: string): Promise<TotpCode>;
  generatePassword(options: PasswordOptions): Promise<string>;
  passwordStrength(password: string, context: { username: string; title: string; urls: string[] }): Promise<StrengthView>;
  masterPasswordCheck(password: string): Promise<MasterPasswordCheck>;
  watchtower(): Promise<WatchtowerReport>;
  copySecret(text: string): Promise<void>;
  pickFolder(title: string): Promise<string | null>;
  /** Let the user pick a file and store it encrypted in the vault. `null` if they cancelled. */
  attachFile(): Promise<FileRef | null>;
  /** Ask where to save, then decrypt one of an item's files there. Returns whether it was saved. */
  exportFile(itemId: string, file: FileRef): Promise<boolean>;
  touchIdStatus(): Promise<TouchIdStatus>;
  setTouchId(enabled: boolean): Promise<void>;
  /** Rejects with "touch-id-cancelled", "password-required", … */
  unlockTouchId(): Promise<void>;
  /** Open a login's website and sign in there through the extension. Returns the browser used, if known. */
  openAndFill(id: string, url: string): Promise<{ browser: string | null }>;
  /** Called when the vault is unlocked from elsewhere (Touch ID in the browser). */
  onUnlocked(callback: () => void): () => void;
  /** Locked from the menu bar. */
  onLocked(callback: () => void): () => void;
  appSettings(): Promise<AppSettings>;
  setAppSettings(settings: AppSettings): Promise<void>;
  backups(): Promise<Backups>;
  backupNow(): Promise<BackupInfo>;
  revealBackups(): Promise<void>;
  /** Items deleted or edited since the backup. */
  backupChanges(id: string): Promise<BackupItem[]>;
  restoreFromBackup(id: string, itemIds: string[]): Promise<number>;
  /** Ask for an export file; `null` if cancelled. */
  pickImportFile(): Promise<string | null>;
  importPreview(path: string): Promise<ImportPreview>;
  /** Saves what the preview showed; returns how many items were added. */
  importCommit(): Promise<number>;
  importCancel(): Promise<void>;
  trashImportedFile(): Promise<void>;
  /** A two-factor QR code on screen, as an otpauth:// URI. Rejects with "qr-none", "qr-permission", … */
  scanTotpQr(): Promise<string>;
  /** The same from an image file (asks for it; `null` if cancelled) or pasted image data. */
  scanTotpQrImage(image?: Blob): Promise<string | null>;
  /** Quick search window: copy a field of an item, then hide. */
  quickCopy(id: string, what: QuickCopy): Promise<void>;
  quickHide(giveBackFocus: boolean): Promise<void>;
  /** ⌘⇧Space showed the quick search window. */
  onQuickOpened(callback: () => void): () => void;
  /** The website's icon as a `data:` URI, or `null` if it has none. */
  siteIcon(url: string): Promise<string | null>;
  /** Called when the vault changes outside the UI (e.g. a login saved from the browser). Returns an unsubscribe function. */
  onVaultChanged(callback: () => void): () => void;
}

const tauriApi: Api = {
  status: () => invoke("status"),
  createVault: (parentDir, password) => invoke("create_vault", { parentDir, password }),
  joinVault: (dir, password) => invoke("join_vault", { dir, password }),
  unlock: (password) => invoke("unlock", { password }),
  lock: () => invoke("lock"),
  forgetVault: () => invoke("forget_vault"),
  listItems: () => invoke("list_items"),
  getItem: (id) => invoke("get_item", { id }),
  saveItem: (input) => invoke("save_item", { input }),
  deleteItem: (id) => invoke("delete_item", { id }),
  syncVault: () => invoke("sync_vault"),
  totpCode: (id) => invoke("totp_code", { id }),
  checkTotp: (input) => invoke("check_totp", { input }),
  generatePassword: (options) => invoke("generate_password", { options }),
  passwordStrength: (password, { username, title, urls }) => invoke("password_strength", { password, username, title, urls }),
  masterPasswordCheck: (password) => invoke("master_password_check", { password }),
  watchtower: () => invoke("watchtower"),
  copySecret: (text) => invoke("copy_secret", { text }),
  pickFolder: async (title) => {
    const picked = await open({ directory: true, multiple: false, title });
    return typeof picked === "string" ? picked : null;
  },
  attachFile: async () => {
    const path = await open({ directory: false, multiple: false, title: "Choose a file to store in Vaultix" });
    return typeof path === "string" ? invoke("attach_file", { path }) : null;
  },
  exportFile: async (itemId, file) => {
    const dest = await save({ defaultPath: file.name, title: "Save a decrypted copy" });
    if (!dest) return false;
    await invoke("export_file", { itemId, fileId: file.id, dest });
    return true;
  },
  siteIcon: (url) => invoke("site_icon", { url }),
  appSettings: () => invoke("app_settings"),
  setAppSettings: (settings) => invoke("set_app_settings", { settings }),
  backups: () => invoke("backups"),
  backupNow: () => invoke("backup_now"),
  revealBackups: () => invoke("reveal_backups"),
  backupChanges: (id) => invoke("backup_changes", { id }),
  restoreFromBackup: (id, itemIds) => invoke("restore_from_backup", { id, itemIds }),
  pickImportFile: async () => {
    const path = await open({
      directory: false,
      multiple: false,
      title: "Choose a 1Password, browser or Bitwarden export",
      filters: [{ name: "Password export", extensions: ["1pux", "csv"] }],
    });
    return typeof path === "string" ? path : null;
  },
  importPreview: (path) => invoke("import_preview", { path }),
  importCommit: () => invoke("import_commit"),
  importCancel: () => invoke("import_cancel"),
  trashImportedFile: () => invoke("trash_imported_file"),
  scanTotpQr: () => invoke("scan_totp_qr"),
  scanTotpQrImage: async (image) => {
    if (image) return invoke("scan_totp_qr_image", { base64: await blobToBase64(image) });
    const path = await open({
      directory: false,
      multiple: false,
      title: "Choose a screenshot of the QR code",
      filters: [{ name: "Image", extensions: ["png", "jpg", "jpeg", "heic", "gif", "tiff", "webp"] }],
    });
    return typeof path === "string" ? invoke("scan_totp_qr_image", { path }) : null;
  },
  quickCopy: (id, what) => invoke("quick_copy", { id, what }),
  quickHide: (giveBackFocus) => invoke("quick_hide", { giveBackFocus }),
  onQuickOpened: (callback) => {
    const unlisten = listen("quick-opened", callback);
    return () => void unlisten.then((fn) => fn());
  },
  touchIdStatus: () => invoke("touch_id_status"),
  setTouchId: (enabled) => invoke("set_touch_id", { enabled }),
  unlockTouchId: () => invoke("unlock_touch_id"),
  openAndFill: (id, url) => invoke("open_and_fill", { id, url }),
  onUnlocked: (callback) => {
    const unlisten = listen("unlocked", callback);
    return () => void unlisten.then((fn) => fn());
  },
  onLocked: (callback) => {
    const unlisten = listen("locked", callback);
    return () => void unlisten.then((fn) => fn());
  },
  onVaultChanged: (callback) => {
    const unlisten = listen("vault-changed", callback);
    return () => void unlisten.then((fn) => fn());
  },
};

async function blobToBase64(blob: Blob): Promise<string> {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const isTauri = "__TAURI_INTERNALS__" in window;

/** Which window this is: the main window, or the ⌘⇧Space quick search ("quick"). */
export const windowLabel: string = isTauri
  ? getCurrentWindow().label
  : new URLSearchParams(location.search).has("quick")
    ? "quick"
    : "main";

/**
 * Outside the app (plain `npm run dev` in a browser) an in-memory fake is used
 * for UI work. Production builds drop the fake entirely.
 */
export const api: Api =
  isTauri || !import.meta.env.DEV ? tauriApi : (await import("./mock")).mockApi;

/** Commands reject with a plain string; normalize anything else. */
export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

export const isLockedError = (e: unknown) => errorMessage(e) === "locked";
