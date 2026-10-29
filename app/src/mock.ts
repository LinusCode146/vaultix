// In-memory stand-in for the Rust backend, used only when the UI runs in a
// normal browser. Nothing here is secure; it exists for layout and flow work.
import type { Api, AppSettings, BackupInfo, FieldValue, ItemInput, ItemView, PhoneView, Status, StrengthLabel, StrengthView, TotpCode, TouchIdStatus, WatchtowerIssue, WatchtowerReport } from "./api";
import { platform } from "./platform";

let stage: Status["stage"] = "setup";
let vaultDir: string | null = null;
let touchId = false;
let importPicks = 0;
const PASSWORD = "correct horse battery";
const items = new Map<string, ItemView>();

let settings: AppSettings = { lockOnSleep: true, quickSearch: true, backupDir: null };
const backups: BackupInfo[] = [3, 2, 1, 0].map((d) => {
  const at = new Date(Date.now() - (d + 1) * 86_400_000);
  const p = (n: number) => String(n).padStart(2, "0");
  return { id: `${at.getFullYear()}-${p(at.getMonth() + 1)}-${p(at.getDate())}_0915${p(d)}`, createdAt: at.getTime() };
}).reverse();
/** Items as they were in the backups: one deleted since, one with an older password. */
const deletedInBackup: ItemView[] = [];

let phones: PhoneView[] = [];
let pairing: ReturnType<typeof setTimeout> | undefined;
const phoneListeners = new Set<() => void>();

const delay = (ms = 120) => new Promise((r) => setTimeout(r, ms));
const now = () => Date.now();

function seed() {
  const add = (partial: Partial<ItemView> & { title: string }) => {
    const id = crypto.randomUUID();
    items.set(id, {
      id,
      category: "login",
      fields: [],
      files: [],
      username: "",
      password: "",
      strength: null,
      urls: [],
      notes: "",
      totpUri: null,
      passkeys: [],
      tags: [],
      favorite: false,
      passwordHistory: [],
      createdAt: now() - 86_400_000 * 30,
      updatedAt: now() - 86_400_000 * 2,
      ...partial,
    });
  };
  add({
    title: "GitHub",
    username: "alice",
    password: "v8#Qm2!xLp7@Rt4z",
    urls: ["https://github.com"],
    totpUri: "otpauth://totp/Vaultix?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30",
    passkeys: [{ credentialId: "q1w2e3", rpId: "github.com", userName: "alice", createdAt: now() - 86_400_000 * 10 }],
    favorite: true,
    passwordHistory: [
      { password: "Gh-2023-old!", changedAt: now() - 86_400_000 * 40 },
      { password: "hunter2github", changedAt: now() - 86_400_000 * 400 },
    ],
  });
  add({ title: "Bank", username: "alice.schmidt", password: "Kx9!pR2@mW", urls: ["https://bank.example"] });
  add({ title: "Gmail", username: "alice@gmail.com", password: "hunter2hunter2", urls: ["https://accounts.google.com"] });
  add({ title: "YouTube", username: "alice@gmail.com", password: "hunter2hunter2", urls: ["https://www.youtube.com"] });
  add({ title: "Amazon", username: "alice@example.com", password: "Tr0ub4dor&3-amz-2019", urls: ["https://www.amazon.com"] });
  add({ title: "Burger shop", username: "Burgir_ohne_Tomaten", password: "Burgir2024", urls: ["http://burger.example"] });
  add({ title: "Wi-Fi at home", password: "kitchen-table-42", notes: "Network: Schmidt-5G" });
  const f = (id: string, label: string, kind: FieldValue["kind"], value: string): FieldValue => ({ id, label, kind, value });
  add({
    title: "Visa",
    category: "creditCard",
    fields: [
      f("cardholder", "cardholder name", "text", "Alice Schmidt"),
      f("number", "number", "concealed", "4242424242424242"),
      f("expiry", "expiry date", "monthYear", "08/2028"),
      f("cvv", "verification number", "concealed", "123"),
      f("bank", "issuing bank", "text", "Example Bank"),
    ],
  });
  add({
    title: "Alice Schmidt",
    category: "identity",
    fields: [
      f("first_name", "first name", "text", "Alice"),
      f("last_name", "last name", "text", "Schmidt"),
      f("birth_date", "birth date", "date", "1990-04-12"),
      f("street", "street", "text", "Keizersgracht 1"),
      f("city", "city", "text", "Amsterdam"),
      f("country", "country", "text", "Netherlands"),
      f("email", "email", "email", "alice@example.com"),
    ],
  });
  add({
    title: "Stripe test key",
    category: "apiCredential",
    fields: [
      f("credential", "credential", "concealed", "sk_test_example"),
      f("type", "type", "text", "secret key"),
      f("hostname", "hostname", "text", "api.stripe.com"),
    ],
  });
  add({ title: "Recovery codes", category: "secureNote", notes: "GitHub recovery codes\n1a2b-3c4d\n5e6f-7a8b" });
  add({ title: "Passport scan", category: "document", files: [{ id: crypto.randomUUID(), name: "passport.pdf", size: 482_133 }] });
  for (const item of items.values()) item.strength = item.password ? estimate(item.password, [item.username, item.title]) : null;
}

// ---------- Rough stand-ins for the Rust strength estimator and Watchtower ----------

const LABELS: StrengthLabel[] = ["terrible", "weak", "fair", "good", "veryGood", "excellent", "fantastic"];
const TEXT: Record<StrengthLabel, string> = {
  terrible: "Terrible", weak: "Weak", fair: "Fair", good: "Good", veryGood: "Very good", excellent: "Excellent", fantastic: "Fantastic",
};
const COMMON = ["password", "hunter2", "123456", "qwerty", "letmein", "welcome", "admin"];

function estimate(password: string, context: string[]): StrengthView {
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/\d/.test(password)) charset += 10;
  if (/[^a-zA-Z\d]/.test(password)) charset += 20;
  let g = password.length * Math.log10(Math.max(charset, 1)) * 0.75;
  const lower = password.toLowerCase();
  const words = [...COMMON, ...context.map((c) => c.toLowerCase()).filter((c) => c.length > 3)];
  for (const w of words) if (w && lower.includes(w.slice(0, 6))) g -= 6;
  g = Math.max(0, g);
  const idx = g < 6 ? 0 : g < 8 ? 1 : g < 10 ? 2 : g < 12 ? 3 : g < 14 ? 4 : g < 17 ? 5 : 6;
  return { label: LABELS[idx], text: TEXT[LABELS[idx]], fraction: Math.min(1, g / 20) };
}

const SITES_TOTP = ["google.com", "youtube.com", "amazon.com", "github.com"];
const SITES_PASSKEYS = ["google.com", "github.com", "amazon.com"];
const siteOf = (url: string) => {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.split(".").slice(-2).join(".");
  } catch {
    return "";
  }
};

function watchtowerReport(): WatchtowerReport {
  const all = [...items.values()];
  const withPw = all.filter((i) => i.password);
  const counts = new Map<StrengthLabel, number>(LABELS.map((l) => [l, 0]));
  const issue = (i: ItemView, detail: string): WatchtowerIssue => ({ itemId: i.id, detail, helpUrl: null });
  const r: WatchtowerReport = {
    score: null, scoreLabel: "No passwords yet", passwordCount: withPw.length, strengthCounts: [],
    reused: [], weak: [], unsecured: [], twoFactorAvailable: [], passkeysAvailable: [], siteListsLoaded: true,
  };
  let health = 0;
  for (const i of withPw) {
    const s = i.strength ?? estimate(i.password, [i.username, i.title]);
    counts.set(s.label, counts.get(s.label)! + 1);
    let h = Math.min(1, (s.fraction * 20) / 16);
    const others = withPw.filter((o) => o !== i && o.password === i.password).length;
    if (others) { r.reused.push(issue(i, `Also used by ${others} other item${others === 1 ? "" : "s"}`)); h *= 0.5; }
    if (LABELS.indexOf(s.label) < 3) r.weak.push(issue(i, s.text));
    const http = i.urls.find((u) => u.startsWith("http://"));
    if (http) { r.unsecured.push(issue(i, http)); h *= 0.8; }
    if (i.totpUri || i.passkeys.length) h = Math.min(1, h + 0.1);
    health += h;
  }
  for (const i of all) {
    const sites = i.urls.map(siteOf);
    if (!i.totpUri && sites.some((s) => SITES_TOTP.includes(s))) r.twoFactorAvailable.push(issue(i, "Supports two-factor codes"));
    if (!i.passkeys.length && sites.some((s) => SITES_PASSKEYS.includes(s))) r.passkeysAvailable.push(issue(i, "Supports passkeys"));
  }
  r.strengthCounts = LABELS.map((label) => ({ label, count: counts.get(label)! }));
  if (withPw.length) {
    r.score = Math.round((1000 * health) / withPw.length);
    const sc = r.score;
    r.scoreLabel = sc < 300 ? "Poor" : sc < 500 ? "Fair" : sc < 700 ? "Good" : sc < 850 ? "Very good" : sc < 950 ? "Excellent" : "Fantastic";
  }
  return r;
}

function code(): TotpCode {
  const secs = Math.floor(Date.now() / 1000);
  const n = (Math.floor(secs / 30) * 7919) % 1_000_000;
  return { code: String(n).padStart(6, "0"), remaining: 30 - (secs % 30), period: 30 };
}

function toView(input: ItemInput, existing?: ItemView): ItemView {
  const history = existing?.passwordHistory ?? [];
  const passwordHistory =
    existing?.password && existing.password !== input.password
      ? [{ password: existing.password, changedAt: now() }, ...history.filter((h) => h.password !== existing.password && h.password !== input.password)].slice(0, 20)
      : history;
  return {
    passwordHistory,
    id: existing?.id ?? crypto.randomUUID(),
    category: existing?.category ?? input.category,
    fields: input.fields,
    files: input.files,
    title: input.title.trim(),
    username: input.username,
    password: input.password,
    strength: input.password ? estimate(input.password, [input.username, input.title]) : null,
    urls: input.urls.map((u) => u.trim()).filter(Boolean),
    notes: input.notes,
    totpUri: input.totp.trim() ? input.totp.trim() : null,
    passkeys: (existing?.passkeys ?? []).filter((p) => input.passkeyIds.includes(p.credentialId)),
    tags: input.tags,
    favorite: input.favorite,
    createdAt: existing?.createdAt ?? now(),
    updatedAt: now(),
  };
}

function subtitle(i: ItemView): string {
  const field = (id: string) => i.fields.find((f) => f.id === id)?.value ?? "";
  switch (i.category) {
    case "login":
      return i.username || i.urls[0] || "";
    case "secureNote":
      return i.notes.split("\n").find((l) => l.trim())?.slice(0, 60) ?? "";
    case "creditCard": {
      const digits = field("number").replace(/\D/g, "");
      return digits ? `${digits.startsWith("4") ? "Visa " : ""}•••• ${digits.slice(-4)}` : field("cardholder");
    }
    case "identity":
      return [field("first_name"), field("last_name")].filter(Boolean).join(" ");
    case "apiCredential":
      return field("hostname") || field("username");
    case "document":
      return i.files[0]?.name ?? "";
  }
}

function requireUnlocked() {
  if (stage !== "unlocked") throw "locked";
}

export const mockApi: Api = {
  async status() {
    return { stage, vaultDir };
  },
  async createVault(parentDir, password) {
    await delay(600);
    const check = await mockApi.masterPasswordCheck(password);
    if (check.problem) throw check.problem;
    vaultDir = `${parentDir}/Vaultix Vault`;
    stage = "unlocked";
    seed();
  },
  async joinVault(dir, password) {
    await delay(600);
    if (password !== PASSWORD) throw "wrong master password";
    vaultDir = dir;
    stage = "unlocked";
    seed();
  },
  async unlock(password) {
    await delay(500);
    if (password !== PASSWORD) throw "wrong master password";
    stage = "unlocked";
  },
  async lock() {
    stage = "locked";
  },
  async forgetVault() {
    stage = "setup";
    vaultDir = null;
    items.clear();
  },
  async listItems() {
    requireUnlocked();
    return [...items.values()]
      .sort((a, b) => a.title.localeCompare(b.title))
      .map((i) => ({
        id: i.id,
        category: i.category,
        title: i.title,
        username: i.username,
        subtitle: subtitle(i),
        url: i.urls[0] ?? null,
        favorite: i.favorite,
        hasTotp: i.totpUri !== null,
        passkeyCount: i.passkeys.length,
      }));
  },
  async getItem(id) {
    requireUnlocked();
    const item = items.get(id);
    if (!item) throw "item not found";
    return structuredClone(item);
  },
  async saveItem(input) {
    requireUnlocked();
    await delay();
    if (input.totp.trim()) await mockApi.checkTotp(input.totp);
    const view = toView(input, input.id ? items.get(input.id) : undefined);
    items.set(view.id, view);
    return structuredClone(view);
  },
  async deleteItem(id) {
    requireUnlocked();
    items.delete(id);
  },
  async syncVault() {
    requireUnlocked();
    return { devices: 2, entries: items.size * 3, skippedLines: 0 };
  },
  async totpCode(id) {
    requireUnlocked();
    return items.get(id)?.totpUri ? code() : null;
  },
  async checkTotp(input) {
    if (!/^(otpauth:\/\/totp\/.*secret=[A-Za-z2-7]+|[A-Za-z2-7 ]{8,})/.test(input.trim())) {
      throw "invalid TOTP configuration: secret is not valid base32";
    }
    return code();
  },
  async passwordStrength(password, { username, title }) {
    return estimate(password, [username, title]);
  },
  async masterPasswordCheck(password) {
    const strength = estimate(password, []);
    const len = password.trim().length;
    const problem =
      len < 12
        ? `Use at least 12 characters (${len} so far).`
        : LABELS.indexOf(strength.label) < 4
          ? "Too easy to guess. Add more words or characters, or use a random passphrase."
          : null;
    return { strength, problem };
  },
  async watchtower() {
    requireUnlocked();
    await delay(60);
    return watchtowerReport();
  },
  async generatePassword(o) {
    let alphabet = "abcdefghijkmnpqrstuvwxyz";
    if (o.uppercase) alphabet += "ABCDEFGHJKLMNPQRSTUVWXYZ";
    if (o.digits) alphabet += "23456789";
    if (o.symbols) alphabet += "!#$%&*+-.:=?@^_~";
    const bytes = crypto.getRandomValues(new Uint32Array(o.length));
    return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
  },
  async copySecret(text) {
    await navigator.clipboard?.writeText(text).catch(() => {});
  },
  async pickFolder() {
    return "/Users/you/Library/Mobile Documents/com~apple~CloudDocs";
  },
  async attachFile() {
    await delay(300);
    return { id: crypto.randomUUID(), name: "scan.pdf", size: 120_400 };
  },
  async exportFile() {
    await delay(200);
    return true;
  },
  async touchIdStatus() {
    const kind = { mac: "touch-id", windows: "windows-hello", linux: null }[platform] as TouchIdStatus["kind"];
    return { kind, available: kind !== null, enabled: touchId, usable: touchId, passwordRequired: false };
  },
  async setTouchId(enabled) {
    requireUnlocked();
    touchId = enabled;
  },
  async unlockTouchId() {
    await delay(700);
    if (!touchId) throw "password-required";
    stage = "unlocked";
  },
  async openAndFill(_id, url) {
    window.open(url, "_blank", "noopener");
    return { browser: null };
  },
  onUnlocked() {
    return () => {};
  },
  onLocked() {
    return () => {};
  },
  async siteIcon(url) {
    await delay(400);
    // Stand-in logos for a couple of seeded sites; the rest show letters.
    const host = url.replace(/^https?:\/\//, "").split("/")[0];
    const logo: Record<string, string> = {
      "github.com": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" fill="#fff"/><path fill="#1f2328" d="M8 1.5a6.5 6.5 0 0 0-2 12.7c.3 0 .4-.2.4-.3v-1.2c-1.8.4-2.2-.8-2.2-.8-.3-.8-.7-1-.7-1-.6-.4 0-.4 0-.4.7 0 1 .7 1 .7.6 1 1.6.7 2 .6 0-.4.2-.7.4-.9-1.4-.2-3-.7-3-3.2 0-.7.3-1.3.7-1.7-.1-.2-.3-.9.1-1.7 0 0 .5-.2 1.8.6a6 6 0 0 1 3.2 0C11 2.7 11.6 3 11.6 3c.3.8.1 1.5 0 1.7.5.4.7 1 .7 1.7 0 2.5-1.5 3-3 3.2.3.2.5.6.5 1.2v1.8c0 .2.1.4.4.3A6.5 6.5 0 0 0 8 1.5Z"/></svg>',
      "www.amazon.com": '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" fill="#9e2a2b"/><path d="M3.5 9.5c2.6 1.6 6.4 1.6 9 0" fill="none" stroke="#fff" stroke-width="1.1" stroke-linecap="round"/><path d="m11.4 8.8 1.3.6-.4 1.3" fill="none" stroke="#fff" stroke-width=".9" stroke-linecap="round"/></svg>',
    };
    return logo[host] ? `data:image/svg+xml,${encodeURIComponent(logo[host])}` : null;
  },
  onVaultChanged() {
    return () => {};
  },
  async phones() {
    return [...phones];
  },
  async addPhone() {
    await delay();
    // Pretend a phone scans the code after a few seconds.
    clearTimeout(pairing);
    pairing = setTimeout(() => {
      phones.push({ id: crypto.randomUUID(), name: "Pixel 9", pairedAt: now(), lastSync: now() });
      phoneListeners.forEach((f) => f());
    }, 6000);
    const cells = Array.from({ length: 21 * 21 }, (_, i) => ((i * 7919) % 13 < 6 ? 1 : 0));
    const rects = cells.map((c, i) => (c ? `<rect x="${i % 21}" y="${Math.floor(i / 21)}" width="1" height="1"/>` : "")).join("");
    const qr = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 25 25" width="240" height="240"><rect x="-2" y="-2" width="25" height="25" fill="#fff"/>${rects}</svg>`;
    return { qr, expiresAt: now() + 5 * 60_000, computerName: "Linus's MacBook Pro" };
  },
  async cancelAddPhone() {
    clearTimeout(pairing);
  },
  async removePhone(id) {
    phones = phones.filter((p) => p.id !== id);
  },
  onPhonesChanged(callback) {
    phoneListeners.add(callback);
    return () => void phoneListeners.delete(callback);
  },
  async appSettings() {
    return { ...settings };
  },
  async setAppSettings(next) {
    settings = { ...next };
  },
  async backups() {
    return { dir: settings.backupDir ?? "~/Library/Application Support/app.vaultix.desktop/backups", backups: [...backups] };
  },
  async backupNow() {
    requireUnlocked();
    await delay(600);
    const b = { id: new Date().toISOString().slice(0, 19).replace("T", "_").replace(/:/g, ""), createdAt: now() };
    backups.unshift(b);
    return b;
  },
  async revealBackups() {},
  async backupChanges(id) {
    requireUnlocked();
    await delay(300);
    if (id !== backups[backups.length - 1]?.id) return [];
    if (deletedInBackup.length === 0) {
      deletedInBackup.push({ ...[...items.values()][0], id: crypto.randomUUID(), title: "Old forum account", username: "alice_1999", urls: ["https://forum.example"] });
    }
    const gh = [...items.values()].find((i) => i.title === "GitHub");
    return [
      ...deletedInBackup.filter((d) => !items.has(d.id)).map((d) => ({ id: d.id, title: d.title, subtitle: d.username, category: d.category, change: "deleted" as const, updatedAt: now() - 86_400_000 * 90 })),
      ...(gh ? [{ id: gh.id, title: gh.title, subtitle: gh.username, category: gh.category, change: "changed" as const, updatedAt: now() - 86_400_000 * 50 }] : []),
    ];
  },
  async restoreFromBackup(_id, itemIds) {
    requireUnlocked();
    await delay(400);
    for (const id of itemIds) {
      const d = deletedInBackup.find((x) => x.id === id);
      if (d) items.set(d.id, structuredClone(d));
    }
    return itemIds.length;
  },
  async pickImportFile() {
    // Each pick shows the next kind of file.
    const files = ["/Users/you/Downloads/1PasswordExport-ABCD-20261028-091500.1pux", "/Users/you/Documents/Passwords.kdbx"];
    return files[importPicks++ % files.length];
  },
  async pickKeyFile() {
    return "/Users/you/Documents/Passwords.keyx";
  },
  async importPreview(path, password) {
    requireUnlocked();
    await delay(700);
    if (path.endsWith(".kdbx")) {
      if (password === undefined) throw "kdbx-password";
      if (password !== "correct horse battery staple") throw "kdbx-wrong-key";
      return {
        source: "KeePass",
        fileName: path.split("/").pop() ?? path,
        counts: [["login", 96], ["secureNote", 7]],
        duplicates: 2,
        files: 1,
        warnings: ["4 items in the recycle bin left out."],
      };
    }
    return {
      source: path.endsWith(".csv") ? "Chrome" : "1Password",
      fileName: path.split("/").pop() ?? path,
      counts: [["login", 182], ["creditCard", 3], ["identity", 1], ["secureNote", 14], ["document", 2]],
      duplicates: 6,
      files: 4,
      warnings: [
        "3 archived items left out.",
        "2 passkeys can't be exported from 1Password. Their logins are imported; add the passkeys again on those sites.",
      ],
    };
  },
  async importCommit() {
    requireUnlocked();
    await delay(1200);
    for (const title of ["Dropbox", "Netflix", "Slack"]) {
      const id = crypto.randomUUID();
      items.set(id, { ...structuredClone([...items.values()][1]), id, title, urls: [`https://${title.toLowerCase()}.com`], passwordHistory: [] });
    }
    return 202;
  },
  async importCancel() {},
  async trashImportedFile() {
    await delay(150);
  },
  async scanTotpQr() {
    await delay(900);
    return "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
  },
  async scanTotpQrImage() {
    await delay(300);
    return "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";
  },
  async quickCopy(id, what) {
    requireUnlocked();
    const item = items.get(id);
    if (!item) throw "item not found";
    const text = what === "password" ? item.password : what === "username" ? item.username : code().code;
    await navigator.clipboard?.writeText(text).catch(() => {});
  },
  async quickHide() {},
  onQuickOpened() {
    return () => {};
  },
};

// The quick search window (`?quick`) has no setup screen of its own: start unlocked.
if (new URLSearchParams(location.search).has("quick")) {
  seed();
  vaultDir = "/Users/you/Library/Mobile Documents/com~apple~CloudDocs/Vaultix Vault";
  stage = "unlocked";
}
