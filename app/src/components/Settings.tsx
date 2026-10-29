import { useCallback, useEffect, useState } from "react";
import {
  api,
  errorMessage,
  type AppSettings,
  type Backups,
  type LinkStatus,
  type PhoneInvite,
  type PhoneView,
  type TouchIdStatus,
} from "../api";
import { biometric, computer, fileManager, isMac, isPhone, keys, systemName } from "../platform";
import { setThemePref, useTheme, type ThemePref } from "../theme";
import { ImportDialog } from "./ImportDialog";
import { RestoreDialog } from "./RestoreDialog";
import { Icon, IconButton, Spinner, TouchIdIcon } from "./ui";

const THEMES: { id: ThemePref; label: string }[] = [
  { id: "system", label: "System" },
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
];

const ENROLL_ERRORS: Record<string, string> = {
  "touch-id-unavailable": isPhone
    ? "No fingerprint or face is set up. Add one in Android's Settings → Security."
    : isMac
      ? "Touch ID isn't available. Add a fingerprint in System Settings → Touch ID & Password."
      : "Windows Hello isn't set up. Set it up in Settings → Accounts → Sign-in options.",
  "touch-id-cancelled": `${biometric} was cancelled.`,
};

export function Settings({ onError, onVaultChanged }: { onError: (e: unknown) => void; onVaultChanged: () => void }) {
  const [touchId, setTouchId] = useState<TouchIdStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [dialog, setDialog] = useState<"import" | "restore" | null>(null);
  const { pref } = useTheme();

  useEffect(() => {
    api.touchIdStatus().then(setTouchId, onError);
    api.appSettings().then(setSettings, onError);
  }, [onError]);

  async function change(patch: Partial<AppSettings>) {
    if (!settings) return;
    const next = { ...settings, ...patch };
    setSettings(next);
    try {
      await api.setAppSettings(next);
    } catch (e) {
      setSettings(settings);
      onError(e);
    }
  }

  async function toggle() {
    if (!touchId) return;
    setBusy(true);
    setError("");
    try {
      await api.setTouchId(!touchId.enabled);
      setTouchId(await api.touchIdStatus());
      // The "Turn on?" offer above is answered now.
      window.dispatchEvent(new Event("vaultix-touch-id-changed"));
    } catch (e) {
      const code = errorMessage(e);
      if (code === "locked") onError(e);
      else setError(ENROLL_ERRORS[code] ?? `Couldn't turn on ${biometric} (${code}).`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="item-detail settings">
      <header className="detail-header">
        <span className="settings-icon">
          <Icon name="gear" size={26} />
        </span>
        <div className="detail-title">
          <h1>Settings</h1>
          <span className="item-sub">{isPhone ? "This phone" : `This ${computer}`}</span>
        </div>
      </header>

      <section className="card">
        <div className="setting">
          <Icon name="moon" size={26} />
          <div className="setting-text">
            <strong>Appearance</strong>
            <p className="muted">Light or dark, or follow {systemName}.{isPhone ? "" : " The moon and sun next to the Vaultix name switch it quickly."}</p>
          </div>
          <div className="segmented" role="radiogroup" aria-label="Appearance">
            {THEMES.map((t) => (
              <button
                key={t.id}
                type="button"
                role="radio"
                aria-checked={pref === t.id}
                className={pref === t.id ? "on" : ""}
                onClick={() => setThemePref(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="card">
        {biometric && (
          <div className="setting">
            <TouchIdIcon size={26} />
            <div className="setting-text">
              <strong>Unlock with {isPhone ? "fingerprint or face" : biometric}</strong>
              <p className="muted">
                {isPhone
                  ? "Unlock Vaultix with your fingerprint or face. The key stays in this phone's secure hardware, and your master password is still asked for every two weeks."
                  : isMac
                    ? "Unlock Vaultix, here and from the browser extension, with your fingerprint. The key stays in this Mac's Secure Enclave, and your master password is still asked for every two weeks."
                    : "Unlock Vaultix, here and from the browser extension, with your face, fingerprint or PIN. The key stays in this computer's security chip, and your master password is still asked for every two weeks."}
              </p>
              {touchId && !touchId.available && (
                <p className="warn-text">
                  {isPhone
                    ? "No fingerprint or face is set up. Add one in Android's Settings → Security."
                    : isMac
                      ? "This Mac has no Touch ID, or no fingerprint is set up in System Settings."
                      : "Windows Hello isn't set up on this computer. Set it up in Settings → Accounts → Sign-in options."}
                </p>
              )}
              {touchId?.enabled && touchId.passwordRequired && (
                <p className="warn-text">Lock and unlock once with your master password to use {biometric} again.</p>
              )}
              {error && <p className="error-text">{error}</p>}
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={!!touchId?.enabled}
              aria-label={`Unlock with ${biometric}`}
              className={`switch${touchId?.enabled ? " on" : ""}`}
              disabled={!touchId || busy || (!touchId.available && !touchId.enabled)}
              onClick={toggle}
            >
              {busy ? <Spinner /> : <span className="knob" />}
            </button>
          </div>
        )}
        {!isPhone && (
          <div className="setting">
            <Icon name="lock" size={26} />
            <div className="setting-text">
              <strong>Lock when your {computer} sleeps</strong>
              <p className="muted">
                Also when the screen locks or another user switches in. Vaultix still locks after 5 idle minutes either way.
              </p>
            </div>
            <Switch
              label={`Lock when your ${computer} sleeps`}
              on={!!settings?.lockOnSleep}
              disabled={!settings}
              onChange={(on) => change({ lockOnSleep: on })}
            />
          </div>
        )}
        {isPhone && (
          <div className="setting">
            <Icon name="lock" size={26} />
            <div className="setting-text">
              <strong>Locks by itself</strong>
              <p className="muted">When you leave Vaultix for 30 seconds, and after 5 minutes without use.</p>
            </div>
          </div>
        )}
      </section>

      {isPhone ? (
        <ComputerCard onError={onError} />
      ) : (
        <>
          <section className="card">
            <div className="setting">
              <Icon name="search" size={26} />
              <div className="setting-text">
                <strong>
                  Quick search <kbd>{isMac ? "⌘" : "Ctrl"}</kbd>
                  <kbd>{isMac ? "⇧" : "Shift"}</kbd>
                  <kbd>Space</kbd>
                </strong>
                <p className="muted">
                  Find a login from any app and copy its password with {keys.enter}, username with {keys.shift}
                  {keys.enter} or one-time code with {keys.alt}
                  {keys.enter}, without opening this window.
                </p>
              </div>
              <Switch
                label="Quick search"
                on={!!settings?.quickSearch}
                disabled={!settings}
                onChange={(on) => change({ quickSearch: on })}
              />
            </div>
          </section>

          <PhonesCard onError={onError} />

          <BackupsCard
            settings={settings}
            onPickFolder={(dir) => change({ backupDir: dir })}
            onRestore={() => setDialog("restore")}
            onError={onError}
          />
        </>
      )}

      {!isPhone && (
        <section className="card">
          <div className="setting">
            <Icon name="arrowRight" size={26} />
            <div className="setting-text">
              <strong>Import</strong>
              <p className="muted">Bring your passwords over from 1Password, KeePass, Chrome, Edge, Safari, Firefox or Bitwarden.</p>
            </div>
            <button className="btn" onClick={() => setDialog("import")}>
              Import…
            </button>
          </div>
        </section>
      )}

      {dialog === "import" && <ImportDialog onClose={() => setDialog(null)} onImported={onVaultChanged} />}
      {dialog === "restore" && <RestoreDialogLoader onClose={() => setDialog(null)} onRestored={onVaultChanged} onError={onError} />}
    </article>
  );
}

function Switch({ label, on, disabled, onChange }: { label: string; on: boolean; disabled?: boolean; onChange: (on: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      className={`switch${on ? " on" : ""}`}
      disabled={disabled}
      onClick={() => onChange(!on)}
    >
      <span className="knob" />
    </button>
  );
}

const when = (ms: number) => new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

function BackupsCard({
  settings,
  onPickFolder,
  onRestore,
  onError,
}: {
  settings: AppSettings | null;
  onPickFolder: (dir: string | null) => void;
  onRestore: () => void;
  onError: (e: unknown) => void;
}) {
  const [backups, setBackups] = useState<Backups | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api.backups().then(setBackups, onError), [onError]);
  useEffect(() => {
    load();
  }, [load, settings?.backupDir]);

  async function backUpNow() {
    setBusy(true);
    try {
      await api.backupNow();
      await load();
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  const newest = backups?.backups[0];
  return (
    <section className="card">
      <div className="setting">
        <Icon name="shield" size={26} />
        <div className="setting-text">
          <strong>Backups</strong>
          <p className="muted">
            Once a day, Vaultix keeps an encrypted copy of your vault on this {computer}, outside the synced folder: the last two weeks,
            then one a month for a year.
          </p>
          <p className="muted small">
            {newest ? `Last backup ${when(newest.createdAt)}` : "No backup yet"}
            {backups && ` · ${backups.backups.length} kept in `}
            {backups && <span className="path">{backups.dir}</span>}
          </p>
          <div className="setting-actions">
            <button className="btn" onClick={backUpNow} disabled={busy}>
              {busy && <Spinner />} Back up now
            </button>
            <button className="btn" onClick={onRestore} disabled={!newest}>
              Restore…
            </button>
            <button className="btn plain" onClick={() => api.revealBackups().catch(onError)}>
              Show in {fileManager}
            </button>
            <button
              className="btn plain"
              onClick={async () => {
                const dir = await api.pickFolder("Choose a folder for backups, e.g. on an external disk");
                if (dir) onPickFolder(dir);
              }}
            >
              Change folder…
            </button>
            {settings?.backupDir && (
              <button className="btn plain" onClick={() => onPickFolder(null)}>
                Use default folder
              </button>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

const ago = (ms: number) => {
  const min = Math.round((Date.now() - ms) / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  return when(ms);
};

const PAIR_ERRORS: Record<string, string> = {
  "no-vault": "Set up a vault first.",
  "no-network": `This ${computer} isn't on a network. Connect it to the same Wi-Fi as your phone.`,
};

function PhonesCard({ onError }: { onError: (e: unknown) => void }) {
  const [phones, setPhones] = useState<PhoneView[] | null>(null);
  const [adding, setAdding] = useState(false);
  const load = useCallback(() => api.phones().then(setPhones, onError), [onError]);
  useEffect(() => {
    load();
    return api.onPhonesChanged(load);
  }, [load]);

  async function remove(phone: PhoneView) {
    if (
      !confirm(
        `Remove ${phone.name}? It stops syncing with this ${computer}. Its copy of the vault stays on the phone until you remove Vaultix there.`,
      )
    )
      return;
    try {
      await api.removePhone(phone.id);
      await load();
    } catch (e) {
      onError(e);
    }
  }

  return (
    <section className="card">
      <div className="setting">
        <Icon name="phone" size={26} />
        <div className="setting-text">
          <strong>Phones</strong>
          <p className="muted">
            Use your vault on your Android phone. It syncs with this {computer} over your Wi-Fi whenever both are on the same network and
            Vaultix is open here; nothing goes through the internet.
          </p>
          {phones && phones.length > 0 && (
            <ul className="phone-list">
              {phones.map((p) => (
                <li key={p.id}>
                  <span>
                    <strong>{p.name}</strong>
                    <span className="muted small">{p.lastSync ? `Synced ${ago(p.lastSync)}` : `Paired ${when(p.pairedAt)}`}</span>
                  </span>
                  <button className="btn plain" onClick={() => remove(p)}>
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="setting-actions">
            <button className="btn" onClick={() => setAdding(true)}>
              Add a phone…
            </button>
          </div>
        </div>
      </div>
      {adding && (
        <AddPhoneDialog
          phones={phones ?? []}
          onClose={() => {
            setAdding(false);
            api.cancelAddPhone().catch(() => {});
          }}
        />
      )}
    </section>
  );
}

function AddPhoneDialog({ phones, onClose }: { phones: PhoneView[]; onClose: () => void }) {
  // Phones paired before the dialog opened; a new one in the list is the one that scanned the code.
  const [known] = useState(() => new Set(phones.map((p) => p.id)));
  const [invite, setInvite] = useState<PhoneInvite | null>(null);
  const [error, setError] = useState("");
  const [left, setLeft] = useState(0);

  const start = useCallback(() => {
    setError("");
    setInvite(null);
    api.addPhone().then(setInvite, (e) => setError(PAIR_ERRORS[errorMessage(e)] ?? errorMessage(e)));
  }, []);
  useEffect(start, [start]);
  useEffect(() => {
    if (!invite) return;
    const tick = () => setLeft(Math.max(0, Math.round((invite.expiresAt - Date.now()) / 1000)));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [invite]);

  const paired = phones.find((p) => !known.has(p.id));

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal dialog add-phone" role="dialog" aria-modal="true" aria-labelledby="add-phone-title">
        <div className="modal-close">
          <IconButton icon="x" label="Close" onClick={onClose} />
        </div>
        <h1 id="add-phone-title">Add a phone</h1>
        {paired ? (
          <>
            <p className="notice">
              <Icon name="check" /> {paired.name} is paired and has your vault. Unlock it there with your master password.
            </p>
            <div className="dialog-actions">
              <button className="btn primary" onClick={onClose}>
                Done
              </button>
            </div>
          </>
        ) : (
          <>
            <ol className="steps">
              <li>Install Vaultix on your Android phone and open it.</li>
              <li>Connect the phone to the same Wi-Fi as this {computer}.</li>
              <li>
                Tap <strong>Pair with your computer</strong> and scan this code.
              </li>
            </ol>
            <div className="qr-box">
              {error ? (
                <p className="error-text">{error}</p>
              ) : !invite ? (
                <Spinner />
              ) : left > 0 ? (
                <img alt="Pairing code" src={`data:image/svg+xml,${encodeURIComponent(invite.qr)}`} width={240} height={240} />
              ) : (
                <button className="btn" onClick={start}>
                  Show a new code
                </button>
              )}
            </div>
            {invite && left > 0 && (
              <p className="muted small center">
                Works once, for {Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}. Only show it to your own phone.{" "}
                <button className="link" onClick={() => api.copySecret(invite.uri).catch(() => {})}>
                  Copy as text
                </button>
              </p>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/** On a phone: the computer it syncs with. */
function ComputerCard({ onError }: { onError: (e: unknown) => void }) {
  const [link, setLink] = useState<LinkStatus | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api.linkStatus().then(setLink, onError);
  }, [onError]);

  async function syncNow() {
    setBusy(true);
    try {
      setLink(await api.syncWithComputer());
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  async function unpair() {
    if (
      !confirm(
        `Remove the vault from this phone and stop syncing with ${link?.computerName ?? "your computer"}? Your vault stays on the computer.`,
      )
    )
      return;
    try {
      await api.unpair();
      location.reload();
    } catch (e) {
      onError(e);
    }
  }

  return (
    <section className="card">
      <div className="setting">
        <Icon name="refresh" size={26} />
        <div className="setting-text">
          <strong>Synced with {link?.computerName ?? "your computer"}</strong>
          <p className="muted">
            Over your Wi-Fi, whenever this phone and the computer are on the same network and Vaultix is open there. Changes made here wait
            on the phone until then.
          </p>
          <p className="muted small">
            {link?.lastError === "link-unreachable"
              ? "Can't reach it right now."
              : link?.lastError
                ? `The last sync failed (${link.lastError}).`
                : link?.lastSync
                  ? `Last synced ${ago(link.lastSync)}`
                  : "Not synced yet"}
          </p>
          <div className="setting-actions">
            <button className="btn" onClick={syncNow} disabled={busy}>
              {busy && <Spinner />} Sync now
            </button>
            <button className="btn plain" onClick={unpair}>
              Remove from this phone…
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

/** Loads the list of backups, then shows the restore dialog. */
function RestoreDialogLoader({
  onClose,
  onRestored,
  onError,
}: {
  onClose: () => void;
  onRestored: () => void;
  onError: (e: unknown) => void;
}) {
  const [backups, setBackups] = useState<Backups | null>(null);
  useEffect(() => {
    api.backups().then(setBackups, onError);
  }, [onError]);
  if (!backups) return null;
  return <RestoreDialog backups={backups.backups} onClose={onClose} onRestored={onRestored} onError={onError} />;
}

/** One-time offer after a master password unlock. */
export function TouchIdOffer({ onDone }: { onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <div className="banner offer" role="status">
      <TouchIdIcon />
      <span>Unlock Vaultix with {biometric} next time?</span>
      {error && <span className="error-text">{error}</span>}
      <span className="row-end">
        <button className="btn" onClick={onDone} disabled={busy}>
          Not now
        </button>
        <button
          className="btn primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              await api.setTouchId(true);
              onDone();
            } catch (e) {
              setError(ENROLL_ERRORS[errorMessage(e)] ?? errorMessage(e));
              setBusy(false);
            }
          }}
        >
          Turn on
        </button>
      </span>
    </div>
  );
}
