import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, type AppSettings, type Backups, type TouchIdStatus } from "../api";
import { setThemePref, useTheme, type ThemePref } from "../theme";
import { ImportDialog } from "./ImportDialog";
import { RestoreDialog } from "./RestoreDialog";
import { Icon, Spinner, TouchIdIcon } from "./ui";

const THEMES: { id: ThemePref; label: string }[] = [
  { id: "system", label: "System" },
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
];

const ENROLL_ERRORS: Record<string, string> = {
  "touch-id-unavailable": "Touch ID isn't available. Add a fingerprint in System Settings → Touch ID & Password.",
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
    } catch (e) {
      const code = errorMessage(e);
      if (code === "locked") onError(e);
      else setError(ENROLL_ERRORS[code] ?? `Couldn't turn on Touch ID (${code}).`);
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
          <span className="item-sub">This Mac</span>
        </div>
      </header>

      <section className="card">
        <div className="setting">
          <Icon name="moon" size={26} />
          <div className="setting-text">
            <strong>Appearance</strong>
            <p className="muted">Light or dark, or follow macOS. The moon and sun next to the Vaultix name switch it quickly.</p>
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
        <div className="setting">
          <TouchIdIcon size={26} />
          <div className="setting-text">
            <strong>Unlock with Touch ID</strong>
            <p className="muted">
              Unlock Vaultix, here and from the browser extension, with your fingerprint. The key stays in this Mac's Secure
              Enclave, and your master password is still asked for every two weeks.
            </p>
            {touchId && !touchId.available && (
              <p className="warn-text">This Mac has no Touch ID, or no fingerprint is set up in System Settings.</p>
            )}
            {touchId?.enabled && touchId.passwordRequired && (
              <p className="warn-text">Lock and unlock once with your master password to use Touch ID again.</p>
            )}
            {error && <p className="error-text">{error}</p>}
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={!!touchId?.enabled}
            aria-label="Unlock with Touch ID"
            className={`switch${touchId?.enabled ? " on" : ""}`}
            disabled={!touchId || busy || (!touchId.available && !touchId.enabled)}
            onClick={toggle}
          >
            {busy ? <Spinner /> : <span className="knob" />}
          </button>
        </div>
        <div className="setting">
          <Icon name="lock" size={26} />
          <div className="setting-text">
            <strong>Lock when your Mac sleeps</strong>
            <p className="muted">Also when the screen locks or another user switches in. Vaultix still locks after 5 idle minutes either way.</p>
          </div>
          <Switch label="Lock when your Mac sleeps" on={!!settings?.lockOnSleep} disabled={!settings} onChange={(on) => change({ lockOnSleep: on })} />
        </div>
      </section>

      <section className="card">
        <div className="setting">
          <Icon name="search" size={26} />
          <div className="setting-text">
            <strong>
              Quick search <kbd>⌘</kbd>
              <kbd>⇧</kbd>
              <kbd>Space</kbd>
            </strong>
            <p className="muted">
              Find a login from any app and copy its password with ↵, username with ⇧↵ or one-time code with ⌥↵, without
              opening this window.
            </p>
          </div>
          <Switch label="Quick search" on={!!settings?.quickSearch} disabled={!settings} onChange={(on) => change({ quickSearch: on })} />
        </div>
      </section>

      <BackupsCard settings={settings} onPickFolder={(dir) => change({ backupDir: dir })} onRestore={() => setDialog("restore")} onError={onError} />

      <section className="card">
        <div className="setting">
          <Icon name="arrowRight" size={26} />
          <div className="setting-text">
            <strong>Import</strong>
            <p className="muted">Bring your passwords over from 1Password, Chrome, Edge, Safari, Firefox or Bitwarden.</p>
          </div>
          <button className="btn" onClick={() => setDialog("import")}>
            Import…
          </button>
        </div>
      </section>

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
            Once a day, Vaultix keeps an encrypted copy of your vault on this Mac, outside the synced folder: the last two
            weeks, then one a month for a year.
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
              Show in Finder
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

/** Loads the list of backups, then shows the restore dialog. */
function RestoreDialogLoader({ onClose, onRestored, onError }: { onClose: () => void; onRestored: () => void; onError: (e: unknown) => void }) {
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
      <span>Unlock Vaultix with Touch ID next time?</span>
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
