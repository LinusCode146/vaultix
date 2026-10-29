import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage, type MasterPasswordCheck } from "../api";
import { Spinner, StrengthMeter } from "../components/ui";
import { computer, computers, isPhone, syncedFolder } from "../platform";

type Mode = "choose" | "create" | "join";

export function Setup({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<Mode>("choose");
  if (isPhone) return <PhoneSetup onDone={onDone} />;

  return (
    <div className="center-screen">
      <div className="panel">
        <div className="brand">
          <img src="/logo.svg" alt="" width={48} height={48} />
          <h1>Vaultix</h1>
        </div>
        {mode === "choose" && (
          <>
            <p className="lead">Set up this {computer}.</p>
            <div className="choice-list">
              <button className="choice" onClick={() => setMode("create")}>
                <strong>Create a new vault</strong>
                <span>Start fresh. You'll pick a synced folder, such as {syncedFolder}, to keep it in.</span>
              </button>
              <button className="choice" onClick={() => setMode("join")}>
                <strong>Use an existing vault</strong>
                <span>Already using Vaultix on another {computer}? Point this one at the same folder.</span>
              </button>
            </div>
          </>
        )}
        {mode === "create" && <CreateForm onBack={() => setMode("choose")} onCreated={onDone} />}
        {mode === "join" && <JoinForm onBack={() => setMode("choose")} onJoined={onDone} />}
      </div>
    </div>
  );
}

function FolderPicker({ value, onChange, title }: { value: string; onChange: (v: string) => void; title: string }) {
  return (
    <div className="folder-picker">
      <span className={value ? "folder-path" : "folder-path placeholder"} title={value}>
        {value || "No folder chosen"}
      </span>
      <button
        type="button"
        className="btn"
        onClick={async () => {
          const picked = await api.pickFolder(title);
          if (picked) onChange(picked);
        }}
      >
        Choose…
      </button>
    </div>
  );
}

function CreateForm({ onBack, onCreated }: { onBack: () => void; onCreated: () => void }) {
  const [folder, setFolder] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [check, setCheck] = useState<MasterPasswordCheck | null>(null);

  useEffect(() => {
    if (!password) {
      setCheck(null);
      return;
    }
    const t = setTimeout(() => api.masterPasswordCheck(password).then(setCheck, () => {}), 150);
    return () => clearTimeout(t);
  }, [password]);

  const mismatch = confirm.length > 0 && confirm !== password;
  const canSubmit = folder && check !== null && check.problem === null && password === confirm && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    try {
      await api.createVault(folder, password);
      onCreated();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="stack">
      <h2>Create a new vault</h2>
      <label className="field">
        <span className="field-label">Where to keep it</span>
        <FolderPicker value={folder} onChange={setFolder} title="Choose a synced folder for your vault" />
        <span className="hint">A "Vaultix Vault" folder is created inside. Pick a folder that syncs to your other {computers}.</span>
      </label>
      <label className="field">
        <span className="field-label">Master password</span>
        <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        <StrengthMeter strength={password ? (check?.strength ?? null) : null} />
        <span className={check?.problem ? "hint warn-text" : "hint"}>
          {check?.problem ??
            "This is the only thing protecting your vault, and it can't be recovered if you forget it. Five or more random words make a strong one that's easy to type."}
        </span>
      </label>
      <label className="field">
        <span className="field-label">Confirm master password</span>
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          aria-invalid={mismatch}
          autoComplete="new-password"
        />
        {mismatch && <span className="hint error-text">The passwords don't match.</span>}
      </label>
      {error && <p className="error-text">{error}</p>}
      <div className="row-end">
        <button type="button" className="btn" onClick={onBack} disabled={busy}>
          Back
        </button>
        <button type="submit" className="btn primary" disabled={!canSubmit}>
          {busy ? <Spinner /> : null} Create vault
        </button>
      </div>
    </form>
  );
}

function JoinForm({ onBack, onJoined }: { onBack: () => void; onJoined: () => void }) {
  const [folder, setFolder] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const canSubmit = folder && password && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    try {
      await api.joinVault(folder, password);
      onJoined();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="stack">
      <h2>Use an existing vault</h2>
      <label className="field">
        <span className="field-label">Vault folder</span>
        <FolderPicker value={folder} onChange={setFolder} title='Choose the "Vaultix Vault" folder' />
        <span className="hint">The "Vaultix Vault" folder, or the folder that contains it.</span>
      </label>
      <label className="field">
        <span className="field-label">Master password</span>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
      </label>
      {error && <p className="error-text">{error}</p>}
      <div className="row-end">
        <button type="button" className="btn" onClick={onBack} disabled={busy}>
          Back
        </button>
        <button type="submit" className="btn primary" disabled={!canSubmit}>
          {busy ? <Spinner /> : null} Unlock
        </button>
      </div>
    </form>
  );
}

const PAIR_ERRORS: Record<string, string> = {
  "link-bad-invite": "That isn't a Vaultix pairing code. On your computer, open Settings → Phones → Add a phone.",
  "link-unreachable": "Couldn't reach your computer. Make sure Vaultix is open there and both are on the same Wi-Fi.",
  "link-bad-code": "That code was already used or has expired. Show a new one on your computer.",
  "link-no-vault": "Vaultix on your computer has no vault yet. Set one up there first.",
  "link-version": "Vaultix on your computer is a different version. Update both to the latest.",
  "camera-denied": "Vaultix needs the camera to scan the code. Allow it in Android's settings, or paste the code instead.",
};

/** The phone has no vault of its own: it gets it from a computer it pairs with. */
function PhoneSetup({ onDone }: { onDone: () => void }) {
  const [pasting, setPasting] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function pair(invite: string | null) {
    if (!invite) return;
    setBusy(true);
    setError("");
    try {
      await api.pairWithComputer(invite);
      onDone();
    } catch (e) {
      const c = errorMessage(e);
      setError(PAIR_ERRORS[c] ?? `Pairing failed (${c}).`);
      setBusy(false);
    }
  }

  async function scan() {
    setError("");
    try {
      await pair(await api.scanQrCode());
    } catch (e) {
      const c = errorMessage(e);
      setError(PAIR_ERRORS[c] ?? `Couldn't scan (${c}).`);
    }
  }

  return (
    <div className="center-screen">
      <div className="panel">
        <div className="brand">
          <img src="/logo.svg" alt="" width={48} height={48} />
          <h1>Vaultix</h1>
        </div>
        <p className="lead">Pair with your computer</p>
        <ol className="steps">
          <li>Open Vaultix on your computer.</li>
          <li>
            Go to <strong>Settings → Phones → Add a phone</strong>.
          </li>
          <li>Scan the code it shows. Keep this phone on the same Wi-Fi.</li>
        </ol>
        <p className="muted small">
          Your vault is copied straight from your computer over your Wi-Fi, encrypted, and stays in sync whenever both are on the same
          network. It never goes through the internet.
        </p>
        {pasting ? (
          <form
            className="stack"
            onSubmit={(e: FormEvent) => {
              e.preventDefault();
              pair(code);
            }}
          >
            <label className="field">
              <span className="field-label">Pairing code</span>
              <textarea
                rows={3}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="vaultix://pair?…"
                autoFocus
                disabled={busy}
              />
              <span className="hint">On your computer, click Copy as text under the QR code, and get the text to this phone.</span>
            </label>
            {error && <p className="error-text">{error}</p>}
            <div className="row-end">
              <button type="button" className="btn" onClick={() => setPasting(false)} disabled={busy}>
                Back
              </button>
              <button type="submit" className="btn primary" disabled={busy || !code.trim()}>
                {busy && <Spinner />} Pair
              </button>
            </div>
          </form>
        ) : (
          <>
            {error && <p className="error-text">{error}</p>}
            <div className="phone-actions">
              <button className="btn primary big" onClick={scan} disabled={busy}>
                {busy ? <Spinner /> : null} {busy ? "Getting your vault…" : "Scan the code"}
              </button>
              <button className="btn plain" onClick={() => setPasting(true)} disabled={busy}>
                Paste the code instead
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
