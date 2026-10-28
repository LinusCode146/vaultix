import { useEffect, useState } from "react";
import { api, errorMessage, type ImportPreview } from "../api";
import { CategoryIcon, categoryDef } from "../categories";
import { IconButton, Spinner } from "./ui";

const SOURCES: { name: string; how: string }[] = [
  { name: "1Password", how: "File → Export → your account, then choose the 1PUX format." },
  { name: "KeePass, KeePassXC", how: "Choose the .kdbx database itself. You'll enter its password here." },
  { name: "Chrome, Edge, Brave", how: "Settings → Passwords (Password Manager) → Settings → Export passwords." },
  { name: "Safari / Passwords", how: "In the Passwords app: File → Export All Passwords." },
  { name: "Firefox", how: "Passwords → ⋯ → Export Passwords." },
  { name: "Bitwarden", how: "Tools → Export vault → .csv (not the encrypted kind)." },
];

type Step =
  | { kind: "pick"; error?: string }
  | { kind: "reading" }
  | { kind: "kdbx"; path: string; keyFile?: string; busy?: boolean; error?: string }
  | { kind: "preview"; preview: ImportPreview }
  | { kind: "importing"; preview: ImportPreview }
  | { kind: "done"; count: number; source: string; trashed: boolean };

/** Import from 1Password, KeePass, a browser or Bitwarden: pick the export, see what it adds, then import. */
export function ImportDialog({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [step, setStep] = useState<Step>({ kind: "pick" });
  const [kdbxPassword, setKdbxPassword] = useState("");
  const busy = step.kind === "reading" || step.kind === "importing" || (step.kind === "kdbx" && !!step.busy);

  const close = () => {
    if (busy) return;
    if (step.kind === "preview") api.importCancel();
    onClose();
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      close();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  });

  async function pick() {
    const path = await api.pickImportFile();
    if (!path) return;
    setStep({ kind: "reading" });
    try {
      setStep({ kind: "preview", preview: await api.importPreview(path) });
    } catch (e) {
      if (errorMessage(e) === "kdbx-password") setStep({ kind: "kdbx", path });
      else setStep({ kind: "pick", error: errorMessage(e) });
    }
  }

  async function openKdbx(step: Extract<Step, { kind: "kdbx" }>) {
    setStep({ ...step, busy: true, error: undefined });
    try {
      const preview = await api.importPreview(step.path, kdbxPassword, step.keyFile);
      setKdbxPassword("");
      setStep({ kind: "preview", preview });
    } catch (e) {
      const wrongKey = step.keyFile ? "Wrong password or key file." : "Wrong password. If the database has a key file, choose it too.";
      setStep({ ...step, busy: false, error: errorMessage(e) === "kdbx-wrong-key" ? wrongKey : errorMessage(e) });
    }
  }

  async function commit(preview: ImportPreview) {
    setStep({ kind: "importing", preview });
    try {
      const count = await api.importCommit();
      setStep({ kind: "done", count, source: preview.source, trashed: false });
      onImported();
    } catch (e) {
      setStep({ kind: "pick", error: errorMessage(e) });
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className="modal dialog" role="dialog" aria-modal="true" aria-labelledby="import-title">
        <div className="modal-close">
          <IconButton icon="x" label="Close" onClick={close} />
        </div>
        <h1 id="import-title">Import passwords</h1>

        {(step.kind === "pick" || step.kind === "reading") && (
          <>
            <p className="muted">Export your passwords from the app you use now, then choose the file here.</p>
            <dl className="how-to">
              {SOURCES.map((s) => (
                <div key={s.name}>
                  <dt>{s.name}</dt>
                  <dd>{s.how}</dd>
                </div>
              ))}
            </dl>
            {step.kind === "pick" && step.error && <p className="error-text">{step.error}</p>}
            <div className="dialog-actions">
              <button className="btn" onClick={close} disabled={busy}>
                Cancel
              </button>
              <button className="btn primary" onClick={pick} disabled={busy} autoFocus>
                {busy && <Spinner />} Choose export file…
              </button>
            </div>
          </>
        )}

        {step.kind === "kdbx" && (
          <form
            className="stack"
            onSubmit={(e) => {
              e.preventDefault();
              openKdbx(step);
            }}
          >
            <p className="muted">
              {fileName(step.path)} is a KeePass database. Enter its password to read it. Vaultix doesn't keep the password.
            </p>
            <label className="field">
              <span className="field-label">Database password</span>
              <input
                type="password"
                value={kdbxPassword}
                onChange={(e) => setKdbxPassword(e.target.value)}
                disabled={step.busy}
                autoFocus
              />
            </label>
            <div className="key-file">
              {step.keyFile && <span>Key file: {fileName(step.keyFile)}</span>}
              <button
                type="button"
                className="btn plain"
                disabled={step.busy}
                onClick={async () => {
                  if (step.keyFile) return setStep({ ...step, keyFile: undefined });
                  const keyFile = await api.pickKeyFile();
                  if (keyFile) setStep({ ...step, keyFile, error: undefined });
                }}
              >
                {step.keyFile ? "Remove" : "Uses a key file? Choose it…"}
              </button>
            </div>
            {step.error && <p className="error-text">{step.error}</p>}
            <div className="dialog-actions">
              <button type="button" className="btn" onClick={() => (setKdbxPassword(""), setStep({ kind: "pick" }))} disabled={step.busy}>
                Choose another file
              </button>
              <button type="submit" className="btn primary" disabled={step.busy || (!kdbxPassword && !step.keyFile)}>
                {step.busy && <Spinner />} Open database
              </button>
            </div>
          </form>
        )}

        {(step.kind === "preview" || step.kind === "importing") && <PreviewBody preview={step.preview} />}
        {step.kind === "preview" && (
          <div className="dialog-actions">
            <button className="btn" onClick={() => (api.importCancel(), setStep({ kind: "pick" }))}>
              Choose another file
            </button>
            <button className="btn primary" onClick={() => commit(step.preview)} disabled={total(step.preview) === 0} autoFocus>
              Import {total(step.preview)} item{total(step.preview) === 1 ? "" : "s"}
            </button>
          </div>
        )}
        {step.kind === "importing" && (
          <div className="dialog-actions">
            <button className="btn primary" disabled>
              <Spinner /> Importing…
            </button>
          </div>
        )}

        {step.kind === "done" && (
          <>
            <p>
              Imported {step.count} item{step.count === 1 ? "" : "s"} from {step.source}. The vault was backed up first, so
              you can undo this from Settings → Backups.
            </p>
            {step.source !== "KeePass" && (
              <div className={step.trashed ? "notice" : "notice warn"}>
                {step.trashed ? (
                  <p>The export file is in the Trash. Empty the Trash to delete it for good.</p>
                ) : (
                  <>
                    <p>
                      <strong>The export file holds all your passwords, unencrypted.</strong> Don't keep it around.
                    </p>
                    <button
                      className="btn"
                      onClick={() =>
                        api.trashImportedFile().then(
                          () => setStep({ ...step, trashed: true }),
                          (e) => setStep({ kind: "pick", error: errorMessage(e) }),
                        )
                      }
                    >
                      Move it to the Trash
                    </button>
                  </>
                )}
              </div>
            )}
            <div className="dialog-actions">
              <button className="btn primary" onClick={onClose} autoFocus>
                Done
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

const fileName = (path: string) => path.split("/").pop() ?? path;

const total = (p: ImportPreview) => p.counts.reduce((n, [, c]) => n + c, 0);

function PreviewBody({ preview }: { preview: ImportPreview }) {
  return (
    <>
      <p className="muted">
        From {preview.source} · {preview.fileName}
      </p>
      {total(preview) === 0 ? (
        <p>Everything in this file is in your vault already.</p>
      ) : (
        <ul className="import-counts">
          {preview.counts.map(([category, count]) => (
            <li key={category}>
              <CategoryIcon category={category} size={30} />
              <span>{categoryDef(category).plural}</span>
              <strong>{count}</strong>
            </li>
          ))}
        </ul>
      )}
      <ul className="import-notes">
        {preview.files > 0 && <li>{preview.files} attached file{preview.files === 1 ? "" : "s"} included.</li>}
        {preview.duplicates > 0 && (
          <li>
            {preview.duplicates} item{preview.duplicates === 1 ? " is" : "s are"} in your vault already and will be skipped.
          </li>
        )}
        {preview.warnings.map((w) => (
          <li key={w}>{w}</li>
        ))}
      </ul>
    </>
  );
}
