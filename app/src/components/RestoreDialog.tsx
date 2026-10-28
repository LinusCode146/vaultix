import { useEffect, useState } from "react";
import { api, type BackupInfo, type BackupItem } from "../api";
import { CategoryIcon } from "../categories";
import { IconButton, Spinner } from "./ui";

const when = (ms: number) => new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

/** Bring back items deleted or changed since a backup. */
export function RestoreDialog({
  backups,
  onClose,
  onRestored,
  onError,
}: {
  backups: BackupInfo[];
  onClose: () => void;
  onRestored: () => void;
  onError: (e: unknown) => void;
}) {
  const [backupId, setBackupId] = useState(backups[0]?.id ?? "");
  const [items, setItems] = useState<BackupItem[] | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [restored, setRestored] = useState<number | null>(null);

  useEffect(() => {
    if (!backupId) return;
    let alive = true;
    setItems(null);
    setChosen(new Set());
    setRestored(null);
    api.backupChanges(backupId).then(
      (list) => alive && setItems(list),
      (e) => alive && (onError(e), setItems([])),
    );
    return () => {
      alive = false;
    };
  }, [backupId, onError]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [busy, onClose]);

  function toggle(id: string) {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setChosen(next);
  }

  async function restore() {
    setBusy(true);
    try {
      setRestored(await api.restoreFromBackup(backupId, [...chosen]));
      onRestored();
      setItems(await api.backupChanges(backupId));
      setChosen(new Set());
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div className="modal dialog" role="dialog" aria-modal="true" aria-labelledby="restore-title">
        <div className="modal-close">
          <IconButton icon="x" label="Close" onClick={onClose} />
        </div>
        <h1 id="restore-title">Restore from a backup</h1>
        <label className="field-label">
          Backup
          <select value={backupId} onChange={(e) => setBackupId(e.target.value)} disabled={busy}>
            {backups.map((b) => (
              <option key={b.id} value={b.id}>
                {when(b.createdAt)}
              </option>
            ))}
          </select>
        </label>
        <p className="muted">
          Items deleted or changed since this backup. Restored items come back as they were then; their newer password
          stays in the password history.
        </p>

        {items === null ? (
          <p className="muted">
            <Spinner /> Reading the backup…
          </p>
        ) : items.length === 0 ? (
          <p>Nothing was deleted or changed since this backup.</p>
        ) : (
          <ul className="restore-list">
            {items.map((i) => (
              <li key={i.id}>
                <label>
                  <input type="checkbox" checked={chosen.has(i.id)} onChange={() => toggle(i.id)} disabled={busy} />
                  <CategoryIcon category={i.category} size={28} />
                  <span className="restore-text">
                    <strong>{i.title || "Untitled"}</strong>
                    <span className="muted small">{i.subtitle}</span>
                  </span>
                  <span className={i.change === "deleted" ? "tag warn" : "tag"}>{i.change === "deleted" ? "Deleted" : "Changed"}</span>
                </label>
              </li>
            ))}
          </ul>
        )}

        {restored !== null && (
          <p className="notice">
            Restored {restored} item{restored === 1 ? "" : "s"}.
          </p>
        )}
        <div className="dialog-actions">
          <button className="btn" onClick={onClose} disabled={busy}>
            Done
          </button>
          <button className="btn primary" onClick={restore} disabled={busy || chosen.size === 0}>
            {busy && <Spinner />} Restore {chosen.size || ""} selected
          </button>
        </div>
      </div>
    </div>
  );
}
