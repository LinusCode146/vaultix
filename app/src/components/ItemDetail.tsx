import { useEffect, useRef, useState } from "react";
import { api, errorMessage, type Category, type FieldValue, type FileRef, type ItemView, type PasswordChange, type TotpCode } from "../api";
import { CategoryIcon, categoryDef, fieldDef, formatSize, groupDigits, isExpired, mergeFields } from "../categories";
import { Avatar, CopyButton, CountdownRing, Icon, IconButton, StrengthIndicator, formatCode, hostOf } from "./ui";

interface Props {
  id: string;
  revision: number;
  onEdit: (item: ItemView) => void;
  /** Saved from here (the favorite star), so the list should refresh. */
  onChanged: () => void;
  onDeleted: () => void;
  onMissing: () => void;
  onError: (e: unknown) => void;
}

/** Read-only view of an item, with copy buttons. */
export function ItemDetail({ id, revision, onEdit, onChanged, onDeleted, onMissing, onError }: Props) {
  const [item, setItem] = useState<ItemView | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Callbacks are read through a ref so a parent re-render doesn't trigger a refetch.
  const callbacks = useRef({ onMissing, onError });
  callbacks.current = { onMissing, onError };
  useEffect(() => {
    api
      .getItem(id)
      .then(setItem)
      .catch((e) =>
        // Deleted on another Mac and picked up by sync.
        errorMessage(e).includes("item not found") ? callbacks.current.onMissing() : callbacks.current.onError(e),
      );
  }, [id, revision]);

  // ⌘E to edit.
  useEffect(() => {
    if (!item) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey && e.key === "e") {
        e.preventDefault();
        onEdit(item);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [item, onEdit]);

  /** Save the item as shown, with `changes`. */
  const saveWith = (item: ItemView, changes: { favorite?: boolean; password?: string }) =>
    api.saveItem({
      id: item.id,
      category: item.category,
      title: item.title,
      username: item.username,
      password: changes.password ?? item.password,
      urls: item.urls,
      notes: item.notes,
      totp: item.totpUri ?? "",
      passkeyIds: item.passkeys.map((p) => p.credentialId),
      fields: item.fields,
      files: item.files,
      tags: item.tags,
      favorite: changes.favorite ?? item.favorite,
    });

  async function toggleFavorite() {
    if (!item) return;
    // Show the new state right away; a second click before the save finishes then toggles back.
    setItem({ ...item, favorite: !item.favorite });
    try {
      await saveWith(item, { favorite: !item.favorite });
      onChanged();
    } catch (e) {
      setItem(item);
      onError(e);
    }
  }

  async function restorePassword(password: string) {
    if (!item) return;
    try {
      setItem(await saveWith(item, { password }));
      onChanged();
    } catch (e) {
      onError(e);
    }
  }

  if (!item) return null;
  const isLogin = item.category === "login";
  const sections = mergeFields(item.category, item.fields)
    .sections.map((s) => ({ ...s, fields: s.fields.filter((f) => f.value) }))
    .filter((s) => s.fields.length > 0);

  return (
    <article className="item-detail">
      <header className="detail-header">
        {isLogin ? <Avatar title={item.title} url={item.urls[0]} size={56} /> : <CategoryIcon category={item.category} size={56} />}
        <div className="detail-title">
          <h1>{item.title || "Untitled"}</h1>
          <span className="item-sub">
            {[isLogin && hostOf(item.urls[0]), categoryDef(item.category).name].filter(Boolean).join(" · ")}
          </span>
        </div>
        <button
          type="button"
          className={item.favorite ? "header-icon-btn on" : "header-icon-btn"}
          onClick={toggleFavorite}
          title={item.favorite ? "Remove from favorites" : "Add to favorites"}
          aria-label={item.favorite ? "Remove from favorites" : "Add to favorites"}
          aria-pressed={item.favorite}
        >
          <Icon name="star" filled={item.favorite} />
        </button>
        <button className="btn header-btn" onClick={() => onEdit(item)} title="Edit (⌘E)">
          Edit
        </button>
      </header>

      {isLogin && (
      <section className="card">
        {item.username && (
          <Row label="username" value={<span className="value">{item.username}</span>}>
            <CopyButton value={item.username} label="Copy username" />
          </Row>
        )}
        {item.password && (
          <Row
            label="password"
            value={
              <span className={`value mono${revealed ? "" : " masked"}`}>
                {revealed ? <ColoredPassword value={item.password} /> : "••••••••••••••"}
              </span>
            }
          >
            <StrengthIndicator strength={item.strength} />
            <IconButton
              icon={revealed ? "eyeOff" : "eye"}
              label={revealed ? "Hide password" : "Reveal password"}
              onClick={() => setRevealed((r) => !r)}
            />
            <CopyButton value={item.password} label="Copy password" />
          </Row>
        )}
        {item.totpUri && <TotpRow id={item.id} revision={revision} />}
        {!item.username && !item.password && !item.totpUri && <p className="muted pad">No login details.</p>}
      </section>
      )}

      {item.files.length > 0 && (
        <section className="card">
          {item.files.map((f) => (
            <FileRow key={f.id} itemId={item.id} file={f} onError={onError} />
          ))}
        </section>
      )}

      {sections.map((section, i) => (
        <section key={section.title ?? i} className="card">
          {section.title && <h2 className="card-title">{section.title}</h2>}
          {section.fields.map((f) => (
            <FieldRow key={f.id} category={item.category} field={f} />
          ))}
        </section>
      ))}

      {item.urls.length > 0 && (
        <section className="card">
          {item.urls.map((url, i) => (
            <WebsiteRow key={i} itemId={item.id} url={url} first={i === 0} canFill={!!item.password} onError={onError} />
          ))}
        </section>
      )}

      {item.passkeys.length > 0 && (
        <section className="card">
          {item.passkeys.map((p) => (
            <Row
              key={p.credentialId}
              lead={<Icon name="key" size={15} />}
              label="passkey"
              value={
                <span className="value">
                  {p.userName} on {p.rpId}
                </span>
              }
            >
              <span className="row-side">Added {new Date(p.createdAt).toLocaleDateString([], { dateStyle: "medium" })}</span>
            </Row>
          ))}
        </section>
      )}

      {item.passwordHistory.length > 0 && <PasswordHistory history={item.passwordHistory} onRestore={restorePassword} />}

      {item.notes && (
        <section className="card">
          <Row label={item.category === "secureNote" ? "note" : "notes"} value={<p className="value notes">{item.notes}</p>} />
        </section>
      )}

      <footer className="detail-footer">
        <span>
          Last edited {new Date(item.updatedAt).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}
        </span>
        {confirmDelete ? (
          <span className="confirm-inline">
            Delete "{item.title}"?
            <button className="btn danger" onClick={() => api.deleteItem(item.id).then(onDeleted, onError)}>
              Delete
            </button>
            <button className="btn" onClick={() => setConfirmDelete(false)}>
              Cancel
            </button>
          </span>
        ) : (
          <button className="btn subtle" onClick={() => setConfirmDelete(true)}>
            <Icon name="trash" size={14} /> Delete
          </button>
        )}
      </footer>
    </article>
  );
}

/** Label over value on the left, buttons (children) on the right. */
function Row({ label, value, lead, children }: { label: string; value: React.ReactNode; lead?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div className="row">
      {lead && (
        <span className="row-lead" aria-hidden="true">
          {lead}
        </span>
      )}
      <div className="row-main">
        <span className="row-label">{label}</span>
        {value}
      </div>
      {children}
    </div>
  );
}

function WebsiteRow({ itemId, url, first, canFill, onError }: { itemId: string; url: string; first: boolean; canFill: boolean; onError: (e: unknown) => void }) {
  const [note, setNote] = useState("");
  // Bare "example.com" or http(s); not ftp:, ssh: and the like.
  const openable = /^https?:\/\//i.test(url) || !/^[a-z][a-z0-9+.-]*:/i.test(url);
  async function openAndFill() {
    try {
      const { browser } = await api.openAndFill(itemId, url);
      setNote(
        browser
          ? `Opening in ${browser}…`
          : "Opened in your default browser. It signs in automatically if the Vaultix extension is installed there.",
      );
    } catch (e) {
      onError(e);
    }
  }
  return (
    <>
      <Row label={first ? "website" : ""} value={<span className="value url">{url}</span>}>
        {openable && canFill && (
          <button className="pill-btn" onClick={openAndFill} title="Open the website and sign in">
            <Icon name="external" size={13} /> Open & Fill
          </button>
        )}
        <CopyButton value={url} label="Copy URL" />
      </Row>
      {note && <p className="row-note">{note}</p>}
    </>
  );
}

function FieldRow({ category, field }: { category: Category; field: FieldValue }) {
  const [revealed, setRevealed] = useState(false);
  const grouped = fieldDef(category, field.id)?.grouped;
  const shown = grouped ? groupDigits(field.value) : field.value;

  if (field.kind === "concealed") {
    // Card numbers keep their last four digits visible, like on a receipt.
    const masked = grouped ? `•••• ${field.value.replace(/\s/g, "").slice(-4)}` : "••••••••";
    return (
      <Row label={field.label} value={<span className={`value mono${revealed ? "" : " masked"}`}>{revealed ? shown : masked}</span>}>
        <IconButton icon={revealed ? "eyeOff" : "eye"} label={revealed ? `Hide ${field.label}` : `Reveal ${field.label}`} onClick={() => setRevealed((r) => !r)} />
        <CopyButton value={field.value} label={`Copy ${field.label}`} />
      </Row>
    );
  }
  let display: React.ReactNode = shown;
  if (field.kind === "date") {
    const d = new Date(`${field.value}T00:00:00`);
    if (!Number.isNaN(d.getTime())) display = d.toLocaleDateString([], { dateStyle: "long" });
  }
  return (
    <Row label={field.label} value={<span className={field.kind === "multiline" ? "value notes" : "value"}>{display}</span>}>
      {field.kind === "monthYear" && isExpired(field.value) && <span className="tag warn">Expired</span>}
      <CopyButton value={field.value} label={`Copy ${field.label}`} />
    </Row>
  );
}

function FileRow({ itemId, file, onError }: { itemId: string; file: FileRef; onError: (e: unknown) => void }) {
  const [state, setState] = useState<"idle" | "saving" | "saved">("idle");
  async function saveCopy() {
    setState("saving");
    try {
      setState((await api.exportFile(itemId, file)) ? "saved" : "idle");
    } catch (e) {
      setState("idle");
      onError(e);
    }
  }
  return (
    <Row
      label="file"
      value={
        <span className="value file-name">
          {file.name} <span className="muted small">{formatSize(file.size)}</span>
        </span>
      }
    >
      {state === "saved" && <span className="row-side">Saved</span>}
      <button className="btn" onClick={saveCopy} disabled={state === "saving"}>
        Save a copy…
      </button>
    </Row>
  );
}

/** Earlier passwords, folded away until asked for. */
function PasswordHistory({ history, onRestore }: { history: PasswordChange[]; onRestore: (password: string) => void }) {
  const [open, setOpen] = useState(false);
  const [confirming, setConfirming] = useState<number | null>(null);
  return (
    <section className="card">
      <button className="card-toggle" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Icon name="refresh" size={14} />
        Previous passwords ({history.length})
        <span className={open ? "chevron open" : "chevron"} aria-hidden="true">
          ›
        </span>
      </button>
      {open &&
        history.map((h, i) => (
          <HistoryRow
            key={`${h.changedAt}-${i}`}
            change={h}
            confirming={confirming === i}
            onAsk={() => setConfirming(i)}
            onCancel={() => setConfirming(null)}
            onRestore={() => {
              setConfirming(null);
              onRestore(h.password);
            }}
          />
        ))}
    </section>
  );
}

function HistoryRow({
  change,
  confirming,
  onAsk,
  onCancel,
  onRestore,
}: {
  change: PasswordChange;
  confirming: boolean;
  onAsk: () => void;
  onCancel: () => void;
  onRestore: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const until = new Date(change.changedAt).toLocaleDateString([], { dateStyle: "medium" });
  return (
    <Row
      label={`used until ${until}`}
      value={
        <span className={`value mono${revealed ? "" : " masked"}`}>{revealed ? <ColoredPassword value={change.password} /> : "••••••••••••••"}</span>
      }
    >
      {confirming ? (
        <span className="confirm-inline">
          Make this the password again?
          <button className="btn primary" onClick={onRestore}>
            Restore
          </button>
          <button className="btn" onClick={onCancel}>
            Cancel
          </button>
        </span>
      ) : (
        <>
          <IconButton icon={revealed ? "eyeOff" : "eye"} label={revealed ? "Hide password" : "Reveal password"} onClick={() => setRevealed((r) => !r)} />
          <CopyButton value={change.password} label="Copy old password" />
          <button className="btn plain" onClick={onAsk} title="Make this the current password again">
            Restore
          </button>
        </>
      )}
    </Row>
  );
}

/** Digits and symbols in different colors, so revealed passwords are easier to read. */
function ColoredPassword({ value }: { value: string }) {
  return (
    <>
      {Array.from(value).map((ch, i) => (
        <span key={i} className={/\d/.test(ch) ? "pw-digit" : /[a-z]/i.test(ch) ? undefined : "pw-symbol"}>
          {ch}
        </span>
      ))}
    </>
  );
}

function TotpRow({ id, revision }: { id: string; revision: number }) {
  const [code, setCode] = useState<TotpCode | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = () => api.totpCode(id).then((c) => alive && setCode(c), () => {});
    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [id, revision]);
  if (!code) return null;
  return (
    <Row label="one-time password" value={<span className="value mono totp">{formatCode(code.code)}</span>}>
      <span className="countdown">
        <CountdownRing remaining={code.remaining} period={code.period} />
        {code.remaining} s
      </span>
      <CopyButton value={code.code} label="Copy one-time password" />
    </Row>
  );
}
