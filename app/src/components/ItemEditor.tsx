import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, errorMessage, type Category, type FieldValue, type FileRef, type ItemView, type PasswordOptions, type StrengthView, type TotpCode } from "../api";
import { CategoryIcon, categoryDef, fieldDef, formatSize, groupDigits, mergeFields, normalizeMonthYear } from "../categories";
import { Avatar, Icon, IconButton, Spinner, StrengthIndicator, formatCode, hostOf } from "./ui";
import { computers, keys, modKey } from "../platform";

interface Props {
  /** `null` for a new item. */
  item: ItemView | null;
  /** For a new item: what kind, and the website if one was typed in the picker. */
  category?: Category;
  website?: string;
  onSaved: (item: ItemView) => void;
  onCancel: () => void;
  onError: (e: unknown) => void;
}

const QR_ERRORS: Record<string, string> = {
  "qr-none": "No QR code found. Open the site's two-factor setup page so the code is visible, then scan again.",
  "qr-permission":
    "To scan your screen, Vaultix needs Screen Recording permission: System Settings → Privacy & Security → Screen & System Audio Recording. Or take a screenshot and use From image….",
  "qr-not-totp": "That QR code isn't a two-factor setup code.",
  "qr-migration": "That's a Google Authenticator export code. Scan the website's own setup QR code instead.",
  "qr-screen-unavailable": "This desktop doesn't let apps read the screen. Take a screenshot and use From image… instead.",
  "qr-failed": "Couldn't read that. Try a screenshot with From image….",
};

export function ItemEditor({ item, category: newCategory = "login", website, onSaved, onCancel, onError }: Props) {
  const category = item?.category ?? newCategory;
  const isLogin = category === "login";
  const [title, setTitle] = useState(item?.title ?? (website ? hostOf(website) : ""));
  const [username, setUsername] = useState(item?.username ?? "");
  const [password, setPassword] = useState(item?.password ?? "");
  const [urls, setUrls] = useState<string[]>(item?.urls.length ? item.urls : [website ? (website.includes("://") ? website : `https://${website}`) : ""]);
  const [sections, setSections] = useState(() => mergeFields(category, item?.fields ?? []).sections);
  const [files, setFiles] = useState<FileRef[]>(item?.files ?? []);
  const [attaching, setAttaching] = useState(false);
  const [totp, setTotp] = useState(item?.totpUri ?? "");
  const [notes, setNotes] = useState(item?.notes ?? "");
  const [favorite, setFavorite] = useState(item?.favorite ?? false);
  const [passkeyIds, setPasskeyIds] = useState(item?.passkeys.map((p) => p.credentialId) ?? []);
  const [showPassword, setShowPassword] = useState(item === null);
  const [showGenerator, setShowGenerator] = useState(false);
  const [totpState, setTotpState] = useState<{ code?: TotpCode; error?: string }>({});
  const [scanning, setScanning] = useState(false);
  const [qrError, setQrError] = useState("");

  /** Fill the one-time password from a QR code: on screen, in a file, or a pasted or dropped image. */
  async function scanQr(from: "screen" | "file" | Blob) {
    setScanning(true);
    setQrError("");
    try {
      const uri = from === "screen" ? await api.scanTotpQr() : await api.scanTotpQrImage(from === "file" ? undefined : from);
      if (uri) setTotp(uri);
    } catch (e) {
      const code = errorMessage(e);
      setQrError(QR_ERRORS[code] ?? `Couldn't read the QR code (${code}).`);
    } finally {
      setScanning(false);
    }
  }
  const [strength, setStrength] = useState<StrengthView | null>(item?.strength ?? null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const formRef = useRef<HTMLFormElement>(null);

  // Validate TOTP input as the user pastes or types it.
  useEffect(() => {
    if (!totp.trim()) {
      setTotpState({});
      return;
    }
    const t = setTimeout(() => {
      api.checkTotp(totp).then(
        (code) => setTotpState({ code }),
        (e) => setTotpState({ error: errorMessage(e).replace(/^invalid TOTP configuration: /, "") }),
      );
    }, 250);
    return () => clearTimeout(t);
  }, [totp]);

  // Re-rate the password as it's typed (judged against this item's username, title and sites).
  useEffect(() => {
    if (!password) {
      setStrength(null);
      return;
    }
    const t = setTimeout(() => {
      api.passwordStrength(password, { username, title, urls: urls.filter(Boolean) }).then(setStrength, () => {});
    }, 150);
    return () => clearTimeout(t);
  }, [password, username, title, urls]);

  // ⌘S (Ctrl+S) saves, Esc cancels.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (modKey(e) && e.key === "s") {
        e.preventDefault();
        formRef.current?.requestSubmit();
      } else if (e.key === "Escape" && !showGenerator) {
        onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel, showGenerator]);

  function setField(id: string, value: string) {
    setSections((ss) => ss.map((s) => ({ ...s, fields: s.fields.map((f) => (f.id === id ? { ...f, value } : f)) })));
  }

  async function chooseFile() {
    setAttaching(true);
    try {
      const file = await api.attachFile();
      if (file) {
        // A document holds one file: choosing another replaces it.
        setFiles([file]);
        if (!title.trim()) setTitle(file.name.replace(/\.[^.]+$/, ""));
      }
    } catch (err) {
      if (errorMessage(err) === "locked") onError(err);
      else setError(errorMessage(err));
    } finally {
      setAttaching(false);
    }
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    if (saving) return;
    const fields: FieldValue[] = [];
    for (const f of sections.flatMap((s) => s.fields)) {
      let value = f.value.trim() ? f.value : "";
      if (value && f.kind === "monthYear") {
        const normalized = normalizeMonthYear(value);
        if (!normalized) {
          setError(`Enter the ${f.label} as MM/YYYY.`);
          return;
        }
        value = normalized;
      }
      if (value && fieldDef(category, f.id)?.grouped) value = value.replace(/\s+/g, "");
      if (value) fields.push({ ...f, value });
    }
    if (category === "document" && files.length === 0) {
      setError("Choose a file to store.");
      return;
    }
    // Check again here: ⌘S can arrive before the debounced live check has run.
    if (totp.trim()) {
      try {
        await api.checkTotp(totp);
      } catch (err) {
        setTotpState({ error: errorMessage(err).replace(/^invalid TOTP configuration: /, "") });
        setError("Fix the one-time password setup or clear it.");
        return;
      }
    }
    const cleanUrls = urls.map((u) => u.trim()).filter(Boolean);
    const finalTitle = isLogin
      ? title.trim() || hostOf(cleanUrls[0]) || username.trim()
      : title.trim() || files[0]?.name || categoryDef(category).name;
    if (!finalTitle) {
      setError("Give the item a title.");
      return;
    }
    setSaving(true);
    setError("");
    try {
      const saved = await api.saveItem({
        id: item?.id ?? null,
        category,
        title: finalTitle,
        username: isLogin ? username : "",
        password: isLogin ? password : "",
        urls: isLogin ? cleanUrls : [],
        notes,
        totp: isLogin ? totp : "",
        passkeyIds,
        fields,
        files,
        tags: item?.tags ?? [],
        favorite,
      });
      onSaved(saved);
    } catch (err) {
      if (errorMessage(err) === "locked") onError(err);
      else setError(errorMessage(err));
      setSaving(false);
    }
  }

  const passkeys = item?.passkeys.filter((p) => passkeyIds.includes(p.credentialId)) ?? [];

  return (
    <form ref={formRef} className="item-detail editor" onSubmit={save}>
      <header className="detail-header">
        {isLogin ? <Avatar title={title || "?"} url={item?.urls[0]} size={48} /> : <CategoryIcon category={category} size={48} />}
        <input
          className="title-input"
          placeholder={isLogin ? "Title" : categoryDef(category).name}
          aria-label="Title"
          autoFocus={item === null}
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
        <IconButton
          icon="star"
          filled={favorite}
          active={favorite}
          label={favorite ? "Remove from favorites" : "Add to favorites"}
          onClick={() => setFavorite((f) => !f)}
        />
      </header>

      {isLogin && (
      <>
      <section className="card">
        <EditRow label="username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username or email" spellCheck={false} autoCapitalize="off" />
        </EditRow>
        <EditRow label="password">
          <input
            className="mono"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            spellCheck={false}
            autoComplete="off"
          />
          <StrengthIndicator strength={password ? strength : null} />
          <IconButton icon={showPassword ? "eyeOff" : "eye"} label={showPassword ? "Hide" : "Show"} onClick={() => setShowPassword((s) => !s)} />
          <IconButton icon="dice" label="Generate password" active={showGenerator} onClick={() => setShowGenerator((s) => !s)} />
        </EditRow>
        {showGenerator && (
          <Generator
            onUse={(pw) => {
              setPassword(pw);
              setShowPassword(true);
              setShowGenerator(false);
            }}
            onClose={() => setShowGenerator(false)}
          />
        )}
        <EditRow label="one-time password">
          <input
            className="mono"
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            onPaste={(e) => {
              const image = [...e.clipboardData.files].find((f) => f.type.startsWith("image/"));
              if (image) {
                e.preventDefault();
                scanQr(image);
              }
            }}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              const image = [...e.dataTransfer.files].find((f) => f.type.startsWith("image/"));
              if (image) {
                e.preventDefault();
                scanQr(image);
              }
            }}
            placeholder="Paste an otpauth:// link, setup key or QR screenshot"
            spellCheck={false}
            aria-invalid={!!totpState.error}
          />
          <button type="button" className="pill-btn" onClick={() => scanQr("screen")} disabled={scanning} title="Find the site's two-factor QR code on your screen">
            {scanning ? <Spinner /> : <Icon name="scan" size={13} />} Scan QR code
          </button>
          <button type="button" className="pill-btn subtle" onClick={() => scanQr("file")} disabled={scanning} title="Read the QR code from a screenshot">
            From image…
          </button>
        </EditRow>
        {qrError && <p className="row-note error-text">{qrError}</p>}
        {totpState.code && <p className="row-note">Current code: <span className="mono">{formatCode(totpState.code.code)}</span></p>}
        {totpState.error && <p className="row-note error-text">{totpState.error}</p>}
      </section>

      <section className="card">
        {urls.map((url, i) => (
          <EditRow key={i} label={i === 0 ? "website" : ""}>
            <input
              value={url}
              onChange={(e) => setUrls(urls.map((u, j) => (j === i ? e.target.value : u)))}
              placeholder="https://example.com"
              spellCheck={false}
              autoCapitalize="off"
            />
            {urls.length > 1 && <IconButton icon="x" label="Remove website" onClick={() => setUrls(urls.filter((_, j) => j !== i))} />}
          </EditRow>
        ))}
        <button type="button" className="link add-row" onClick={() => setUrls([...urls, ""])}>
          <Icon name="plus" size={12} /> Add website
        </button>
      </section>

      {passkeys.length > 0 && (
        <section className="card">
          {passkeys.map((p) => (
            <EditRow key={p.credentialId} label="passkey">
              <span className="value">
                <Icon name="key" size={13} /> {p.userName} on {p.rpId}
              </span>
              <IconButton
                icon="trash"
                label="Remove passkey"
                onClick={() => setPasskeyIds(passkeyIds.filter((id) => id !== p.credentialId))}
              />
            </EditRow>
          ))}
          {item && passkeyIds.length < item.passkeys.length && (
            <p className="row-note error-text">Removed passkeys stop working on that website once you save.</p>
          )}
        </section>
      )}
      </>
      )}

      {category === "document" && (
        <section className="card">
          <EditRow label="file">
            {files[0] ? (
              <span className="value file-name">
                {files[0].name} <span className="muted small">{formatSize(files[0].size)}</span>
              </span>
            ) : (
              <span className="value muted">No file chosen</span>
            )}
            <button type="button" className="btn" onClick={chooseFile} disabled={attaching}>
              {attaching ? <Spinner /> : null} {files[0] ? "Replace…" : "Choose file…"}
            </button>
          </EditRow>
          <p className="row-note">Stored encrypted in your vault folder, and synced to your other {computers}. Up to 100 MB.</p>
        </section>
      )}

      {sections.map((section, i) => (
        <section key={section.title ?? i} className="card">
          {section.title && <h2 className="card-title">{section.title}</h2>}
          {section.fields.map((f) => (
            <FieldInput key={f.id} category={category} field={f} onChange={(v) => setField(f.id, v)} />
          ))}
        </section>
      ))}

      <section className="card">
        <EditRow label={category === "secureNote" ? "note" : "notes"}>
          <textarea
            rows={category === "secureNote" ? 14 : 4}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder={category === "secureNote" ? "Write your note" : "Notes"}
          />
        </EditRow>
      </section>

      {error && <p className="error-text">{error}</p>}
      <footer className="detail-footer">
        <span className="muted small">{keys.mod}S to save · Esc to cancel</span>
        <span className="row-end">
          <button type="button" className="btn" onClick={onCancel} disabled={saving}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={saving}>
            {saving ? <Spinner /> : null} Save
          </button>
        </span>
      </footer>
    </form>
  );
}

function FieldInput({ category, field, onChange }: { category: Category; field: FieldValue; onChange: (value: string) => void }) {
  const def = fieldDef(category, field.id);
  const [show, setShow] = useState(false);
  const common = {
    value: def?.grouped && show ? groupDigits(field.value) : field.value,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange(e.target.value),
    placeholder: def?.placeholder ?? "",
    spellCheck: false,
    autoCapitalize: "off" as const,
    autoComplete: "off",
  };
  return (
    <EditRow label={field.label}>
      {field.kind === "multiline" ? (
        <textarea rows={3} {...common} />
      ) : field.kind === "concealed" ? (
        <>
          <input className="mono" type={show ? "text" : "password"} {...common} />
          <IconButton icon={show ? "eyeOff" : "eye"} label={show ? "Hide" : "Show"} onClick={() => setShow((s) => !s)} />
        </>
      ) : field.kind === "date" ? (
        <input type="date" {...common} />
      ) : (
        <input
          type={field.kind === "email" ? "email" : field.kind === "phone" ? "tel" : "text"}
          inputMode={field.kind === "monthYear" ? "numeric" : undefined}
          {...common}
        />
      )}
    </EditRow>
  );
}

function EditRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="row edit-row">
      <span className="row-label">{label}</span>
      <div className="row-value">{children}</div>
    </label>
  );
}

const DEFAULT_OPTIONS: PasswordOptions = { length: 20, uppercase: true, digits: true, symbols: true, avoid_ambiguous: true };

function Generator({ onUse, onClose }: { onUse: (password: string) => void; onClose: () => void }) {
  const [options, setOptions] = useState(DEFAULT_OPTIONS);
  const [value, setValue] = useState("");

  useEffect(() => {
    api.generatePassword(options).then(setValue);
  }, [options]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const toggle = (key: "uppercase" | "digits" | "symbols") => setOptions({ ...options, [key]: !options[key] });

  return (
    <div className="generator">
      <div className="generator-value mono">{value || " "}</div>
      <div className="generator-controls">
        <label className="slider">
          Length <strong>{options.length}</strong>
          <input
            type="range"
            min={8}
            max={64}
            value={options.length}
            onChange={(e) => setOptions({ ...options, length: Number(e.target.value) })}
          />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={options.uppercase} onChange={() => toggle("uppercase")} /> A–Z
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={options.digits} onChange={() => toggle("digits")} /> 0–9
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={options.symbols} onChange={() => toggle("symbols")} /> !@#
        </label>
      </div>
      <div className="row-end">
        <IconButton icon="refresh" label="Generate another" onClick={() => setOptions({ ...options })} />
        <button type="button" className="btn primary" onClick={() => onUse(value)} disabled={!value}>
          Use password
        </button>
      </div>
    </div>
  );
}
