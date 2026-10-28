import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { api, errorMessage, type ItemSummary, type QuickCopy, type Status, type TouchIdStatus } from "../api";
import { Avatar, Spinner, TouchIdIcon, hostOf } from "../components/ui";

const MAX_RESULTS = 8;

/** The ⌘⇧Space window: find a login, copy what's needed, get out of the way. */
export function QuickSearch() {
  const [status, setStatus] = useState<Status | null>(null);
  const [opened, setOpened] = useState(0);
  const refresh = useCallback(() => api.status().then(setStatus), []);

  useEffect(() => {
    refresh();
    const offs = [
      api.onQuickOpened(() => {
        refresh();
        setOpened((n) => n + 1);
      }),
      api.onUnlocked(refresh),
      api.onLocked(refresh),
    ];
    return () => offs.forEach((off) => off());
  }, [refresh]);

  // Esc closes; so does clicking another app (unless a Touch ID prompt took the focus).
  const busy = useRef(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && api.quickHide(false);
    const onBlur = () => !busy.current && api.quickHide(false);
    window.addEventListener("keydown", onKey);
    window.addEventListener("blur", onBlur);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("blur", onBlur);
    };
  }, []);

  if (!status) return null;
  return (
    <div className="quick">
      {status.stage === "setup" && <p className="quick-empty">Set up Vaultix in its main window first.</p>}
      {status.stage === "locked" && <QuickUnlock key={opened} busy={busy} onUnlocked={refresh} />}
      {status.stage === "unlocked" && <QuickResults key={opened} />}
    </div>
  );
}

function QuickUnlock({ busy, onUnlocked }: { busy: React.RefObject<boolean>; onUnlocked: () => void }) {
  const [touchId, setTouchId] = useState<TouchIdStatus | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const withTouchId = useCallback(async () => {
    busy.current = true;
    setWorking(true);
    setError("");
    try {
      await api.unlockTouchId();
      onUnlocked();
    } catch (e) {
      const code = errorMessage(e);
      if (code === "password-required") setError("Enter your master password. It's needed every two weeks.");
      else if (code !== "touch-id-cancelled" && code !== "touch-id-busy") setError("Touch ID didn't work. Use your master password.");
      input.current?.focus();
    } finally {
      busy.current = false;
      setWorking(false);
    }
  }, [busy, onUnlocked]);

  useEffect(() => {
    api.touchIdStatus().then((s) => {
      setTouchId(s);
      if (s.usable) withTouchId();
    }, () => {});
  }, [withTouchId]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password || working) return;
    setWorking(true);
    setError("");
    try {
      await api.unlock(password);
      onUnlocked();
    } catch (err) {
      const msg = errorMessage(err);
      setError(msg.charAt(0).toUpperCase() + msg.slice(1) + ".");
      setPassword("");
      setWorking(false);
    }
  }

  return (
    <form className="quick-unlock" onSubmit={submit}>
      <img src="/logo.svg" alt="" width={44} height={44} />
      <p>Vaultix is locked</p>
      <div className="quick-unlock-row">
        <input
          ref={input}
          type="password"
          className="big-input"
          placeholder="Master password"
          aria-label="Master password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {touchId?.usable && (
          <button type="button" className="btn touch-id" onClick={withTouchId} disabled={working} title="Unlock with Touch ID">
            {working ? <Spinner /> : <TouchIdIcon />}
          </button>
        )}
      </div>
      {error && <p className="error-text">{error}</p>}
    </form>
  );
}

function QuickResults() {
  const [items, setItems] = useState<ItemSummary[] | null>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    api.listItems().then(
      (all) => setItems(all.filter((i) => i.category === "login")),
      (e) => setError(errorMessage(e)),
    );
  }, []);

  const results = useMemo(() => {
    if (!items) return [];
    const q = query.trim().toLowerCase();
    if (!q) return [...items].sort((a, b) => Number(b.favorite) - Number(a.favorite)).slice(0, MAX_RESULTS);
    const score = (i: ItemSummary) => {
      const title = i.title.toLowerCase();
      const host = hostOf(i.url).toLowerCase();
      if (title.startsWith(q) || host.startsWith(q)) return 0;
      if (title.includes(q) || host.includes(q)) return 1;
      return [i.username, i.url ?? "", i.subtitle].some((s) => s.toLowerCase().includes(q)) ? 2 : -1;
    };
    return items
      .map((i) => ({ i, s: score(i) }))
      .filter(({ s }) => s >= 0)
      .sort((a, b) => a.s - b.s || Number(b.i.favorite) - Number(a.i.favorite))
      .slice(0, MAX_RESULTS)
      .map(({ i }) => i);
  }, [items, query]);

  useEffect(() => setActive(0), [query]);

  async function copy(item: ItemSummary | undefined, what: QuickCopy) {
    if (!item) return;
    setError("");
    try {
      await api.quickCopy(item.id, what);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  function onKey(e: React.KeyboardEvent) {
    const item = results[active];
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const step = e.key === "ArrowDown" ? 1 : -1;
      setActive((a) => (a + step + results.length) % Math.max(results.length, 1));
    } else if (e.key === "Enter" && item) {
      e.preventDefault();
      if (e.metaKey && item.url) {
        api.openAndFill(item.id, item.url).then(() => api.quickHide(false), (err) => setError(errorMessage(err)));
      } else {
        copy(item, e.shiftKey ? "username" : e.altKey ? "totp" : "password");
      }
    }
  }

  return (
    <div className="quick-results">
      <input
        className="quick-search"
        autoFocus
        placeholder="Search logins"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={onKey}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
      />
      <ul className="quick-list" role="listbox">
        {results.map((item, i) => (
          <li
            key={item.id}
            role="option"
            aria-selected={i === active}
            className={i === active ? "active" : undefined}
            onMouseMove={() => setActive(i)}
            onClick={() => copy(item, "password")}
          >
            <Avatar title={item.title} url={item.url} size={30} />
            <span className="quick-text">
              <strong>{item.title || "Untitled"}</strong>
              <span>{item.username || hostOf(item.url)}</span>
            </span>
            {i === active && <span className="quick-hint">↵ copy password</span>}
          </li>
        ))}
        {items && results.length === 0 && <li className="quick-empty">{items.length ? "No matches." : "No logins yet."}</li>}
      </ul>
      {error && <p className="error-text quick-error">{error}</p>}
      <footer className="quick-footer">
        <span>
          <kbd>↵</kbd> password
        </span>
        <span>
          <kbd>⇧↵</kbd> username
        </span>
        {results[active]?.hasTotp && (
          <span>
            <kbd>⌥↵</kbd> one-time code
          </span>
        )}
        <span>
          <kbd>⌘↵</kbd> open & fill
        </span>
        <span className="quick-footer-end">Clipboard clears after 30 s</span>
      </footer>
    </div>
  );
}
