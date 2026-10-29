import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage, isLockedError, type Category, type ItemSummary, type ItemView, type LinkStatus } from "../api";
import { CATEGORIES, CategoryIcon } from "../categories";
import { ItemDetail } from "../components/ItemDetail";
import { ImportDialog } from "../components/ImportDialog";
import { ItemEditor } from "../components/ItemEditor";
import { NewItemPicker } from "../components/NewItemPicker";
import { Settings, TouchIdOffer } from "../components/Settings";
import { Watchtower, type IssueFilter } from "../components/Watchtower";
import { Avatar, Icon, IconButton, forgetSiteIcons, hostOf } from "../components/ui";
import { setThemePref, useTheme } from "../theme";
import { computer, computers, isPhone, keys, modKey } from "../platform";

/** Lock after this much time without mouse or keyboard input. */
const IDLE_LOCK_MS = 5 * 60_000;
/**
 * Changes from other computers are picked up as soon as they land in the vault
 * folder (the app watches it). This timer, and syncing when the window gains
 * focus, are a fallback, and also make the daily backup.
 */
const SYNC_EVERY_MS = 5 * 60_000;
/** On a phone, sync with the computer this often while the app is open. */
const PHONE_SYNC_EVERY_MS = 60_000;
/** On a phone, lock when the app was in the background this long. */
const PHONE_BACKGROUND_LOCK_MS = 30_000;

type Selection =
  | { kind: "none" }
  | { kind: "watchtower" }
  | { kind: "settings" }
  | { kind: "view"; id: string }
  | {
      kind: "edit";
      item: ItemView | null;
      category?: Category;
      website?: string;
    };

export function VaultScreen({ onLocked }: { onLocked: () => void }) {
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [importing, setImporting] = useState(false);
  const [query, setQuery] = useState("");
  // Set by Watchtower's "Show items": the list then shows only these, with the reason.
  const [issueFilter, setIssueFilter] = useState<IssueFilter | null>(null);
  // Sidebar category: the list then shows only items of that kind.
  const [categoryFilter, setCategoryFilter] = useState<Category | null>(null);
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [score, setScore] = useState<number | null>(null);
  const { theme } = useTheme();
  const [picking, setPicking] = useState(false);
  const [offerTouchId, setOfferTouchId] = useState(false);

  // After unlocking with the password on a computer with Touch ID or Windows Hello, offer it once.
  useEffect(() => {
    let dismissed = false;
    try {
      dismissed = localStorage.getItem("vaultix.touchIdOffered") === "1";
    } catch {}
    if (dismissed) return;
    api.touchIdStatus().then(
      (s) => setOfferTouchId(s.available && !s.enabled),
      () => {},
    );
  }, []);
  const closeOffer = useCallback(() => {
    setOfferTouchId(false);
    try {
      localStorage.setItem("vaultix.touchIdOffered", "1");
    } catch {}
  }, []);
  useEffect(() => {
    window.addEventListener("vaultix-touch-id-changed", closeOffer);
    return () => window.removeEventListener("vaultix-touch-id-changed", closeOffer);
  }, [closeOffer]);
  const [selection, setSelection] = useState<Selection>({ kind: "none" });
  const [lastSync, setLastSync] = useState<{
    at: Date;
    devices: number;
  } | null>(null);
  const [error, setError] = useState("");
  // Bumped after a sync so an open item re-reads its data.
  const [revision, setRevision] = useState(0);
  const searchRef = useRef<HTMLInputElement>(null);

  const handleError = useCallback(
    (e: unknown) => {
      if (isLockedError(e)) onLocked();
      else setError(errorMessage(e));
    },
    [onLocked],
  );

  // Icons say which sites are in the vault: don't keep them around once locked.
  useEffect(() => forgetSiteIcons, []);

  const lock = useCallback(async () => {
    await api.lock();
    onLocked();
  }, [onLocked]);

  const reload = useCallback(async () => {
    try {
      setItems(await api.listItems());
    } catch (e) {
      handleError(e);
    }
  }, [handleError]);

  const [link, setLink] = useState<LinkStatus | null>(null);
  const sync = useCallback(async () => {
    try {
      // The phone first fetches what changed on its computer, then re-reads the vault.
      if (isPhone) setLink(await api.syncWithComputer());
      const r = await api.syncVault();
      setLastSync({ at: new Date(), devices: r.devices });
      setItems(await api.listItems());
      setRevision((n) => n + 1);
    } catch (e) {
      handleError(e);
    }
  }, [handleError]);

  useEffect(() => {
    reload().then(sync);
    const timer = setInterval(sync, isPhone ? PHONE_SYNC_EVERY_MS : SYNC_EVERY_MS);
    window.addEventListener("focus", sync);
    const unsubscribe = api.onVaultChanged(sync);
    return () => {
      clearInterval(timer);
      window.removeEventListener("focus", sync);
      unsubscribe();
    };
  }, [reload, sync]);

  // Auto-lock when idle.
  useEffect(() => {
    let timer = setTimeout(lock, IDLE_LOCK_MS);
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(lock, IDLE_LOCK_MS);
    };
    const events = ["mousemove", "mousedown", "keydown", "wheel", "touchstart"] as const;
    events.forEach((ev) => window.addEventListener(ev, reset, { passive: true }));
    return () => {
      clearTimeout(timer);
      events.forEach((ev) => window.removeEventListener(ev, reset));
    };
  }, [lock]);

  // A phone locks once the app has been in the background for a while (the
  // timer may not run in the background, so the time is checked on return too).
  useEffect(() => {
    if (!isPhone) return;
    let hiddenAt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onVisibility = () => {
      if (document.hidden) {
        hiddenAt = Date.now();
        timer = setTimeout(lock, PHONE_BACKGROUND_LOCK_MS);
      } else {
        clearTimeout(timer);
        if (hiddenAt && Date.now() - hiddenAt >= PHONE_BACKGROUND_LOCK_MS) lock();
        else sync();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [lock, sync]);

  // ⌘F search, ⌘N new item, ⌘L lock (Ctrl on Windows and Linux).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!modKey(e)) return;
      if (e.key === "f") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "n") {
        e.preventDefault();
        setPicking(true);
      } else if (e.key === "l") {
        e.preventDefault();
        lock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock]);

  // On a phone, Android's back gesture returns from an item (or Settings) to the list.
  const open = selection.kind !== "none";
  const pushed = useRef(false);
  useEffect(() => {
    if (!isPhone || !open) return;
    if (!pushed.current) {
      history.pushState({ vaultixDetail: true }, "");
      pushed.current = true;
    }
    const onPop = () => {
      pushed.current = false;
      setSelection({ kind: "none" });
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [open]);
  // Closed from the UI (the back button, a delete): drop the history entry too.
  useEffect(() => {
    if (isPhone && !open && pushed.current) {
      pushed.current = false;
      if (history.state?.vaultixDetail) history.back();
    }
  }, [open]);

  // Pull down on the list to sync.
  const [syncing, setSyncing] = useState(false);
  const pull = useRef<number | null>(null);
  const [pulling, setPulling] = useState(false);
  const onTouchStart = (e: React.TouchEvent<HTMLElement>) => {
    pull.current = e.currentTarget.scrollTop <= 0 ? e.touches[0].clientY : null;
  };
  const onTouchMove = (e: React.TouchEvent) => {
    if (pull.current !== null) setPulling(e.touches[0].clientY - pull.current > 70);
  };
  const onTouchEnd = async () => {
    pull.current = null;
    if (!pulling) return;
    setPulling(false);
    setSyncing(true);
    await sync();
    setSyncing(false);
  };

  const issueDetail = useMemo(() => (issueFilter ? new Map(issueFilter.issues.map((i) => [i.itemId, i.detail])) : null), [issueFilter]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = issueDetail ? items.filter((i) => issueDetail.has(i.id)) : items;
    if (categoryFilter) list = list.filter((i) => i.category === categoryFilter);
    if (favoritesOnly) list = list.filter((i) => i.favorite);
    if (q) list = list.filter((i) => [i.title, i.username, i.url ?? "", i.subtitle].some((s) => s.toLowerCase().includes(q)));
    return [...list].sort((a, b) =>
      (a.title || "Untitled").localeCompare(b.title || "Untitled", undefined, {
        sensitivity: "base",
      }),
    );
  }, [items, query, issueDetail, categoryFilter, favoritesOnly]);

  // Watchtower score for the sidebar badge, refreshed when items change.
  const itemsKey = useMemo(() => items.map((i) => `${i.id}:${i.title}:${i.username}`).join(), [items]);
  useEffect(() => {
    let alive = true;
    api.watchtower().then(
      (r) => alive && setScore(r.score),
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [itemsKey, revision]);

  const categoryCounts = useMemo(() => {
    const counts = new Map<Category, number>();
    for (const i of items) counts.set(i.category, (counts.get(i.category) ?? 0) + 1);
    return counts;
  }, [items]);

  const favoriteCount = items.filter((i) => i.favorite).length;
  const listTitle = issueFilter
    ? issueFilter.title
    : favoritesOnly
      ? "Favorites"
      : categoryFilter
        ? CATEGORIES.find((c) => c.id === categoryFilter)!.plural
        : "All items";
  const showList = selection.kind !== "watchtower" && selection.kind !== "settings";

  /** Show a different set of items in the list column. */
  function showItems(filter: { category?: Category; favorites?: boolean }) {
    setIssueFilter(null);
    setCategoryFilter(filter.category ?? null);
    setFavoritesOnly(!!filter.favorites);
    if (!showList) setSelection({ kind: "none" });
  }

  const selectedId = selection.kind === "view" ? selection.id : selection.kind === "edit" ? (selection.item?.id ?? null) : null;

  function onListKey(e: React.KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const idx = filtered.findIndex((i) => i.id === selectedId);
    const next = filtered[Math.min(filtered.length - 1, Math.max(0, idx + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) setSelection({ kind: "view", id: next.id });
  }

  return (
    <div
      className={["vault", showList ? "" : "no-list", isPhone ? `phone ${open ? "pane-detail" : "pane-list"}` : ""]
        .filter(Boolean)
        .join(" ")}
    >
      <aside className="sidebar">
        <div className="sidebar-brand">
          <img src="/logo-small.svg" alt="" width={28} height={28} />
          <span className="nav-label">Vaultix</span>
          <IconButton
            icon={theme === "dark" ? "sun" : "moon"}
            label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            onClick={() => setThemePref(theme === "dark" ? "light" : "dark")}
          />
        </div>

        <div className="sidebar-top">
          <label className="search">
            <Icon name="search" size={15} />
            <input
              ref={searchRef}
              placeholder={`Search  ${keys.mod}F`}
              aria-label="Search items"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                if (!showList) setSelection({ kind: "none" });
              }}
              onKeyDown={(e) => {
                if (e.key === "Escape") setQuery("");
                else if (e.key === "Enter" && filtered[0]) setSelection({ kind: "view", id: filtered[0].id });
                else onListKey(e);
              }}
            />
          </label>
          <button className="btn primary new-item" onClick={() => setPicking(true)} title={`New item (${keys.mod}N)`}>
            <Icon name="plus" size={14} /> New item
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Vault">
          <button
            className={selection.kind === "watchtower" ? "nav-item selected" : "nav-item"}
            onClick={() => setSelection({ kind: "watchtower" })}
          >
            <Icon name="shield" />
            <span className="nav-label">Watchtower</span>
            {score !== null && <span className="score-badge">{score}</span>}
          </button>
          <button
            className={showList && !issueFilter && !categoryFilter && !favoritesOnly ? "nav-item selected" : "nav-item"}
            onClick={() => showItems({})}
          >
            <Icon name="items" />
            <span className="nav-label">All items</span>
            <span className="nav-count">{items.length}</span>
          </button>
          <button
            className={showList && !issueFilter && favoritesOnly ? "nav-item selected" : "nav-item"}
            onClick={() => showItems({ favorites: true })}
          >
            <Icon name="star" />
            <span className="nav-label">Favorites</span>
            <span className="nav-count">{favoriteCount}</span>
          </button>
        </nav>

        {categoryCounts.size > 0 && (
          <div className="sidebar-group">
            <h2>Categories</h2>
            {CATEGORIES.filter((c) => categoryCounts.get(c.id)).map((c) => (
              <button
                key={c.id}
                className={showList && !issueFilter && categoryFilter === c.id ? "nav-item selected" : "nav-item"}
                onClick={() => showItems({ category: c.id })}
              >
                <span className="chip" style={{ background: `var(--c-${c.id})` }} aria-hidden="true" />
                <span className="nav-label">{c.plural}</span>
                <span className="nav-count">{categoryCounts.get(c.id)}</span>
              </button>
            ))}
          </div>
        )}

        <div className="sidebar-bottom">
          <button className="sync-status" onClick={sync} title="Sync now">
            <span className={lastSync ? "sync-dot" : "sync-dot pending"} aria-hidden="true" />
            {lastSync
              ? `Synced ${syncedAgo(lastSync.at)} · ${lastSync.devices} ${lastSync.devices === 1 ? computer : computers}`
              : "Syncing…"}
          </button>
          <IconButton
            icon="gear"
            label="Settings"
            active={selection.kind === "settings"}
            onClick={() => setSelection({ kind: "settings" })}
          />
          <IconButton icon="lock" label={`Lock (${keys.mod}L)`} onClick={lock} />
        </div>
      </aside>

      {showList && (
        <section className="list-column" aria-label="Items" onTouchStart={onTouchStart} onTouchMove={onTouchMove} onTouchEnd={onTouchEnd}>
          {isPhone && (
            <>
              <div className="phone-bar">
                <img src="/logo-small.svg" alt="" width={28} height={28} />
                <label className="search">
                  <Icon name="search" size={15} />
                  <input
                    placeholder="Search"
                    aria-label="Search items"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    enterKeyHint="search"
                  />
                </label>
                <IconButton icon="plus" label="New item" onClick={() => setPicking(true)} />
              </div>
              <div className="phone-chips" role="tablist" aria-label="Show">
                <button role="tab" aria-selected={!issueFilter && !categoryFilter && !favoritesOnly} onClick={() => showItems({})}>
                  All {items.length}
                </button>
                {favoriteCount > 0 && (
                  <button role="tab" aria-selected={!issueFilter && favoritesOnly} onClick={() => showItems({ favorites: true })}>
                    Favorites
                  </button>
                )}
                {CATEGORIES.filter((c) => categoryCounts.get(c.id)).map((c) => (
                  <button
                    key={c.id}
                    role="tab"
                    aria-selected={!issueFilter && categoryFilter === c.id}
                    onClick={() => showItems({ category: c.id })}
                  >
                    {c.plural}
                  </button>
                ))}
              </div>
              <button
                className={`phone-sync${link?.lastError ? " failed" : ""}`}
                onClick={async () => {
                  setSyncing(true);
                  await sync();
                  setSyncing(false);
                }}
              >
                {syncing || pulling ? "Syncing…" : phoneSyncText(link)}
              </button>
            </>
          )}
          <div className="list-head">
            <h1>{listTitle}</h1>
            <span>Sorted by title</span>
          </div>

          {issueFilter && (
            <div className="filter-chip">
              <span>
                Showing {filtered.length} {filtered.length === 1 ? "item" : "items"} to fix
              </span>
              <IconButton icon="x" label="Show all items" onClick={() => setIssueFilter(null)} />
            </div>
          )}

          <ul className="item-list" role="listbox" aria-label={listTitle} tabIndex={0} onKeyDown={onListKey}>
            {filtered.map((item) => (
              <li
                key={item.id}
                role="option"
                aria-selected={item.id === selectedId}
                className={item.id === selectedId ? "selected" : ""}
                onClick={() => setSelection({ kind: "view", id: item.id })}
              >
                {item.category === "login" ? (
                  <Avatar title={item.title} url={item.url} size={36} />
                ) : (
                  <CategoryIcon category={item.category} size={36} />
                )}
                <div className="item-text">
                  <span className="item-title">
                    {item.title || "Untitled"}
                    {item.favorite && <Icon name="star" size={11} filled />}
                  </span>
                  <span className={issueDetail ? "item-sub issue" : "item-sub"}>
                    {issueDetail?.get(item.id) ?? ((item.category === "login" ? item.username || hostOf(item.url) : item.subtitle) || " ")}
                  </span>
                </div>
                {item.passkeyCount > 0 && (
                  <span className="badge" title="Has a passkey">
                    <Icon name="key" size={12} />
                  </span>
                )}
              </li>
            ))}
            {filtered.length === 0 && (
              <li className="empty-list">
                {items.length === 0 ? (
                  <>
                    No items yet. {isPhone ? "Tap + to add one" : `Press ${keys.mod}N to add one`}, or{" "}
                    <button className="link" onClick={() => setImporting(true)}>
                      import from 1Password or your browser
                    </button>
                    .
                  </>
                ) : issueFilter ? (
                  "Nothing left to fix here."
                ) : favoritesOnly && !query ? (
                  "No favorites yet. Star an item to keep it here."
                ) : (
                  "No matches."
                )}
              </li>
            )}
          </ul>
        </section>
      )}

      <main className="detail">
        {isPhone && open && (
          <div className="phone-back">
            <button className="btn plain" onClick={() => setSelection({ kind: "none" })}>
              ‹ {selection.kind === "settings" ? "Items" : selection.kind === "watchtower" ? "Items" : listTitle}
            </button>
          </div>
        )}
        {error && (
          <div className="banner error" role="alert">
            {error}
            <IconButton icon="x" label="Dismiss" onClick={() => setError("")} />
          </div>
        )}
        {offerTouchId && <TouchIdOffer onDone={closeOffer} />}
        {selection.kind === "settings" && <Settings onError={handleError} onVaultChanged={sync} />}
        {selection.kind === "none" && (
          <div className="placeholder">
            <img src="/logo.svg" alt="" width={56} height={56} />
            <p>
              {items.length} {items.length === 1 ? "item" : "items"}
            </p>
          </div>
        )}
        {selection.kind === "watchtower" && (
          <Watchtower
            revision={`${revision}:${items.map((i) => i.id).join()}`}
            onShowItems={(filter) => {
              setIssueFilter(filter);
              setCategoryFilter(null);
              setFavoritesOnly(false);
              setQuery("");
              const first = items.find((i) => filter.issues.some((x) => x.itemId === i.id));
              setSelection(first ? { kind: "view", id: first.id } : { kind: "none" });
            }}
            onError={handleError}
          />
        )}
        {selection.kind === "view" && (
          <ItemDetail
            key={selection.id}
            id={selection.id}
            revision={revision}
            onEdit={(item) => setSelection({ kind: "edit", item })}
            onChanged={reload}
            onDeleted={() => {
              setSelection({ kind: "none" });
              reload();
            }}
            onMissing={() => setSelection({ kind: "none" })}
            onError={handleError}
          />
        )}
        {selection.kind === "edit" && (
          <ItemEditor
            key={selection.item?.id ?? `new-${selection.category}-${selection.website ?? ""}`}
            item={selection.item}
            category={selection.category}
            website={selection.website}
            onSaved={(saved) => {
              setSelection({ kind: "view", id: saved.id });
              reload();
            }}
            onCancel={() => setSelection(selection.item ? { kind: "view", id: selection.item.id } : { kind: "none" })}
            onError={handleError}
          />
        )}
      </main>

      {isPhone && !open && (
        <nav className="phone-tabs" aria-label="Vault">
          <button onClick={() => setSelection({ kind: "watchtower" })}>
            <Icon name="shield" size={20} />
            <span>Watchtower</span>
          </button>
          <button onClick={() => setSelection({ kind: "settings" })}>
            <Icon name="gear" size={20} />
            <span>Settings</span>
          </button>
          <button onClick={lock}>
            <Icon name="lock" size={20} />
            <span>Lock</span>
          </button>
        </nav>
      )}

      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={sync} />}
      {picking && (
        <NewItemPicker
          onPick={({ category, website }) => {
            setPicking(false);
            setSelection({ kind: "edit", item: null, category, website });
          }}
          onClose={() => setPicking(false)}
        />
      )}
    </div>
  );
}

const LINK_ERRORS: Record<string, string> = {
  "link-unreachable": "Can't reach",
  "link-not-paired": "No longer paired with",
  "link-wrong-vault": "Another vault is on",
};

/** The phone's sync line: "Synced with Linus's MacBook Pro 2 min ago". */
function phoneSyncText(link: LinkStatus | null): string {
  if (!link) return "Syncing…";
  const name = link.computerName ?? "your computer";
  if (link.lastError)
    return `${LINK_ERRORS[link.lastError] ?? "Couldn't sync with"} ${name}${link.lastError === "link-unreachable" ? " · Tap to retry" : ""}`;
  return link.lastSync ? `Synced with ${name} ${syncedAgo(new Date(link.lastSync))}` : `Not synced with ${name} yet`;
}

/** "just now", "4 min ago", then the time. */
function syncedAgo(at: Date): string {
  const minutes = Math.floor((Date.now() - at.getTime()) / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  return `at ${at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}
