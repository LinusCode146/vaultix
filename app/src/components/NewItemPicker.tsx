import { useEffect, useMemo, useState } from "react";
import type { Category } from "../api";
import { CATEGORIES, CategoryIcon } from "../categories";
import { Icon, IconButton } from "./ui";

export interface NewItemChoice {
  category: Category;
  /** Set when the user typed a website: becomes the new login's title and URL. */
  website?: string;
}

/** Looks like a site name ("github.com"), not a category search. */
const looksLikeWebsite = (q: string) => /^[^\s/]+\.[a-z]{2,}(\/\S*)?$/i.test(q) || /^https?:\/\//i.test(q);

/** "What would you like to add?": choose the kind of item to create. */
export function NewItemPicker({ onPick, onClose }: { onPick: (choice: NewItemChoice) => void; onClose: () => void }) {
  const [query, setQuery] = useState("");

  const q = query.trim().toLowerCase();
  const matches = useMemo(
    () => (q ? CATEGORIES.filter((c) => `${c.name} ${c.keywords}`.toLowerCase().includes(q)) : CATEGORIES),
    [q],
  );
  const website = looksLikeWebsite(query.trim()) ? query.trim() : null;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      }
    };
    // Capture, so the editor's or list's own Escape handling doesn't also run.
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  function pickFirst() {
    if (website) onPick({ category: "login", website });
    else if (matches[0]) onPick({ category: matches[0].id });
  }

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal picker" role="dialog" aria-modal="true" aria-labelledby="picker-title">
        <div className="modal-close">
          <IconButton icon="x" label="Close" onClick={onClose} />
        </div>
        <h1 id="picker-title">What would you like to add?</h1>
        <label className="picker-search">
          <Icon name="search" size={17} />
          <input
            autoFocus
            placeholder="Search for a website or category"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key !== "Enter") return;
              // Otherwise this Enter goes on to submit the editor that opens in its place.
              e.preventDefault();
              pickFirst();
            }}
            spellCheck={false}
            autoCapitalize="off"
          />
        </label>
        <div className="picker-grid">
          {website && (
            <button className="picker-tile default" onClick={() => onPick({ category: "login", website })}>
              <CategoryIcon category="login" size={38} />
              <span>
                Login for <strong>{website}</strong>
              </span>
            </button>
          )}
          {matches.map((c, i) => (
            // Highlight the tile Enter would pick.
            <button key={c.id} className={!website && i === 0 ? "picker-tile default" : "picker-tile"} onClick={() => onPick({ category: c.id })}>
              <CategoryIcon category={c.id} size={38} />
              <span>{c.name}</span>
            </button>
          ))}
        </div>
        {!website && matches.length === 0 && <p className="muted picker-empty">No category matches "{query}".</p>}
        <p className="picker-hint">Type a website, like github.com, to start a login for it · Esc to close</p>
      </div>
    </div>
  );
}
