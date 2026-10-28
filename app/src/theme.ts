import { useSyncExternalStore } from "react";

/** "system" follows the OS; "light" and "dark" stay put whatever it does. */
export type ThemePref = "system" | "light" | "dark";
export type Theme = "light" | "dark";

const KEY = "vaultix.theme";
const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");
const listeners = new Set<() => void>();

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark") return v;
  } catch {}
  return "system";
}

let pref = readPref();

function resolved(): Theme {
  return pref === "system" ? (darkQuery.matches ? "dark" : "light") : pref;
}

/** Set the colors (styles.css keys them off data-theme) and the window's title bar. */
function apply() {
  document.documentElement.dataset.theme = resolved();
  if ("__TAURI_INTERNALS__" in window) {
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().setTheme(pref === "system" ? null : pref))
      .catch(() => {});
  }
  listeners.forEach((l) => l());
}

/** Call once before the first render, so there's no flash of the wrong theme. */
export function initTheme() {
  darkQuery.addEventListener("change", () => pref === "system" && apply());
  apply();
}

export function setThemePref(next: ThemePref) {
  pref = next;
  try {
    if (next === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, next);
  } catch {}
  apply();
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** The chosen preference and the theme actually showing. */
export function useTheme(): { pref: ThemePref; theme: Theme } {
  const p = useSyncExternalStore(subscribe, () => pref);
  const theme = useSyncExternalStore(subscribe, resolved);
  return { pref: p, theme };
}
