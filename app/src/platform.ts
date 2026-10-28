/**
 * What differs between macOS, Windows and Linux in the UI: shortcut keys and
 * the names of things. In the browser demo, `?platform=windows` or
 * `?platform=linux` shows the other systems.
 */
export type Platform = "mac" | "windows" | "linux";

function detect(): Platform {
  const forced = new URLSearchParams(location.search).get("platform");
  if (forced === "mac" || forced === "windows" || forced === "linux") return forced;
  const ua = navigator.userAgent;
  if (/Windows/.test(ua)) return "windows";
  if (/Mac/.test(ua)) return "mac";
  return "linux";
}

export const platform = detect();
export const isMac = platform === "mac";

/** The ⌘ key on a Mac, Ctrl elsewhere: for app shortcuts like ⌘F / Ctrl+F. */
export const modKey = (e: { metaKey: boolean; ctrlKey: boolean }) => (isMac ? e.metaKey : e.ctrlKey);

/** Shortcut labels: `keys.mod + "F"` reads "⌘F" or "Ctrl+F". */
export const keys = isMac
  ? { mod: "⌘", shift: "⇧", alt: "⌥", enter: "↵" }
  : { mod: "Ctrl+", shift: "Shift+", alt: "Alt+", enter: "Enter" };

/** "Mac" or "computer", as in "Set up this Mac" / "your other Macs". */
export const computer = isMac ? "Mac" : "computer";
export const computers = isMac ? "Macs" : "computers";

export const fileManager = { mac: "Finder", windows: "File Explorer", linux: "your file manager" }[platform];
export const trashName = { mac: "Trash", windows: "Recycle Bin", linux: "trash" }[platform];

/** The light/dark appearance setting's source: "macOS", "Windows", "your desktop". */
export const systemName = { mac: "macOS", windows: "Windows", linux: "your desktop" }[platform];

/** The biometric unlock this system has: Touch ID, Windows Hello, or none (Linux). */
export const biometric = { mac: "Touch ID", windows: "Windows Hello", linux: null }[platform];

/** A synced folder people here are likely to have. */
export const syncedFolder = { mac: "iCloud Drive", windows: "OneDrive", linux: "Syncthing or Dropbox" }[platform];
