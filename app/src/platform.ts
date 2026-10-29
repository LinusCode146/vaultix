/**
 * What differs between macOS, Windows, Linux and Android in the UI: shortcut
 * keys and the names of things. In the browser demo, `?platform=windows`,
 * `?platform=linux` or `?platform=android` shows the other systems.
 */
export type Platform = "mac" | "windows" | "linux" | "android";

function detect(): Platform {
  const forced = new URLSearchParams(location.search).get("platform");
  if (forced === "mac" || forced === "windows" || forced === "linux" || forced === "android") return forced;
  const ua = navigator.userAgent;
  if (/Android/.test(ua)) return "android";
  if (/Windows/.test(ua)) return "windows";
  if (/Mac/.test(ua)) return "mac";
  return "linux";
}

export const platform = detect();
export const isMac = platform === "mac";
/** The phone app: one screen at a time, synced with a paired computer. */
export const isPhone = platform === "android";

/** The ⌘ key on a Mac, Ctrl elsewhere: for app shortcuts like ⌘F / Ctrl+F. */
export const modKey = (e: { metaKey: boolean; ctrlKey: boolean }) => (isMac ? e.metaKey : e.ctrlKey);

/** Shortcut labels: `keys.mod + "F"` reads "⌘F" or "Ctrl+F". */
export const keys = isMac
  ? { mod: "⌘", shift: "⇧", alt: "⌥", enter: "↵" }
  : { mod: "Ctrl+", shift: "Shift+", alt: "Alt+", enter: "Enter" };

/** "Mac" or "computer", as in "Set up this Mac" / "your other Macs". */
export const computer = isMac ? "Mac" : "computer";
export const computers = isMac ? "Macs" : "computers";

export const fileManager = { mac: "Finder", windows: "File Explorer", linux: "your file manager", android: "Files" }[platform];
export const trashName = { mac: "Trash", windows: "Recycle Bin", linux: "trash", android: "trash" }[platform];

/** The light/dark appearance setting's source: "macOS", "Windows", "your desktop". */
export const systemName = { mac: "macOS", windows: "Windows", linux: "your desktop", android: "Android" }[platform];

/** The biometric unlock this system has: Touch ID, Windows Hello, fingerprint or face (Android), or none (Linux). */
export const biometric = { mac: "Touch ID", windows: "Windows Hello", linux: null, android: "fingerprint" }[platform];

/** A synced folder people here are likely to have. */
export const syncedFolder = { mac: "iCloud Drive", windows: "OneDrive", linux: "Syncthing or Dropbox", android: "" }[platform];
