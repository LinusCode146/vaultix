// The square next to a login in the inline menu and the popup: the
// website's logo when the app has it cached, otherwise two letters
// (same as in the app).

/** "Green-ocean-0bdb32b03" → "Gr", "hessen.de" → "He". */
export function initials(title: string): string {
  const chars = Array.from(title.replace(/[^\p{L}\p{N}]/gu, ""));
  if (chars.length === 0) return "?";
  return chars[0].toUpperCase() + (chars[1] ?? "").toLowerCase();
}

export function avatar(title: string, icon?: string | null, text?: string): HTMLSpanElement {
  const box = document.createElement("span");
  box.className = "avatar";
  const letters = () => {
    box.className = "avatar";
    box.replaceChildren(text ?? initials(title));
  };
  // Only data: URIs from the app; never a URL the page could have influenced.
  if (icon?.startsWith("data:image/")) {
    box.className = "avatar logo";
    const img = document.createElement("img");
    img.alt = "";
    img.src = icon;
    // A page's Content-Security-Policy may block data: images in the inline menu.
    img.addEventListener("error", letters);
    box.append(img);
  } else {
    letters();
  }
  return box;
}
