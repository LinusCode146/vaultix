import { useEffect, useState, type ReactNode } from "react";
import { api, type StrengthView } from "../api";

const PATHS: Record<string, ReactNode> = {
  copy: (
    <>
      <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
      <path d="M10.5 5.5v-2a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 3.5V9A1.5 1.5 0 0 0 4 10.5h1.5" />
    </>
  ),
  eye: (
    <>
      <path d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8s-2.4 4.5-6.5 4.5S1.5 8 1.5 8Z" />
      <circle cx="8" cy="8" r="2" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M6.2 3.8A6.6 6.6 0 0 1 8 3.5c4.1 0 6.5 4.5 6.5 4.5a11 11 0 0 1-1.7 2.2M10 10.6A3.6 3.6 0 0 1 8 12.5C3.9 12.5 1.5 8 1.5 8a11.3 11.3 0 0 1 2.7-3.1" />
      <path d="m2 2 12 12" />
    </>
  ),
  lock: (
    <>
      <rect x="3" y="7" width="10" height="7" rx="1.5" />
      <path d="M5 7V5a3 3 0 0 1 6 0v2" />
    </>
  ),
  plus: <path d="M8 3v10M3 8h10" />,
  search: (
    <>
      <circle cx="7" cy="7" r="4.5" />
      <path d="m10.5 10.5 3.5 3.5" />
    </>
  ),
  star: <path d="m8 1.8 1.9 3.9 4.3.6-3.1 3 .7 4.3L8 11.6l-3.8 2 .7-4.3-3.1-3 4.3-.6Z" />,
  trash: <path d="M2.5 4h11M6 4V2.5h4V4M4 4l.7 9.5h6.6L12 4" />,
  key: (
    <>
      <circle cx="5" cy="11" r="3" />
      <path d="m7.2 8.8 6.3-6.3M11 5l2 2M9.5 6.5l1.5 1.5" />
    </>
  ),
  refresh: <path d="M13.5 8A5.5 5.5 0 1 1 11.9 4M13.5 2v3.5H10" />,
  check: <path d="m3 8.5 3 3 7-7" />,
  dice: (
    <>
      <rect x="2" y="2" width="12" height="12" rx="2.5" />
      <circle cx="5.5" cy="5.5" r=".6" fill="currentColor" />
      <circle cx="10.5" cy="10.5" r=".6" fill="currentColor" />
      <circle cx="8" cy="8" r=".6" fill="currentColor" />
    </>
  ),
  x: <path d="m4 4 8 8M12 4l-8 8" />,
  tower: (
    <>
      <path d="M4.5 14.5V6h7v8.5M3.5 14.5h9M4.5 6 4 2.5h1.6v1.3h1.6V2.5h1.6v1.3h1.6V2.5H12L11.5 6" />
      <path d="M6.8 14.5v-3a1.2 1.2 0 0 1 2.4 0v3" />
    </>
  ),
  arrowRight: <path d="M3 8h10M9 4l4 4-4 4" />,
  list: <path d="M5.5 4h8M5.5 8h8M5.5 12h8M2.5 4h.01M2.5 8h.01M2.5 12h.01" />,
  // A toothed cog, so it can't be mistaken for a sun (the theme toggle).
  gear: (
    <>
      <path d="M6.9 1.5h2.2l.4 1.8 1.2.6 1.6-.9 1.6 1.6-.9 1.6.5 1.2 1.8.5v2.2l-1.8.4-.5 1.2.9 1.6-1.6 1.6-1.6-.9-1.2.5-.4 1.8H6.9l-.4-1.8-1.2-.5-1.6.9-1.6-1.6.9-1.6-.5-1.2-1.8-.4V6.9l1.8-.5.5-1.2-.9-1.6 1.6-1.6 1.6.9 1.2-.6Z" />
      <circle cx="8" cy="8" r="2.2" />
    </>
  ),
  sun: (
    <>
      <circle cx="8" cy="8" r="2.8" />
      <path d="M8 1.5v1.3M8 13.2v1.3M1.5 8h1.3M13.2 8h1.3M3.4 3.4l.9.9M11.7 11.7l.9.9M3.4 12.6l.9-.9M11.7 4.3l.9-.9" />
    </>
  ),
  moon: <path d="M13.6 9.6A5.8 5.8 0 0 1 6.4 2.4a5.8 5.8 0 1 0 7.2 7.2Z" />,
  shield: (
    <>
      <path d="M8 1.8 13 3.6v4c0 3-2.1 5.4-5 6.6-2.9-1.2-5-3.6-5-6.6v-4Z" />
      <path d="m5.8 8 1.6 1.6 3-3.2" />
    </>
  ),
  items: (
    <>
      <rect x="2.5" y="2.5" width="11" height="11" rx="2.5" />
      <path d="M5.5 6h5M5.5 8.5h5M5.5 11h3" />
    </>
  ),
  // Viewfinder corners around a line: "scan a code".
  scan: <path d="M2.5 5.5v-3h3M10.5 2.5h3v3M13.5 10.5v3h-3M5.5 13.5h-3v-3M4.5 8h7" />,
  external: <path d="M9.5 2.5h4v4M13.5 2.5 7.5 8.5M11.5 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3" />,
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 16, filled = false }: { name: IconName; size?: number; filled?: boolean }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}

/** Icon-only button with a tooltip and accessible label. */
export function IconButton({
  icon,
  label,
  onClick,
  active,
  filled,
}: {
  icon: IconName;
  label: string;
  onClick: () => void;
  active?: boolean;
  filled?: boolean;
}) {
  return (
    <button type="button" className={`icon-btn${active ? " active" : ""}`} title={label} aria-label={label} onClick={onClick}>
      <Icon name={icon} filled={filled} />
    </button>
  );
}

/** Copies through the backend (which clears the clipboard after 30 s) and briefly shows a check. */
export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1400);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <IconButton
      icon={copied ? "check" : "copy"}
      label={copied ? "Copied" : label}
      active={copied}
      onClick={() => api.copySecret(value).then(() => setCopied(true))}
    />
  );
}

const AVATAR_HUES = [222, 262, 160, 24, 340, 190, 290, 45];

/** "Green-ocean-0bdb32b03" → "Gr", "my bank" → "My". */
export function initials(title: string): string {
  const chars = Array.from(title.replace(/[^\p{L}\p{N}]/gu, ""));
  if (chars.length === 0) return "?";
  return chars[0].toUpperCase() + (chars[1] ?? "").toLowerCase();
}

/**
 * Website logo for a login when the site has one, otherwise two letters on a
 * stable color. Icons are fetched by the backend straight from the site and
 * cached encrypted; see icons.rs.
 */
export function Avatar({ title, url, size = 32 }: { title: string; url?: string | null; size?: number }) {
  const icon = useSiteIcon(url);
  const [small, setSmall] = useState(false);
  const [broken, setBroken] = useState(false);
  useEffect(() => setBroken(false), [icon]);

  if (icon && !broken) {
    return (
      <span className={`avatar site-icon${small ? " small" : ""}`} style={{ width: size, height: size }} aria-hidden="true">
        <img
          src={icon}
          alt=""
          draggable={false}
          // Big icons (touch icons) are full tiles; small favicons get some padding.
          onLoad={(e) => setSmall(e.currentTarget.naturalWidth > 0 && e.currentTarget.naturalWidth < 96)}
          onError={() => setBroken(true)}
        />
      </span>
    );
  }
  let hash = 0;
  for (const ch of title) hash = (hash * 31 + ch.charCodeAt(0)) | 0;
  const hue = AVATAR_HUES[Math.abs(hash) % AVATAR_HUES.length];
  return (
    <span
      className="avatar"
      style={{ width: size, height: size, fontSize: Math.round(size * 0.36), ["--hue" as string]: hue }}
      aria-hidden="true"
    >
      {initials(title)}
    </span>
  );
}

// One request per site per session, shared by every avatar showing it.
const iconRequests = new Map<string, Promise<string | null>>();

/** Drop remembered icons, e.g. on lock. */
export function forgetSiteIcons() {
  iconRequests.clear();
}

function useSiteIcon(url: string | null | undefined): string | null {
  const host = url ? hostOf(url) : "";
  const [icon, setIcon] = useState<{ host: string; uri: string | null } | null>(null);
  useEffect(() => {
    if (!host || !url) return;
    let request = iconRequests.get(host);
    if (!request) {
      request = api.siteIcon(url).catch(() => {
        iconRequests.delete(host); // try again next time (e.g. after unlocking)
        return null;
      });
      iconRequests.set(host, request);
    }
    let alive = true;
    request.then((uri) => alive && setIcon({ host, uri }));
    return () => {
      alive = false;
    };
  }, [host, url]);
  return icon?.host === host ? icon.uri : null;
}

/** Fingerprint glyph for Touch ID buttons. */
export function TouchIdIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <path d="M3 15v-2.5a9 9 0 0 1 18 0v1M6 18.5v-6a6 6 0 0 1 12 0v2.5c0 1.6-.3 3.2-.8 4.5M9 20.5v-8a3 3 0 0 1 6 0v2.5c0 2.5-.4 4.6-1.2 6.3M12 12.5v3.5c0 2-.3 3.6-.9 5" />
    </svg>
  );
}

/** Circular countdown for TOTP codes. */
export function CountdownRing({ remaining, period }: { remaining: number; period: number }) {
  const r = 7;
  const circumference = 2 * Math.PI * r;
  const fraction = remaining / period;
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" className={`ring${remaining <= 5 ? " ring-low" : ""}`} aria-label={`${remaining} seconds left`}>
      <circle cx="9" cy="9" r={r} className="ring-track" />
      <circle
        cx="9"
        cy="9"
        r={r}
        className="ring-fill"
        strokeDasharray={circumference}
        strokeDashoffset={circumference * (1 - fraction)}
        transform="rotate(-90 9 9)"
      />
    </svg>
  );
}

export function formatCode(code: string) {
  const mid = Math.ceil(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

export function hostOf(url: string | null | undefined): string {
  if (!url) return "";
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/** Ring and label like "◔ Weak", next to a password. */
export function StrengthIndicator({ strength }: { strength: StrengthView | null }) {
  if (!strength) return null;
  const r = 7;
  const circumference = 2 * Math.PI * r;
  const fraction = Math.max(0.06, strength.fraction);
  return (
    <span className="strength" data-label={strength.label} title={`Password strength: ${strength.text}`} style={{ ["--strength" as string]: `var(--s-${strength.label})` }}>
      <svg width="14" height="14" viewBox="0 0 18 18" aria-hidden="true">
        <circle cx="9" cy="9" r={r} className="ring-track" />
        <circle
          cx="9"
          cy="9"
          r={r}
          className="strength-fill"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - fraction)}
          transform="rotate(-90 9 9)"
        />
      </svg>
      <span className="strength-text">{strength.text}</span>
    </span>
  );
}

/** Horizontal meter for the master password on the setup screen. */
export function StrengthMeter({ strength }: { strength: StrengthView | null }) {
  return (
    <div className="strength-meter" style={{ ["--strength" as string]: strength ? `var(--s-${strength.label})` : "transparent" }}>
      <div className="strength-meter-track">
        <div className="strength-meter-fill" style={{ width: `${Math.round((strength?.fraction ?? 0) * 100)}%` }} />
      </div>
      <span className="strength-meter-text">{strength?.text ?? "\u00a0"}</span>
    </div>
  );
}
