import { useEffect, useState } from "react";
import { api, type StrengthLabel, type WatchtowerIssue, type WatchtowerReport } from "../api";
import { Icon, type IconName } from "./ui";
import { computer, isPhone } from "../platform";

export interface IssueFilter {
  title: string;
  issues: WatchtowerIssue[];
}

interface Props {
  /** Changes whenever the vault does, so the report is recomputed. */
  revision: unknown;
  onShowItems: (filter: IssueFilter) => void;
  onError: (e: unknown) => void;
}

const STRENGTH_TEXT: Record<StrengthLabel, string> = {
  terrible: "Terrible",
  weak: "Weak",
  fair: "Fair",
  good: "Good",
  veryGood: "Very good",
  excellent: "Excellent",
  fantastic: "Fantastic",
};

export function Watchtower({ revision, onShowItems, onError }: Props) {
  const [report, setReport] = useState<WatchtowerReport | null>(null);

  useEffect(() => {
    api.watchtower().then(setReport, onError);
  }, [revision]);

  if (!report) return null;

  const listsPending = !report.siteListsLoaded;
  const cards: CardProps[] = [
    {
      kind: "risk",
      icon: "key",
      title: "Reused passwords",
      issues: report.reused,
      text: "Don't use the same password on more than one site. If one site leaks it, every account using it is exposed.",
    },
    {
      kind: "risk",
      icon: "lock",
      title: "Weak passwords",
      issues: report.weak,
      text: "Weak passwords are easier to guess. Generate strong ones to keep these accounts safe.",
    },
    {
      kind: "risk",
      icon: "x",
      title: "Unsecured websites",
      issues: report.unsecured,
      text: "These logins are saved for http:// addresses, where passwords are sent unencrypted. Switch them to https:// if the site supports it.",
    },
    {
      kind: "tip",
      icon: "refresh",
      title: "Two-factor authentication",
      issues: report.twoFactorAvailable,
      pending: listsPending,
      text: "These sites offer one-time codes but you haven't set them up. Add the code to the item and Vaultix will fill it for you.",
    },
    {
      kind: "tip",
      icon: "key",
      title: "Passkeys available",
      issues: report.passkeysAvailable,
      pending: listsPending,
      text: "Passkeys can't be phished or reused. These sites support them; save one to the item to upgrade its security.",
    },
  ];

  return (
    <div className="watchtower">
      <header className="wt-head">
        <div className="wt-intro">
          <h1>
            <Icon name="shield" size={26} /> Watchtower
          </h1>
          <p>
            Security issues across your vault, checked on this {isPhone ? "phone" : computer}. The score gives an overall idea of how safe your logins are;
            fix the flagged items to raise it.
          </p>
        </div>
        <ScoreGauge score={report.score} label={report.scoreLabel} />
      </header>

      <section className="card wt-strength">
        <h2>Overall password strength</h2>
        <StrengthBar counts={report.strengthCounts} />
      </section>

      <div className="wt-grid">
        {cards.map((c) => (
          <IssueCard key={c.title} {...c} onShow={() => onShowItems({ title: c.title, issues: c.issues })} />
        ))}
      </div>
    </div>
  );
}

// ---------- Score gauge ----------

const GAUGE_SWEEP = 270;

function polar(cx: number, cy: number, r: number, degrees: number) {
  const a = (degrees * Math.PI) / 180;
  return { x: cx + r * Math.sin(a), y: cy - r * Math.cos(a) };
}

function arc(cx: number, cy: number, r: number, from: number, to: number) {
  const start = polar(cx, cy, r, from);
  const end = polar(cx, cy, r, to);
  const large = to - from > 180 ? 1 : 0;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${large} 1 ${end.x} ${end.y}`;
}

function ScoreGauge({ score, label }: { score: number | null; label: string }) {
  const from = -GAUGE_SWEEP / 2;
  const fraction = score === null ? 0 : Math.min(1, score / 1000);
  const marker = polar(100, 100, 60, from + GAUGE_SWEEP * fraction);
  const ticks = Array.from({ length: 28 }, (_, i) => from + (GAUGE_SWEEP * i) / 27);
  return (
    <div className="wt-gauge" role="img" aria-label={score === null ? "No score yet" : `Security score ${score} of 1000: ${label}`}>
      <svg viewBox="0 0 200 175" width="220">
        <defs>
          <linearGradient id="wt-gauge-gradient" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0" stopColor="#2f9a44" />
            <stop offset="0.5" stopColor="#38b2ac" />
            <stop offset="1" stopColor="#3b82f6" />
          </linearGradient>
        </defs>
        <path d={arc(100, 100, 82, from, -from)} className="wt-gauge-track" />
        {score !== null && fraction > 0 && (
          <path d={arc(100, 100, 82, from, from + GAUGE_SWEEP * fraction)} className="wt-gauge-value" stroke="url(#wt-gauge-gradient)" />
        )}
        {ticks.map((t, i) => {
          const a = polar(100, 100, 66, t);
          const b = polar(100, 100, i % 3 === 0 ? 72 : 70, t);
          return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="wt-gauge-tick" />;
        })}
        {score !== null && <circle cx={marker.x} cy={marker.y} r="4" className="wt-gauge-marker" />}
        <text x="100" y="108" textAnchor="middle" className="wt-gauge-score">
          {score ?? "—"}
        </text>
        <text x="100" y="132" textAnchor="middle" className="wt-gauge-label">
          {label.toUpperCase()}
        </text>
      </svg>
    </div>
  );
}

// ---------- Overall strength ----------

function StrengthBar({ counts }: { counts: WatchtowerReport["strengthCounts"] }) {
  const total = counts.reduce((n, c) => n + c.count, 0);
  if (total === 0) return <p className="muted">No passwords saved yet.</p>;
  // Strongest first, like reading a report card left to right.
  const ordered = [...counts].reverse().filter((c) => c.count > 0);
  return (
    <>
      <div className="wt-bar" role="img" aria-label={ordered.map((c) => `${c.count} ${STRENGTH_TEXT[c.label]}`).join(", ")}>
        {ordered.map((c) => (
          <span
            key={c.label}
            className="wt-bar-segment"
            title={`${c.count} ${STRENGTH_TEXT[c.label]}`}
            style={{ flexGrow: c.count, background: `var(--s-${c.label})` }}
          />
        ))}
      </div>
      <ul className="wt-legend">
        {ordered.map((c) => (
          <li key={c.label}>
            <span className="wt-dot" style={{ background: `var(--s-${c.label})` }} />
            {STRENGTH_TEXT[c.label]} <strong>{c.count}</strong>
          </li>
        ))}
      </ul>
    </>
  );
}

// ---------- Issue cards ----------

interface CardProps {
  kind: "risk" | "tip";
  icon: IconName;
  title: string;
  text: string;
  issues: WatchtowerIssue[];
  pending?: boolean;
}

function IssueCard({ kind, icon, title, text, issues, pending, onShow }: CardProps & { onShow: () => void }) {
  const count = issues.length;
  const clear = !pending && count === 0;
  return (
    <section className={`card wt-card ${kind}${clear ? " clear" : ""}`}>
      <div className="wt-card-body">
        <span className="wt-card-icon" aria-hidden="true">
          <Icon name={clear ? "check" : icon} size={40} />
        </span>
        <div className="wt-count">{pending ? "—" : count}</div>
        <h2>{title}</h2>
        <p>{pending ? "The list of supported sites hasn't been downloaded yet. It updates in the background when you're online." : text}</p>
      </div>
      <button className="wt-card-foot" onClick={onShow} disabled={pending || count === 0}>
        {clear ? "All good" : "Show items"}
        {!clear && <Icon name="arrowRight" />}
      </button>
    </section>
  );
}
