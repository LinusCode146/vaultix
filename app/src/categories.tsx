// The kinds of item Vaultix can store, and which fields each one has. The
// backend only stores labelled values; the templates here decide what the
// editor offers. Field ids are stored, so never rename one.
import type { Category, FieldKind, FieldValue } from "./api";

export interface FieldDef {
  id: string;
  label: string;
  kind: FieldKind;
  placeholder?: string;
  /** Show in groups of four (card numbers). */
  grouped?: boolean;
}

export interface SectionDef {
  title?: string;
  fields: FieldDef[];
}

export interface CategoryDef {
  id: Category;
  name: string;
  /** Sidebar label, e.g. "Logins". */
  plural: string;
  /** Extra words the "new item" search matches. */
  keywords: string;
  sections: SectionDef[];
}

export const CATEGORIES: CategoryDef[] = [
  { id: "login", name: "Login", plural: "Logins", keywords: "password website account sign in", sections: [] },
  { id: "secureNote", name: "Secure Note", plural: "Secure Notes", keywords: "text notes memo", sections: [] },
  {
    id: "creditCard",
    name: "Credit Card",
    plural: "Credit Cards",
    keywords: "debit card payment visa mastercard amex bank",
    sections: [
      {
        fields: [
          { id: "cardholder", label: "cardholder name", kind: "text", placeholder: "Name on card" },
          { id: "number", label: "number", kind: "concealed", placeholder: "1234 5678 9012 3456", grouped: true },
          { id: "expiry", label: "expiry date", kind: "monthYear", placeholder: "MM/YYYY" },
          { id: "cvv", label: "verification number", kind: "concealed", placeholder: "CVV" },
          { id: "pin", label: "PIN", kind: "concealed", placeholder: "PIN" },
        ],
      },
      {
        title: "Issuer",
        fields: [
          { id: "bank", label: "issuing bank", kind: "text", placeholder: "Bank name" },
          { id: "phone", label: "customer service", kind: "phone", placeholder: "Phone number" },
        ],
      },
    ],
  },
  {
    id: "identity",
    name: "Identity",
    plural: "Identities",
    keywords: "person name address contact profile",
    sections: [
      {
        title: "Identification",
        fields: [
          { id: "first_name", label: "first name", kind: "text", placeholder: "First name" },
          { id: "middle_name", label: "middle name", kind: "text", placeholder: "Middle name" },
          { id: "last_name", label: "last name", kind: "text", placeholder: "Last name" },
          { id: "birth_date", label: "birth date", kind: "date" },
        ],
      },
      {
        title: "Address",
        fields: [
          { id: "street", label: "street", kind: "text", placeholder: "Street and number" },
          { id: "city", label: "city", kind: "text", placeholder: "City" },
          { id: "zip", label: "postal code", kind: "text", placeholder: "Postal code" },
          { id: "state", label: "state", kind: "text", placeholder: "State or province" },
          { id: "country", label: "country", kind: "text", placeholder: "Country" },
        ],
      },
      {
        title: "Contact",
        fields: [
          { id: "email", label: "email", kind: "email", placeholder: "name@example.com" },
          { id: "phone", label: "phone", kind: "phone", placeholder: "Phone number" },
          { id: "website", label: "website", kind: "url", placeholder: "https://example.com" },
        ],
      },
      {
        title: "Work",
        fields: [
          { id: "company", label: "company", kind: "text", placeholder: "Company" },
          { id: "job_title", label: "job title", kind: "text", placeholder: "Job title" },
        ],
      },
    ],
  },
  {
    id: "apiCredential",
    name: "API Credentials",
    plural: "API Credentials",
    keywords: "api key token secret developer credential",
    sections: [
      {
        fields: [
          { id: "username", label: "username", kind: "text", placeholder: "Username or client ID" },
          { id: "credential", label: "credential", kind: "concealed", placeholder: "API key, token or secret" },
          { id: "type", label: "type", kind: "text", placeholder: "e.g. bearer token, API key" },
          { id: "hostname", label: "hostname", kind: "text", placeholder: "api.example.com" },
          { id: "valid_from", label: "valid from", kind: "date" },
          { id: "expires", label: "expires", kind: "date" },
        ],
      },
    ],
  },
  { id: "document", name: "Document", plural: "Documents", keywords: "file pdf scan attachment upload", sections: [] },
];

export const categoryDef = (id: Category) => CATEGORIES.find((c) => c.id === id) ?? CATEGORIES[0];

/**
 * The fields to edit: the template's, filled from the item, followed by any
 * stored fields the template doesn't know (so nothing is ever dropped).
 */
export function mergeFields(category: Category, stored: FieldValue[]): { sections: { title?: string; fields: FieldValue[] }[] } {
  const byId = new Map(stored.map((f) => [f.id, f]));
  const sections = categoryDef(category).sections.map((s) => ({
    title: s.title,
    fields: s.fields.map((d) => ({ id: d.id, label: d.label, kind: d.kind, value: byId.get(d.id)?.value ?? "" })),
  }));
  const known = new Set(sections.flatMap((s) => s.fields.map((f) => f.id)));
  const extra = stored.filter((f) => !known.has(f.id));
  if (extra.length) sections.push({ title: "Other", fields: extra });
  return { sections };
}

export function fieldDef(category: Category, id: string): FieldDef | undefined {
  for (const s of categoryDef(category).sections) {
    const f = s.fields.find((f) => f.id === id);
    if (f) return f;
  }
}

/** "4242424242424242" → "4242 4242 4242 4242". */
export const groupDigits = (v: string) => v.replace(/\s+/g, "").replace(/(.{4})(?=.)/g, "$1 ");

/** Accepts "7/27", "07/2027" or "072027"; returns "07/2027", or null if it isn't a month and year. */
export function normalizeMonthYear(input: string): string | null {
  const m = input.trim().match(/^(\d{1,2})\s*[/\-.]?\s*(\d{2}|\d{4})$/);
  if (!m) return null;
  const month = Number(m[1]);
  if (month < 1 || month > 12) return null;
  const year = m[2].length === 2 ? 2000 + Number(m[2]) : Number(m[2]);
  return `${String(month).padStart(2, "0")}/${year}`;
}

/** True for an "MM/YYYY" date in a month that has already ended. */
export function isExpired(monthYear: string): boolean {
  const m = monthYear.match(/^(\d{2})\/(\d{4})$/);
  if (!m) return false;
  const endOfMonth = new Date(Number(m[2]), Number(m[1]), 1);
  return endOfMonth.getTime() <= Date.now();
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Colored illustration for each category, in the spirit of 1Password's. */
export function CategoryIcon({ category, size = 32 }: { category: Category; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className="category-icon">
      {ICONS[category]}
    </svg>
  );
}

const ICONS: Record<Category, React.ReactNode> = {
  login: (
    <>
      <rect x="2" y="2" width="28" height="28" rx="6" fill="#1fa39a" />
      <rect x="5" y="5" width="22" height="22" rx="4" fill="#9ae6df" />
      <circle cx="16" cy="14" r="3" fill="#0d4f4a" />
      <rect x="14.6" y="15" width="2.8" height="6.5" rx="1.2" fill="#0d4f4a" />
    </>
  ),
  secureNote: (
    <>
      <rect x="5" y="3" width="22" height="26" rx="3" fill="#fde7a8" />
      <path d="M5 6a3 3 0 0 1 3-3h16a3 3 0 0 1 3 3v2H5Z" fill="#f5a524" />
      <path d="M8 13h18M8 17h18M8 21h18M8 25h18" stroke="#f0c56a" strokeWidth="1" />
      <path d="M10.5 8v21" stroke="#e5484d" strokeWidth="1" />
    </>
  ),
  creditCard: (
    <>
      <rect x="2" y="6" width="28" height="20" rx="3.5" fill="#4dabf7" />
      <path d="M2 9.5A3.5 3.5 0 0 1 5.5 6h21A3.5 3.5 0 0 1 30 9.5V11H2Z" fill="#1c2e4a" />
      <rect x="5" y="15" width="12" height="2" rx="1" fill="#d0ebff" />
      <rect x="5" y="19.5" width="7" height="2" rx="1" fill="#d0ebff" />
      <rect x="21" y="18" width="6" height="4.5" rx="1.2" fill="#d0ebff" />
    </>
  ),
  identity: (
    <>
      <rect x="2" y="6" width="28" height="20" rx="3.5" fill="#63c58a" />
      <path d="M2 9.5A3.5 3.5 0 0 1 5.5 6h21A3.5 3.5 0 0 1 30 9.5V10H2Z" fill="#3b9d63" />
      <rect x="5" y="12.5" width="10" height="10" rx="2" fill="#e6f7ec" />
      <circle cx="10" cy="16" r="2" fill="#1e5a36" />
      <path d="M6.8 22a3.2 3.2 0 0 1 6.4 0Z" fill="#1e5a36" />
      <path d="M18 14.5h8.5M18 18h8.5M18 21.5h6" stroke="#e6f7ec" strokeWidth="1.6" strokeLinecap="round" />
    </>
  ),
  apiCredential: (
    <>
      <rect x="2" y="4" width="28" height="24" rx="4" fill="#5ad8d0" />
      <path d="M2 8a4 4 0 0 1 4-4h20a4 4 0 0 1 4 4v3H2Z" fill="#127c75" />
      <path d="M16 4v7" stroke="#5ad8d0" strokeWidth="1.2" />
      <path d="m11.5 15.5-3.5 3.5 3.5 3.5M20.5 15.5l3.5 3.5-3.5 3.5M17.5 14.5l-3 9" fill="none" stroke="#0b4f4a" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </>
  ),
  document: (
    <>
      <rect x="6" y="2" width="20" height="28" rx="3.5" fill="#4dabf7" />
      <rect x="8.5" y="4.5" width="15" height="23" rx="2" fill="#d0ebff" />
      <path d="M21.5 6.5 13 19l-1 3.5 3-2 8.5-12.5Z" fill="#1864ab" />
      <path d="M10 25c2-2 3 1 5-.5s2.5-1 4 .2" fill="none" stroke="#1864ab" strokeWidth="1.2" strokeLinecap="round" />
    </>
  ),
};
