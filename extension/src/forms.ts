// Finding login fields on arbitrary web pages. Heuristics, deliberately
// conservative: offering logins on a newsletter field is worse than missing a
// strange login form (the toolbar popup still works there).

export type FieldKind = "username" | "password" | "new-password" | "totp";

export interface LoginGroup {
  form: HTMLFormElement | null;
  username?: HTMLInputElement;
  password?: HTMLInputElement;
  newPassword?: HTMLInputElement;
  totp?: HTMLInputElement;
}

const TEXT_TYPES = new Set(["", "text", "email", "tel", "password", "number"]);
const OTP_HINT = /(^|[^a-z])(otp|totp|2fa|mfa|one.?time|verification.?code|security.?code|auth(entication)?.?code|token)([^a-z]|$)/i;
const USERNAME_HINT = /user|e-?mail|login|account|identifier|phone|handle/i;
const NOT_USERNAME = /search|query|filter|coupon|promo|captcha|zip|postal|city|address|first.?name|last.?name/i;
const NEW_PASSWORD_HINT = /new|confirm|repeat|retype|again|signup|sign.?up|register|create/i;
const CONFIRM_HINT = /confirm|repeat|retype|again|verify|wiederhol|bevestig|herhaal/i;

function hints(input: HTMLInputElement): string {
  return [input.name, input.id, input.placeholder, input.getAttribute("aria-label") ?? "", input.className]
    .join(" ")
    .slice(0, 500);
}

export function isVisible(el: HTMLElement): boolean {
  if (!el.isConnected || el.getClientRects().length === 0) return false;
  const style = getComputedStyle(el);
  if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0) return false;
  const rect = el.getBoundingClientRect();
  return rect.width > 2 && rect.height > 2;
}

export function classify(input: HTMLInputElement): FieldKind | null {
  if (!TEXT_TYPES.has(input.type) || input.disabled || input.readOnly || !isVisible(input)) return null;
  const autocomplete = (input.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/);
  if (autocomplete.includes("one-time-code")) return "totp";
  if (autocomplete.includes("new-password")) return "new-password";
  if (autocomplete.includes("current-password")) return "password";

  const h = hints(input);
  if (input.type === "password") return NEW_PASSWORD_HINT.test(h) ? "new-password" : "password";
  if (autocomplete.includes("username")) return "username";

  const maxLength = input.maxLength > 0 ? input.maxLength : Infinity;
  if (OTP_HINT.test(h) && maxLength <= 10) return "totp";
  if (input.type === "number") return null;
  if (autocomplete.includes("email") || input.type === "email") return "username";
  if (USERNAME_HINT.test(h) && !NOT_USERNAME.test(h)) return "username";
  return null;
}

/** All login-ish field groups on the page, one per form (plus one for inputs outside any form). */
export function findGroups(doc: Document = document): LoginGroup[] {
  const byContainer = new Map<HTMLFormElement | null, { input: HTMLInputElement; kind: FieldKind }[]>();
  for (const input of doc.querySelectorAll<HTMLInputElement>("input")) {
    const kind = classify(input);
    if (!kind) continue;
    const form = input.form;
    if (!byContainer.has(form)) byContainer.set(form, []);
    byContainer.get(form)!.push({ input, kind });
  }

  const groups: LoginGroup[] = [];
  for (const [form, fields] of byContainer) {
    const group: LoginGroup = { form };
    const passwordIndex = fields.findIndex((f) => f.kind === "password");
    if (passwordIndex >= 0) {
      group.password = fields[passwordIndex].input;
      // The username is the closest username-like field before the password.
      group.username = fields
        .slice(0, passwordIndex)
        .reverse()
        .find((f) => f.kind === "username")?.input;
    }
    group.newPassword = fields.find((f) => f.kind === "new-password")?.input;
    if (group.newPassword && !group.username) {
      const idx = fields.findIndex((f) => f.input === group.newPassword);
      group.username = fields.slice(0, idx).reverse().find((f) => f.kind === "username")?.input;
    }
    group.totp = fields.find((f) => f.kind === "totp")?.input;

    // Username-first sign-in pages (Google, Microsoft, Apple): a lone username
    // field. Only trusted when the page says so clearly, to avoid newsletter boxes.
    if (!group.password && !group.newPassword && !group.username) {
      const lone = fields.filter((f) => f.kind === "username");
      if (lone.length === 1 && isClearlyUsername(lone[0].input, form)) group.username = lone[0].input;
    }

    if (group.username || group.password || group.newPassword || group.totp) groups.push(group);
  }
  return groups;
}

function isClearlyUsername(input: HTMLInputElement, form: HTMLFormElement | null): boolean {
  const autocomplete = (input.getAttribute("autocomplete") ?? "").toLowerCase();
  if (/\b(username|webauthn)\b/.test(autocomplete)) return true;
  // Inside a small form that looks like a sign-in step.
  if (!form) return false;
  const visibleInputs = [...form.querySelectorAll<HTMLInputElement>("input")].filter(
    (i) => i.type !== "hidden" && i.type !== "submit" && i.type !== "checkbox" && isVisible(i),
  );
  const text = (form.getAttribute("action") ?? "") + " " + (form.id ?? "") + " " + (form.className ?? "");
  return visibleInputs.length === 1 && /log.?in|sign.?in|auth|session|account/i.test(text);
}

export function groupFor(input: HTMLInputElement, doc: Document = document): LoginGroup | undefined {
  return findGroups(doc).find(
    (g) => g.username === input || g.password === input || g.newPassword === input || g.totp === input,
  );
}

export function kindIn(group: LoginGroup, input: HTMLInputElement): FieldKind | null {
  if (group.username === input) return "username";
  if (group.password === input) return "password";
  if (group.newPassword === input) return "new-password";
  if (group.totp === input) return "totp";
  return null;
}

/**
 * Set a field's value the way typing would, so frameworks (React, Vue,
 * Angular) that track input through events and property setters notice.
 */
export function setValue(input: HTMLInputElement, value: string) {
  input.focus({ preventScroll: true });
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertReplacementText", data: value }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/**
 * The fields a new password goes into on a sign-up or change-password form:
 * the new password and its "confirm" twins, never the current password.
 * Empty on login forms.
 */
export function newPasswordFields(group: LoginGroup): HTMLInputElement[] {
  if (!group.newPassword) return [];
  const scope: ParentNode = group.form ?? group.newPassword.ownerDocument;
  const fields = [...scope.querySelectorAll<HTMLInputElement>('input[type="password"]')].filter(
    (i) => !i.disabled && !i.readOnly && isVisible(i),
  );
  // "Password" + "Confirm password" without autocomplete hints: the first one
  // looks like a current password, but the pair is a sign-up form.
  const current = group.password;
  const signUpPair =
    fields.length === 2 &&
    current !== undefined &&
    !(current.getAttribute("autocomplete") ?? "").includes("current-password") &&
    CONFIRM_HINT.test(hints(group.newPassword));
  return fields.filter((f) => signUpPair || f !== current);
}

/** What the user is submitting, if it looks like a login or sign-up. */
export function readSubmission(group: LoginGroup): { username: string; password: string } | null {
  const password = group.newPassword?.value || group.password?.value || "";
  if (!password) return null;
  return { username: group.username?.value.trim() ?? "", password };
}

const SUBMIT_HINT = /log.?[io]n|sign.?[io]n|submit|continue|next|verify|confirm|enter|anmelden|einloggen|weiter|inloggen|aanmelden|volgende|doorgaan|^go$/i;
const NOT_SUBMIT = /forgot|reset|sign.?up|register|create|cancel|back|google|apple|facebook|microsoft|github|sso|passkey|show|hide|remember/i;

function buttonLabel(el: Element): string {
  const text = el instanceof HTMLInputElement ? el.value : el.textContent ?? "";
  return [text, el.getAttribute("aria-label") ?? "", el.getAttribute("title") ?? ""].join(" ").trim().slice(0, 200);
}

function isSubmitButton(el: Element): el is HTMLButtonElement | HTMLInputElement {
  return (el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.type === "submit";
}

/**
 * The button that signs in with this group's fields, or nothing when it isn't
 * clear which one that is. Clicking the wrong thing ("Create account", "Sign in
 * with Google") is worse than not clicking at all.
 */
export function findSubmitButton(group: LoginGroup): HTMLElement | null {
  const anchor = group.password ?? group.totp ?? group.username;
  if (!anchor) return null;

  if (group.form) {
    const submits = [...group.form.elements].filter(
      (el): el is HTMLButtonElement | HTMLInputElement => isSubmitButton(el) && isVisible(el) && !NOT_SUBMIT.test(buttonLabel(el)),
    );
    // Prefer one labelled like a sign-in; otherwise the first submit button,
    // which is the one pressing Enter in the form would use.
    return submits.find((b) => SUBMIT_HINT.test(buttonLabel(b))) ?? submits[0] ?? null;
  }

  // No form element: look outward from the field for a nearby sign-in button
  // that comes after it on the page.
  let container: Element | null = anchor.parentElement;
  for (let depth = 0; container && depth < 6; depth++, container = container.parentElement) {
    const candidates = container.querySelectorAll<HTMLElement>(
      'button, input[type="submit"], input[type="button"], [role="button"]',
    );
    for (const el of candidates) {
      if (!(anchor.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING)) continue;
      const label = buttonLabel(el);
      if (isVisible(el) && SUBMIT_HINT.test(label) && !NOT_SUBMIT.test(label)) return el;
    }
  }
  return null;
}

export function isDisabled(el: HTMLElement): boolean {
  return (el as HTMLButtonElement).disabled === true || el.getAttribute("aria-disabled") === "true";
}
