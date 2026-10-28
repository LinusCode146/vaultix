import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, errorMessage, type Status, type TouchIdStatus } from "../api";
import { Spinner, TouchIdIcon } from "../components/ui";
import { biometric, computer, isMac } from "../platform";

const TOUCH_ID_ERRORS: Record<string, string> = {
  "touch-id-invalidated": isMac
    ? "Your fingerprints changed, so Touch ID was turned off. Unlock with your master password to turn it back on."
    : "Windows Hello was reset, so Vaultix stopped using it. Turn it on again in Settings.",
  "touch-id-lockout": `${biometric} is locked after too many attempts. Use your master password.`,
  "touch-id-unavailable": `${biometric} isn't available right now. Use your master password.`,
  "password-required": "Enter your master password. It's needed every two weeks so you don't forget it.",
};

export function Unlock({ status, onUnlocked, onForgotten }: { status: Status; onUnlocked: () => void; onForgotten: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmForget, setConfirmForget] = useState(false);
  const [touchId, setTouchId] = useState<TouchIdStatus | null>(null);
  const [touchBusy, setTouchBusy] = useState(false);
  const autoPrompted = useRef(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  const unlockWithTouchId = useCallback(async () => {
    setTouchBusy(true);
    setError("");
    try {
      await api.unlockTouchId();
      onUnlocked();
    } catch (err) {
      const code = errorMessage(err);
      if (code !== "touch-id-cancelled" && code !== "touch-id-busy") {
        setError(TOUCH_ID_ERRORS[code] ?? `${biometric} didn't work. Use your master password.`);
        api.touchIdStatus().then(setTouchId, () => {});
      }
      setTouchBusy(false);
      passwordRef.current?.focus();
    }
  }, [onUnlocked]);

  useEffect(() => {
    // Ask for a fingerprint right away, once, like 1Password does; but only
    // while the window is in front. Locked in the background (idle, or from
    // the menu bar), it waits until the window is opened.
    let usable = false;
    const prompt = () => {
      if (!usable || autoPrompted.current || !document.hasFocus()) return;
      autoPrompted.current = true;
      unlockWithTouchId();
    };
    api.touchIdStatus().then((s) => {
      setTouchId(s);
      if (s.passwordRequired) setError(TOUCH_ID_ERRORS["password-required"]);
      usable = s.usable;
      prompt();
    }, () => {});
    window.addEventListener("focus", prompt);
    return () => window.removeEventListener("focus", prompt);
  }, [unlockWithTouchId]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError("");
    try {
      await api.unlock(password);
      onUnlocked();
    } catch (err) {
      const msg = errorMessage(err);
      setError(msg.charAt(0).toUpperCase() + msg.slice(1) + ".");
      setPassword("");
      setBusy(false);
    }
  }

  return (
    <div className="center-screen">
      <form className="panel unlock" onSubmit={submit}>
        <img src="/logo.svg" alt="" width={76} height={76} />
        <div className="unlock-title">
          <h1>Welcome back</h1>
          <p>Vaultix is locked</p>
        </div>
        {touchId?.usable && (
          <>
            <button type="button" className="touch-id-big" onClick={unlockWithTouchId} disabled={touchBusy}>
              <span className="touch-id-ring" aria-hidden="true">
                {touchBusy ? <Spinner /> : <TouchIdIcon size={34} />}
              </span>
              Unlock with {biometric}
            </button>
            <div className="or-divider">or use your master password</div>
          </>
        )}
        <div className="unlock-fields">
          <input
            type="password"
            className="big-input"
            placeholder="Master password"
            aria-label="Master password"
            autoFocus
            ref={passwordRef}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
          <button type="submit" className="btn primary big-btn" disabled={!password || busy}>
            {busy ? <Spinner /> : null} Unlock
          </button>
          {error && <p className={touchId?.passwordRequired && !password ? "hint" : "error-text"}>{error}</p>}
        </div>
        <div className="unlock-foot">
          <p className="hint vault-dir" title={status.vaultDir ?? ""}>
            {status.vaultDir}
          </p>
          {confirmForget ? (
            <p className="hint">
              Disconnect this {computer} from the vault? The vault files stay where they are.{" "}
              <button
                type="button"
                className="link danger"
                onClick={async () => {
                  await api.forgetVault();
                  onForgotten();
                }}
              >
                Disconnect
              </button>{" "}
              <button type="button" className="link" onClick={() => setConfirmForget(false)}>
                Cancel
              </button>
            </p>
          ) : (
            <button type="button" className="link subtle" onClick={() => setConfirmForget(true)}>
              Use a different vault…
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
