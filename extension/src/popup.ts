import { avatar } from "./avatar";
import type { FillResult, PopupMessage, PopupState, UnlockResult } from "./messages";

const send = <T>(msg: PopupMessage): Promise<T> => chrome.runtime.sendMessage(msg) as Promise<T>;
const main = document.querySelector("main")!;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function message(title: string, body: string, action?: { label: string; run: () => void }) {
  const box = el("div", { className: "message" }, el("strong", {}, title), el("p", {}, body));
  if (action) box.append(el("button", { className: "primary", onclick: action.run }, action.label));
  main.replaceChildren(box);
}

const openApp = () => {
  send({ type: "openApp" });
  window.close();
};

async function render() {
  const { site, logins } = await send<PopupState>({ type: "popupState" });

  if (logins.state === "locked" && logins.touchId) {
    message("Vaultix is locked", "Unlock with your fingerprint to fill passwords.", {
      label: "Unlock with Touch ID",
      run: async () => {
        message("Touch the sensor…", "Confirm with Touch ID to unlock Vaultix.");
        const result = await send<UnlockResult>({ type: "unlock" });
        if (result.ok || result.error === "touch-id-cancelled") render();
        else openApp();
      },
    });
    return;
  }
  if (logins.state === "locked") {
    message("Vaultix is locked", "Unlock the app to fill passwords.", { label: "Open Vaultix", run: openApp });
    return;
  }
  if (logins.state === "unavailable") {
    const text: Record<string, [string, string]> = {
      "app-not-running": ["Vaultix isn't running", "Start the Vaultix app on this Mac."],
      "not-installed": ["Vaultix isn't connected", "Open the Vaultix app once so it can register with this browser, then reload this page."],
      rejected: ["Connection refused", logins.detail ?? "The Vaultix app didn't accept this browser."],
      error: ["Can't reach Vaultix", logins.detail ?? "Something went wrong talking to the app."],
    };
    const [title, body] = text[logins.reason];
    message(title, body);
    return;
  }
  if (logins.logins.length === 0) {
    message(site ? `No logins for ${site}` : "Nothing to fill here", "Logins you save on this site will show up here.", {
      label: "Open Vaultix",
      run: openApp,
    });
    return;
  }

  const list = el("ul");
  for (const login of logins.logins) {
    const button = el(
      "button",
      {
        className: "login",
        onclick: async () => {
          const r = await send<FillResult>({ type: "popupFill", itemId: login.id });
          if (r.ok) window.close();
          else message("Couldn't fill", r.error);
        },
      },
      avatar(login.title, login.icon),
      el("span", { className: "text" }, el("span", { className: "title" }, login.title), el("span", { className: "sub" }, login.username || "No username")),
      el("span", { className: "fill" }, "Fill"),
    );
    list.append(el("li", {}, button));
  }
  main.replaceChildren(el("p", { className: "site" }, site), list);
  (list.querySelector("button") as HTMLButtonElement | null)?.focus();
}

document.getElementById("open")!.addEventListener("click", openApp);
render().catch((e) => message("Something went wrong", String(e)));
