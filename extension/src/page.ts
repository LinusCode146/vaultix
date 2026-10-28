// Runs in the page's own JavaScript world ("world": "MAIN"), before the
// page's scripts, to wrap navigator.credentials.create/get. It holds no
// secrets and decides nothing: each passkey request goes to the content
// script, which asks the user and the app. The app builds clientDataJSON from
// the origin the browser reports, so a page can't ask for another site's
// passkeys through here.
//
// "fallback" answers hand the request to the browser untouched, so when
// Vaultix isn't running or has nothing for the site, nothing changes.

import type { PageRequest, PageResponse, PasskeyCredential } from "./messages";

type Request = PageRequest extends infer R ? (R extends unknown ? Omit<R, "vaultix" | "id"> : never) : never;

const container = navigator.credentials;

if (container && typeof PublicKeyCredential !== "undefined" && window.isSecureContext) {
  const originalCreate = container.create.bind(container);
  const originalGet = container.get.bind(container);
  const post = window.postMessage.bind(window);
  const waiting = new Map<number, (r: PageResponse) => void>();
  let nextId = 1;

  // The content script loads at document_idle and announces itself. If it
  // never does (e.g. the extension was reloaded under this page), the browser
  // handles passkeys as usual.
  let bridge: Promise<boolean>;
  {
    let settle!: (ok: boolean) => void;
    bridge = new Promise((r) => (settle = r));
    window.addEventListener("message", (e) => {
      if (e.source !== window || !e.data || typeof e.data !== "object") return;
      if (e.data.vaultix === "ready") settle(true);
      if (e.data.vaultix !== "response") return;
      const done = waiting.get(e.data.id);
      if (!done) return;
      waiting.delete(e.data.id);
      done(e.data as PageResponse);
    });
    const giveUp = () => setTimeout(() => settle(false), 3000);
    if (document.readyState === "complete") giveUp();
    else window.addEventListener("load", giveUp, { once: true });
  }

  const abortError = (signal: AbortSignal) => signal.reason ?? new DOMException("The operation was aborted.", "AbortError");

  async function ask(request: Request, signal?: AbortSignal | null): Promise<PageResponse | null> {
    if (!(await bridge)) return null;
    if (signal?.aborted) throw abortError(signal);
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        waiting.delete(id);
        post({ vaultix: "request", id, kind: "abort" } satisfies PageRequest, "*");
        reject(abortError(signal!));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      waiting.set(id, (r) => {
        signal?.removeEventListener("abort", onAbort);
        resolve(r);
      });
      post({ vaultix: "request", id, ...request } as PageRequest, "*");
    });
  }

  function create(options?: CredentialCreationOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    // Not a passkey (e.g. a password credential), or the site asks for a security key.
    if (!pk || pk.authenticatorSelection?.authenticatorAttachment === "cross-platform") return originalCreate(options);
    return (async () => {
      const response = await ask(
        {
          kind: "create",
          options: {
            rpId: pk.rp.id ?? location.hostname,
            userId: toB64(pk.user.id),
            userName: pk.user.name,
            userDisplayName: pk.user.displayName ?? "",
            challenge: toB64(pk.challenge),
            algorithms: pk.pubKeyCredParams.map((p) => p.alg),
            exclude: (pk.excludeCredentials ?? []).map((c) => toB64(c.id)),
          },
        },
        options!.signal,
      );
      if (!response || response.action === "fallback") return originalCreate(options);
      if (response.action === "error") throw new DOMException(response.message, response.name);
      return credential("create", response.credential, !!pk.extensions?.credProps);
    })();
  }

  function get(options?: CredentialRequestOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk || options!.mediation === "silent") return originalGet(options);
    return (async () => {
      const response = await ask(
        {
          kind: "get",
          conditional: options!.mediation === "conditional",
          options: {
            rpId: pk.rpId ?? location.hostname,
            challenge: toB64(pk.challenge),
            allow: (pk.allowCredentials ?? []).map((c) => toB64(c.id)),
          },
        },
        options!.signal,
      );
      if (!response || response.action === "fallback") return originalGet(options);
      if (response.action === "error") throw new DOMException(response.message, response.name);
      return credential("get", response.credential, false);
    })();
  }

  for (const [name, fn] of [["create", create], ["get", get]] as const) {
    Object.defineProperty(container, name, { value: fn, configurable: true, writable: true });
  }
}

/**
 * A PublicKeyCredential for the page. The browser can't construct one for an
 * outside authenticator, so this is an object with the real prototypes (for
 * `instanceof`) and own properties shadowing their getters.
 */
function credential(kind: "create" | "get", c: PasskeyCredential, credProps: boolean): PublicKeyCredential {
  const transports = ["hybrid", "internal"];
  let response: AuthenticatorResponse;
  let responseJson: Record<string, unknown>;
  if (kind === "create") {
    responseJson = {
      clientDataJSON: c.clientDataJSON,
      attestationObject: c.attestationObject,
      authenticatorData: c.authenticatorData,
      publicKey: c.publicKey,
      publicKeyAlgorithm: c.publicKeyAlgorithm,
      transports,
    };
    response = withProps(AuthenticatorAttestationResponse.prototype, {
      clientDataJSON: fromB64(c.clientDataJSON),
      attestationObject: fromB64(c.attestationObject!),
      getTransports: () => [...transports],
      getAuthenticatorData: () => fromB64(c.authenticatorData),
      getPublicKey: () => fromB64(c.publicKey!),
      getPublicKeyAlgorithm: () => c.publicKeyAlgorithm,
      toJSON: () => responseJson,
    });
  } else {
    responseJson = {
      clientDataJSON: c.clientDataJSON,
      authenticatorData: c.authenticatorData,
      signature: c.signature,
      userHandle: c.userHandle,
    };
    response = withProps(AuthenticatorAssertionResponse.prototype, {
      clientDataJSON: fromB64(c.clientDataJSON),
      authenticatorData: fromB64(c.authenticatorData),
      signature: fromB64(c.signature!),
      userHandle: c.userHandle ? fromB64(c.userHandle) : null,
      toJSON: () => responseJson,
    });
  }
  const extensions = credProps ? { credProps: { rk: true } } : {};
  return withProps(PublicKeyCredential.prototype, {
    id: c.credentialId,
    rawId: fromB64(c.credentialId),
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    getClientExtensionResults: () => extensions,
    toJSON: () => ({
      id: c.credentialId,
      rawId: c.credentialId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response: responseJson,
      clientExtensionResults: extensions,
    }),
  });
}

/**
 * Writable, like assigning on a real credential (whose fields live on the
 * prototype): libraries such as @github/webauthn-json set `credential.toJSON`
 * and other fields, which would throw on read-only properties in strict code.
 */
function withProps<T extends object>(proto: T, props: Record<string, unknown>): T {
  const o = Object.create(proto);
  for (const [key, value] of Object.entries(props)) {
    Object.defineProperty(o, key, { value, enumerable: true, writable: true, configurable: true });
  }
  return o;
}

function toB64(data: BufferSource): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64(s: string): ArrayBuffer {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
