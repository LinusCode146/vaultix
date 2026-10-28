import { useCallback, useEffect, useState } from "react";
import { api, type Status } from "./api";
import { Setup } from "./screens/Setup";
import { Unlock } from "./screens/Unlock";
import { VaultScreen } from "./screens/VaultScreen";

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const refresh = useCallback(() => {
    api.status().then(setStatus);
  }, []);
  useEffect(refresh, [refresh]);
  // Unlocked with Touch ID from the browser extension.
  useEffect(() => api.onUnlocked(refresh), [refresh]);
  // Locked from the menu bar.
  useEffect(() => api.onLocked(refresh), [refresh]);

  if (!status) return null;
  switch (status.stage) {
    case "setup":
      return <Setup onDone={refresh} />;
    case "locked":
      return <Unlock status={status} onUnlocked={refresh} onForgotten={refresh} />;
    case "unlocked":
      return <VaultScreen onLocked={refresh} />;
  }
}
