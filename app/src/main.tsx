import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { windowLabel } from "./api";
import { QuickSearch } from "./screens/QuickSearch";
import { initTheme } from "./theme";
import "./styles.css";

initTheme();
// The quick search window is transparent so its panel can have rounded corners.
if (windowLabel === "quick") document.documentElement.classList.add("quick-window");

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {windowLabel === "quick" ? <QuickSearch /> : <App />}
  </StrictMode>,
);
