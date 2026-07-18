import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import "./styles.css";

// rootElement is the sole Vite document mount point for the local management interface.
// rootElement 是本地管理界面的唯一 Vite 文档挂载点。
const rootElement = document.getElementById("root");

if (rootElement === null) {
  throw new Error("Vite management root element is required");
}

// root owns the React application lifecycle under the fixed local management page.
// root 管理固定本地管理页面下的 React 应用生命周期。
const root = createRoot(rootElement);

root.render(
  <StrictMode>
    <App />
  </StrictMode>
);
