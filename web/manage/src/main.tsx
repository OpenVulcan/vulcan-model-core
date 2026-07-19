import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { BrowserRouter } from "react-router-dom"

import { App } from "@/App"
import { I18nProvider } from "@/i18n"
import "@/index.css"

// applicationRoot is the single Vite mount point for the management interface.
// applicationRoot 是管理界面的唯一 Vite 挂载点。
const applicationRoot = document.getElementById("root")

if (applicationRoot === null) {
  throw new Error("Application root element was not found.")
}

createRoot(applicationRoot).render(
  <StrictMode>
    <I18nProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </I18nProvider>
  </StrictMode>
)
