import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// default exports the loopback-only Vite development configuration for the local management interface.
// default 导出本地管理界面的仅环回 Vite 开发配置。
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 13520,
    strictPort: true,
    proxy: {
      "/vulcan/manage": {
        target: "http://127.0.0.1:13514",
        changeOrigin: false
      }
    }
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts"
  }
});
