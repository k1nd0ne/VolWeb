import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
      "/core": "http://localhost:8000",
      "/media": "http://localhost:8000",
      "/admin": "http://localhost:8000",
      "/swagger": "http://localhost:8000",
      "/static": "http://localhost:8000",
      "/ws": {
        target: "ws://localhost:8000",
        ws: true,
      },
    },
  },
});
