import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));
const monacoRoot = fileURLToPath(new URL("./node_modules/monaco-editor-core/", import.meta.url));

export default defineConfig({
  base: "/vendor/monaco/",
  plugins: [{
    name: "monaco-license-assets",
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "LICENSE",
        source: readFileSync(`${monacoRoot}LICENSE`),
      });
      this.emitFile({
        type: "asset",
        fileName: "ThirdPartyNotices.txt",
        source: readFileSync(`${monacoRoot}ThirdPartyNotices.txt`),
      });
    },
  }],
  worker: {
    format: "es",
    rolldownOptions: {
      output: {
        entryFileNames: "assets/monaco-editor.worker.js",
      },
    },
  },
  build: {
    copyPublicDir: false,
    cssCodeSplit: false,
    emptyOutDir: true,
    minify: true,
    outDir: `${root}public/vendor/monaco`,
    sourcemap: false,
    target: "es2022",
    lib: {
      entry: `${root}src/shared/ui/monaco-runtime.ts`,
      formats: ["es"],
      fileName: "monaco-runtime",
      cssFileName: "monaco-runtime",
    },
  },
});
