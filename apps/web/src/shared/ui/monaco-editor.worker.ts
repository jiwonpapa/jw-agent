import { start } from "monaco-editor-core/esm/vs/editor/editor.worker.start.js";

let initialized = false;

self.onmessage = () => {
  if (initialized) return;
  initialized = true;
  start(() => ({}));
};
