import EditorWorker from "./monaco-editor.worker?worker";
import * as monaco from "monaco-editor-core/esm/vs/editor/editor.api.js";
import "monaco-editor-core/esm/vs/editor/contrib/bracketMatching/browser/bracketMatching.js";
import "monaco-editor-core/esm/vs/editor/contrib/clipboard/browser/clipboard.js";
import "monaco-editor-core/esm/vs/editor/contrib/comment/browser/comment.js";
import "monaco-editor-core/esm/vs/editor/contrib/contextmenu/browser/contextmenu.js";
import "monaco-editor-core/esm/vs/editor/contrib/find/browser/findController.js";
import "monaco-editor-core/esm/vs/editor/contrib/folding/browser/folding.js";
import "monaco-editor-core/esm/vs/editor/contrib/gotoError/browser/gotoError.js";
import "monaco-editor-core/esm/vs/editor/contrib/indentation/browser/indentation.js";
import "monaco-editor-core/esm/vs/editor/contrib/linesOperations/browser/linesOperations.js";
import "monaco-editor-core/esm/vs/editor/contrib/multicursor/browser/multicursor.js";
import "monaco-editor-core/esm/vs/editor/contrib/stickyScroll/browser/stickyScrollContribution.js";

const scope = self as typeof self & {
  MonacoEnvironment?: {
    getWorker: (moduleId: string, label: string) => Worker;
  };
};

scope.MonacoEnvironment = {
  getWorker: () => new EditorWorker(),
};

registerLanguages();
registerTheme();

const runtimeScope = globalThis as typeof globalThis & {
  __JW_AGENT_MONACO__?: typeof monaco;
};
runtimeScope.__JW_AGENT_MONACO__ = monaco;

export { monaco };

function registerLanguages(): void {
  if (!monaco.languages.getLanguages().some(({ id }) => id === "jw-nginx")) {
    monaco.languages.register({ id: "jw-nginx", aliases: ["Nginx"] });
    monaco.languages.setLanguageConfiguration("jw-nginx", {
      comments: { lineComment: "#" },
      brackets: [["{", "}"]],
      autoClosingPairs: [
        { open: "{", close: "}" },
        { open: "\"", close: "\"" },
        { open: "'", close: "'" },
      ],
    });
    monaco.languages.setMonarchTokensProvider("jw-nginx", {
      tokenizer: {
        root: [
          [/#.*$/u, "comment"],
          [/"(?:[^"\\]|\\.)*"/u, "string"],
          [/'(?:[^'\\]|\\.)*'/u, "string"],
          [/\$[a-zA-Z_][\w]*/u, "variable"],
          [/\b(?:http|server|location|upstream|events|mail|stream|if|map|geo|types|limit_except)\b/u, "keyword"],
          [/\b(?:on|off)\b/u, "constant"],
          [/\b\d+(?:\.\d+)?(?:ms|s|m|h|d|k|K|m|M|g|G)?\b/u, "number"],
          [/[{};]/u, "delimiter.bracket"],
          [/[a-zA-Z_][\w.-]*/u, "type.identifier"],
        ],
      },
    });
  }

  if (!monaco.languages.getLanguages().some(({ id }) => id === "jw-ini")) {
    monaco.languages.register({ id: "jw-ini", aliases: ["INI", "PHP INI"] });
    monaco.languages.setLanguageConfiguration("jw-ini", {
      comments: { lineComment: ";" },
      brackets: [["[", "]"]],
    });
    monaco.languages.setMonarchTokensProvider("jw-ini", {
      tokenizer: {
        root: [
          [/^[\t ]*[;#].*$/u, "comment"],
          [/^[\t ]*\[[^\]]+\]/u, "type.identifier"],
          [/^[\t ]*[a-zA-Z_][\w.-]*(?=[\t ]*=)/u, "key"],
          [/"(?:[^"\\]|\\.)*"/u, "string"],
          [/'(?:[^'\\]|\\.)*'/u, "string"],
          [/\b(?:true|false|yes|no|on|off|null|none)\b/iu, "constant"],
          [/\b\d+(?:\.\d+)?(?:K|M|G|ms|s)?\b/iu, "number"],
          [/[=|&~!()]/u, "delimiter"],
        ],
      },
    });
  }
}

function registerTheme(): void {
  monaco.editor.defineTheme("jw-agent-light", {
    base: "vs",
    inherit: true,
    rules: [
      { token: "comment", foreground: "7A746A", fontStyle: "italic" },
      { token: "keyword", foreground: "005F8F", fontStyle: "bold" },
      { token: "type.identifier", foreground: "7C3E00" },
      { token: "key", foreground: "005F8F" },
      { token: "variable", foreground: "7C3E00" },
      { token: "string", foreground: "17643A" },
      { token: "number", foreground: "6B3FA0" },
      { token: "constant", foreground: "9B2C2C" },
    ],
    colors: {
      "editor.background": "#FFFFFF",
      "editor.foreground": "#22211F",
      "editor.lineHighlightBackground": "#F3F1EC",
      "editor.selectionBackground": "#CDE7F5",
      "editor.inactiveSelectionBackground": "#E3EFF5",
      "editorGutter.background": "#F8F7F4",
      "editorLineNumber.foreground": "#8A857C",
      "editorLineNumber.activeForeground": "#22211F",
      "editorError.foreground": "#C2413A",
      "editorOverviewRuler.errorForeground": "#C2413A",
      "editorStickyScroll.background": "#F8F7F4",
      "editorStickyScroll.border": "#D9D5CC",
    },
  });
}
