import { useEffect, useRef, useState } from "react";
import type * as Monaco from "monaco-editor-core/esm/vs/editor/editor.api.js";

import { cn } from "./cn";

export type EditorLanguage = "ini" | "nginx" | "plain";

export interface EditorDiagnostic {
  line: number;
  column: number | null;
  severity: "error" | "warning";
  message: string;
}

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  ariaLabel: string;
  language?: EditorLanguage;
  readOnly?: boolean;
  diagnosticLine?: number | null;
  diagnosticMessage?: string;
  diagnostics?: readonly EditorDiagnostic[];
  className?: string;
}

let runtimePromise: ReturnType<typeof importRuntime> | null = null;

function importRuntime() {
  loadMonacoStyle();
  return new Promise<{ monaco: typeof Monaco }>((resolve, reject) => {
    const scope = globalThis as typeof globalThis & {
      __JW_AGENT_MONACO__?: typeof Monaco;
    };
    if (scope.__JW_AGENT_MONACO__ !== undefined) {
      resolve({ monaco: scope.__JW_AGENT_MONACO__ });
      return;
    }

    const scriptId = "jw-agent-monaco-runtime";
    const existing = document.getElementById(scriptId);
    const script = existing instanceof HTMLScriptElement
      ? existing
      : document.createElement("script");
    const onLoad = (): void => {
      if (scope.__JW_AGENT_MONACO__ === undefined) {
        reject(new Error("Monaco runtime loaded without an editor API"));
        return;
      }
      resolve({ monaco: scope.__JW_AGENT_MONACO__ });
    };
    script.addEventListener("load", onLoad, { once: true });
    script.addEventListener(
      "error",
      () => reject(new Error("Monaco runtime failed to load")),
      { once: true },
    );
    if (existing === null) {
      script.id = scriptId;
      script.type = "module";
      script.src = "/vendor/monaco/monaco-runtime.js";
      document.head.append(script);
    }
  });
}

function loadRuntime(): ReturnType<typeof importRuntime> {
  runtimePromise ??= importRuntime();
  return runtimePromise;
}

function languageId(language: EditorLanguage): string {
  if (language === "nginx") return "jw-nginx";
  if (language === "ini") return "jw-ini";
  return "plaintext";
}

export function CodeEditor({
  value,
  onChange,
  ariaLabel,
  language = "plain",
  readOnly = false,
  diagnosticLine = null,
  diagnosticMessage = "서버 문법검사가 이 줄에서 실패했습니다.",
  diagnostics = [],
  className,
}: CodeEditorProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<typeof Monaco | null>(null);
  const onChangeRef = useRef(onChange);
  const valueRef = useRef(value);
  const diagnosticLineRef = useRef(diagnosticLine);
  const diagnosticMessageRef = useRef(diagnosticMessage);
  const diagnosticsRef = useRef(diagnostics);
  const synchronizing = useRef(false);
  const desktopInput = useDesktopEditorInput();
  const effectiveReadOnly = readOnly || !desktopInput;
  const effectiveReadOnlyRef = useRef(effectiveReadOnly);

  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    valueRef.current = value;
  }, [value]);

  useEffect(() => {
    diagnosticLineRef.current = diagnosticLine;
    diagnosticMessageRef.current = diagnosticMessage;
    diagnosticsRef.current = diagnostics;
  }, [diagnosticLine, diagnosticMessage, diagnostics]);

  useEffect(() => {
    effectiveReadOnlyRef.current = effectiveReadOnly;
  }, [effectiveReadOnly]);

  useEffect(() => {
    const parent = hostRef.current;
    if (parent === null) return;
    let disposed = false;
    let editor: Monaco.editor.IStandaloneCodeEditor | null = null;
    let model: Monaco.editor.ITextModel | null = null;
    let subscription: Monaco.IDisposable | null = null;

    void loadRuntime().then(({ monaco }) => {
      if (disposed) return;
      monacoRef.current = monaco;
      model = monaco.editor.createModel(valueRef.current, languageId(language));
      editor = monaco.editor.create(parent, {
        model,
        ariaLabel,
        automaticLayout: true,
        bracketPairColorization: { enabled: true },
        cursorBlinking: "smooth",
        cursorSmoothCaretAnimation: "on",
        fixedOverflowWidgets: true,
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
        fontLigatures: false,
        fontSize: 13,
        glyphMargin: true,
        lineHeight: 21,
        minimap: { enabled: true, maxColumn: 80, renderCharacters: false },
        padding: { top: 12, bottom: 16 },
        readOnly: effectiveReadOnlyRef.current,
        renderValidationDecorations: "on",
        roundedSelection: false,
        scrollBeyondLastLine: false,
        smoothScrolling: true,
        stickyScroll: { enabled: true, maxLineCount: 4 },
        tabSize: 2,
        theme: "jw-agent-light",
        wordWrap: "off",
      });
      editorRef.current = editor;
      subscription = editor.onDidChangeModelContent(() => {
        if (!synchronizing.current && model !== null) {
          onChangeRef.current(model.getValue());
        }
      });
      applyDiagnostics(
        monaco,
        editor,
        diagnosticsRef.current,
        diagnosticLineRef.current,
        diagnosticMessageRef.current,
      );
    });

    return () => {
      disposed = true;
      subscription?.dispose();
      editor?.dispose();
      model?.dispose();
      if (editorRef.current === editor) editorRef.current = null;
      monacoRef.current = null;
    };
  }, [ariaLabel, language]);

  useEffect(() => {
    const editor = editorRef.current;
    if (editor === null) return;
    const model = editor.getModel();
    if (model === null || model.getValue() === value) return;
    synchronizing.current = true;
    editor.executeEdits("jw-agent-state", [{
      range: model.getFullModelRange(),
      text: value,
      forceMoveMarkers: true,
    }]);
    synchronizing.current = false;
  }, [value]);

  useEffect(() => {
    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (editor === null || monaco === null) return;
    editor.updateOptions({ readOnly: effectiveReadOnly });
  }, [effectiveReadOnly]);

  useEffect(() => {
    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (editor === null || monaco === null) return;
    applyDiagnostics(monaco, editor, diagnostics, diagnosticLine, diagnosticMessage);
  }, [diagnosticLine, diagnosticMessage, diagnostics]);

  return (
    <div
      aria-label={ariaLabel}
      data-code-editor
      data-readonly={String(effectiveReadOnly)}
      className={cn(
        "h-[32rem] overflow-hidden rounded-control border border-border bg-surface focus-within:ring-2 focus-within:ring-focus/30",
        className,
      )}
      ref={hostRef}
    />
  );
}

function applyDiagnostics(
  monaco: typeof Monaco,
  editor: Monaco.editor.IStandaloneCodeEditor,
  diagnostics: readonly EditorDiagnostic[],
  fallbackLine: number | null,
  fallbackMessage: string,
): void {
  const model = editor.getModel();
  if (model === null) return;
  const validDiagnostics = diagnostics.filter(
    ({ line }) => line > 0 && line <= model.getLineCount(),
  );
  const markers = validDiagnostics.map(({ line, column, message, severity }) => ({
    severity:
      severity === "warning" ? monaco.MarkerSeverity.Warning : monaco.MarkerSeverity.Error,
    message,
    startLineNumber: line,
    startColumn: Math.min(column ?? 1, model.getLineMaxColumn(line)),
    endLineNumber: line,
    endColumn: model.getLineMaxColumn(line),
    source: "server-validator",
  }));
  if (
    markers.length === 0
    && fallbackLine !== null
    && fallbackLine > 0
    && fallbackLine <= model.getLineCount()
  ) {
    markers.push({
      severity: monaco.MarkerSeverity.Error,
      message: fallbackMessage,
      startLineNumber: fallbackLine,
      startColumn: 1,
      endLineNumber: fallbackLine,
      endColumn: model.getLineMaxColumn(fallbackLine),
      source: "server-validator",
    });
  }
  monaco.editor.setModelMarkers(model, "jw-agent", markers);
  const firstLine = validDiagnostics[0]?.line ?? fallbackLine;
  if (firstLine === null || firstLine <= 0 || firstLine > model.getLineCount()) return;
  editor.setPosition({ lineNumber: firstLine, column: 1 });
  editor.revealLineInCenter(firstLine, monaco.editor.ScrollType.Smooth);
  editor.focus();
}

function useDesktopEditorInput(): boolean {
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(min-width: 1024px) and (pointer: fine)");
    const update = (): void => setEnabled(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  return enabled;
}

function loadMonacoStyle(): void {
  const href = "/vendor/monaco/monaco-runtime.css";
  if (document.head.querySelector(`link[href="${href}"]`) !== null) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = href;
  document.head.append(link);
}
