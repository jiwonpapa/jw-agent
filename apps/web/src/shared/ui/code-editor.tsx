import {
  bracketMatching,
  defaultHighlightStyle,
  StreamLanguage,
  syntaxHighlighting,
  type LanguageSupport,
} from "@codemirror/language";
import { nginx } from "@codemirror/legacy-modes/mode/nginx";
import { Compartment, type Extension } from "@codemirror/state";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import {
  Decoration,
  drawSelection,
  dropCursor,
  EditorView,
  gutter,
  GutterMarker,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
} from "@codemirror/view";
import { useEffect, useRef } from "react";

import { cn } from "./cn";

export type EditorLanguage = "nginx" | "plain";

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  ariaLabel: string;
  language?: EditorLanguage;
  readOnly?: boolean;
  diagnosticLine?: number | null;
  diagnosticMessage?: string;
  className?: string;
}

const nginxLanguage = StreamLanguage.define(nginx);

export const editorTheme = EditorView.theme({
  "&": {
    color: "var(--color-text)",
    backgroundColor: "var(--color-surface)",
    fontSize: "13px",
  },
  "&.cm-focused": {
    outline: "none",
    boxShadow: "0 0 0 3px color-mix(in oklch, var(--color-focus) 28%, transparent)",
  },
  ".cm-scroller": {
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
    lineHeight: "1.55",
  },
  ".cm-content": {
    minHeight: "20rem",
    padding: "0.75rem 0",
    caretColor: "var(--color-action)",
  },
  ".cm-gutters": {
    color: "var(--color-muted)",
    backgroundColor: "var(--color-subtle)",
    borderRight: "1px solid var(--color-border)",
  },
  ".cm-activeLine, .cm-activeLineGutter": {
    backgroundColor: "color-mix(in oklch, var(--color-action) 9%, transparent)",
  },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
    backgroundColor: "color-mix(in oklch, var(--color-action) 22%, transparent)",
  },
  ".cm-cursor": {
    borderLeftColor: "var(--color-action)",
  },
  ".cm-diagnostic-line": {
    backgroundColor: "color-mix(in oklch, var(--color-danger) 10%, transparent)",
  },
  ".cm-diagnostic-gutter": {
    color: "var(--color-danger)",
    backgroundColor: "var(--color-subtle)",
    borderRight: "1px solid var(--color-border)",
  },
  ".cm-diagnostic-marker": {
    display: "grid",
    width: "1rem",
    height: "1rem",
    placeItems: "center",
    borderRadius: "999px",
    color: "var(--color-action-foreground)",
    backgroundColor: "var(--color-danger)",
    fontSize: "10px",
    fontWeight: "700",
  },
});

class DiagnosticGutterMarker extends GutterMarker {
  readonly elementClass = "cm-diagnostic-marker";

  constructor(private readonly message: string) {
    super();
  }

  override toDOM(): HTMLElement {
    const element = document.createElement("span");
    element.textContent = "!";
    element.title = this.message;
    element.setAttribute("aria-label", this.message);
    return element;
  }
}

function diagnosticExtension(view: EditorView, lineNumber: number | null, message: string): Extension {
  if (lineNumber === null || lineNumber <= 0 || lineNumber > view.state.doc.lines) return [];
  const line = view.state.doc.line(lineNumber);
  const marker = new DiagnosticGutterMarker(message);
  return [
    EditorView.decorations.of(Decoration.set([Decoration.line({ class: "cm-diagnostic-line" }).range(line.from)])),
    gutter({
      class: "cm-diagnostic-gutter",
      lineMarker: (_view, block) => block.from === line.from ? marker : null,
    }),
  ];
}

export function languageExtension(language: EditorLanguage): LanguageSupport | ReturnType<typeof StreamLanguage.define> | null {
  return language === "nginx" ? nginxLanguage : null;
}

export function CodeEditor({
  value,
  onChange,
  ariaLabel,
  language = "plain",
  readOnly = false,
  diagnosticLine = null,
  diagnosticMessage = "서버 문법검사가 이 줄에서 실패했습니다.",
  className,
}: CodeEditorProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const diagnosticCompartmentRef = useRef<Compartment | null>(null);
  const onChangeRef = useRef(onChange);
  const synchronizing = useRef(false);
  const initialValueRef = useRef(value);

  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  useEffect(() => {
    initialValueRef.current = value;
  }, [value]);

  useEffect(() => {
    const parent = hostRef.current;
    if (parent === null) return;
    const syntax = languageExtension(language);
    const diagnosticCompartment = new Compartment();
    diagnosticCompartmentRef.current = diagnosticCompartment;
    const extensions = [
      highlightSpecialChars(),
      history(),
      drawSelection(),
      dropCursor(),
      keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
      lineNumbers(),
      highlightActiveLine(),
      highlightActiveLineGutter(),
      bracketMatching(),
      syntaxHighlighting(defaultHighlightStyle),
      diagnosticCompartment.of([]),
      editorTheme,
      EditorView.lineWrapping,
      EditorView.editable.of(!readOnly),
      EditorView.contentAttributes.of({
        "aria-label": ariaLabel,
        "aria-readonly": readOnly ? "true" : "false",
        autocapitalize: "off",
        autocomplete: "off",
        spellcheck: "false",
      }),
      EditorView.updateListener.of((update) => {
        if (update.docChanged && !synchronizing.current) {
          onChangeRef.current(update.state.doc.toString());
        }
      }),
    ];
    if (syntax !== null) extensions.push(syntax);
    const view = new EditorView({ doc: initialValueRef.current, extensions, parent });
    viewRef.current = view;
    return () => {
      viewRef.current = null;
      diagnosticCompartmentRef.current = null;
      view.destroy();
    };
  }, [ariaLabel, language, readOnly]);

  useEffect(() => {
    const view = viewRef.current;
    if (view === null || view.state.doc.toString() === value) return;
    synchronizing.current = true;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } });
    synchronizing.current = false;
  }, [value]);

  useEffect(() => {
    const view = viewRef.current;
    const compartment = diagnosticCompartmentRef.current;
    if (view === null || compartment === null) return;
    view.dispatch({
      effects: compartment.reconfigure(
        diagnosticExtension(view, diagnosticLine, diagnosticMessage),
      ),
    });
    if (diagnosticLine !== null && diagnosticLine > 0 && diagnosticLine <= view.state.doc.lines) {
      const line = view.state.doc.line(diagnosticLine);
      view.dispatch({
        selection: { anchor: line.from },
        effects: EditorView.scrollIntoView(line.from, { y: "center" }),
      });
    }
  }, [diagnosticLine, diagnosticMessage, value]);

  return (
    <div
      className={cn("overflow-hidden rounded-control border border-border bg-surface", className)}
      ref={hostRef}
    />
  );
}
