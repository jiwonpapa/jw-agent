import { bracketMatching, defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { unifiedMergeView } from "@codemirror/merge";
import {
  drawSelection,
  EditorView,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  lineNumbers,
} from "@codemirror/view";
import { useEffect, useRef } from "react";

import { cn } from "./cn";
import { editorTheme, languageExtension, type EditorLanguage } from "./code-editor";

interface CodeDiffProps {
  original: string;
  modified: string;
  ariaLabel: string;
  language?: EditorLanguage;
  className?: string;
}

export function CodeDiff({
  original,
  modified,
  ariaLabel,
  language = "plain",
  className,
}: CodeDiffProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const parent = hostRef.current;
    if (parent === null) return;
    const syntax = languageExtension(language);
    const extensions = [
      highlightSpecialChars(),
      drawSelection(),
      lineNumbers(),
      highlightActiveLine(),
      highlightActiveLineGutter(),
      bracketMatching(),
      syntaxHighlighting(defaultHighlightStyle),
      editorTheme,
      EditorView.lineWrapping,
      EditorView.editable.of(false),
      EditorView.contentAttributes.of({
        "aria-label": ariaLabel,
        "aria-readonly": "true",
        spellcheck: "false",
      }),
      unifiedMergeView({
        original,
        gutter: true,
        highlightChanges: true,
        allowInlineDiffs: true,
        mergeControls: false,
        collapseUnchanged: { margin: 2, minSize: 5 },
        diffConfig: { scanLimit: 8_000, timeout: 500 },
      }),
    ];
    if (syntax !== null) extensions.push(syntax);
    const view = new EditorView({ doc: modified, extensions, parent });
    return () => view.destroy();
  }, [ariaLabel, language, modified, original]);

  return (
    <div
      className={cn("max-h-[28rem] overflow-auto rounded-control border border-border bg-surface", className)}
      ref={hostRef}
    />
  );
}
