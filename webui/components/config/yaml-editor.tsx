"use client";

import { useMemo, useRef } from "react";
import { cn } from "@/lib/utils";

interface YamlEditorProps {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  className?: string;
  lineNumbers?: boolean;
}

export function YamlEditor({
  value,
  onChange,
  readOnly = false,
  className,
  lineNumbers = true,
}: YamlEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const lineNumbersRef = useRef<HTMLDivElement>(null);
  const lines = useMemo(() => {
    const lineCount = value.split("\n").length;
    return Array.from({ length: lineCount }, (_, i) => i + 1);
  }, [value]);

  const handleScroll = () => {
    if (textareaRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const target = e.target as HTMLTextAreaElement;
      const start = target.selectionStart;
      const end = target.selectionEnd;
      const newValue = value.substring(0, start) + "  " + value.substring(end);
      onChange?.(newValue);
      requestAnimationFrame(() => {
        target.selectionStart = target.selectionEnd = start + 2;
      });
    }
  };

  return (
    <div
      className={cn(
        "relative flex rounded-md border bg-muted/30 font-mono text-sm overflow-hidden",
        className,
      )}
    >
      {lineNumbers && (
        <div
          ref={lineNumbersRef}
          className="flex-shrink-0 select-none overflow-hidden bg-muted/50 text-muted-foreground text-right py-3 px-2 border-r"
          style={{ minWidth: "3rem" }}
        >
          {lines.map((line) => (
            <div key={line} className="leading-6 h-6">
              {line}
            </div>
          ))}
        </div>
      )}
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        onScroll={handleScroll}
        onKeyDown={handleKeyDown}
        readOnly={readOnly}
        spellCheck={false}
        className={cn(
          "flex-1 resize-none bg-transparent p-3 leading-6 outline-none",
          "placeholder:text-muted-foreground",
          readOnly && "cursor-default",
        )}
        style={{
          minHeight: "400px",
          tabSize: 2,
        }}
      />
    </div>
  );
}
