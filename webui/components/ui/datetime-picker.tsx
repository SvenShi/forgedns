"use client";

import * as React from "react";
import {
  CalendarDays,
  ChevronLeft,
  ChevronRight,
  X,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

const WEEKDAYS = ["日", "一", "二", "三", "四", "五", "六"];

function pad(value: number) {
  return value.toString().padStart(2, "0");
}

// Parses the `datetime-local` string format (`YYYY-MM-DDTHH:mm`) into a Date.
function parseValue(value: string): Date | null {
  if (!value) return null;
  const match = value.match(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/,
  );
  if (!match) return null;
  const [, y, mo, d, h, mi] = match;
  const date = new Date(
    Number(y),
    Number(mo) - 1,
    Number(d),
    Number(h),
    Number(mi),
  );
  return Number.isNaN(date.getTime()) ? null : date;
}

// Serializes a Date back into the `datetime-local` string the form expects.
function formatValue(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formatDisplay(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function sameDay(a: Date, b: Date) {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

interface DateTimePickerProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}

function DateTimePicker({
  value,
  onChange,
  placeholder = "选择日期",
  className,
}: DateTimePickerProps) {
  const [open, setOpen] = React.useState(false);
  const selected = React.useMemo(() => parseValue(value), [value]);

  // The month currently shown in the calendar grid; tracks the selected
  // value but stays independent so navigation does not mutate the filter.
  const [viewDate, setViewDate] = React.useState<Date>(
    () => selected ?? new Date(),
  );

  const handleOpenChange = (next: boolean) => {
    if (next) {
      setViewDate(selected ?? new Date());
    }
    setOpen(next);
  };

  const commit = React.useCallback(
    (next: Date) => {
      onChange(formatValue(next));
    },
    [onChange],
  );

  const handleDayClick = (day: Date) => {
    const base = selected ?? new Date(day);
    const next = new Date(
      day.getFullYear(),
      day.getMonth(),
      day.getDate(),
      selected ? base.getHours() : 0,
      selected ? base.getMinutes() : 0,
    );
    commit(next);
  };

  const handleTimeChange = (part: "h" | "m", raw: string) => {
    const digits = raw.replace(/\D/g, "");
    if (!digits) return;
    const num = Number(digits);
    const base = selected ?? viewDate;
    const next = new Date(
      base.getFullYear(),
      base.getMonth(),
      base.getDate(),
      part === "h" ? Math.min(23, Math.max(0, num)) : base.getHours(),
      part === "m" ? Math.min(59, Math.max(0, num)) : base.getMinutes(),
    );
    commit(next);
  };

  const goToToday = () => {
    const now = new Date();
    setViewDate(now);
    commit(now);
  };

  const clear = (event: React.MouseEvent) => {
    event.stopPropagation();
    onChange("");
  };

  const monthStart = new Date(
    viewDate.getFullYear(),
    viewDate.getMonth(),
    1,
  );
  const gridStart = new Date(monthStart);
  gridStart.setDate(1 - monthStart.getDay());

  const days = Array.from({ length: 42 }, (_, index) => {
    const day = new Date(gridStart);
    day.setDate(gridStart.getDate() + index);
    return day;
  });

  const today = new Date();

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <button
          type="button"
          data-slot="datetime-trigger"
          className={cn(
            "flex h-8 w-full min-w-0 items-center gap-2 rounded-lg border border-input bg-transparent px-2.5 py-1 text-left text-sm transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 aria-expanded:border-ring dark:bg-input/30",
            className,
          )}
        >
          <CalendarDays className="size-3.5 shrink-0 text-muted-foreground" />
          <span
            className={cn(
              "flex-1 truncate font-mono",
              !selected && "text-muted-foreground",
            )}
          >
            {selected ? formatDisplay(selected) : placeholder}
          </span>
          {selected ? (
            <span
              role="button"
              tabIndex={-1}
              aria-label="清除"
              onClick={clear}
              className="grid size-4 shrink-0 place-items-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <X className="size-3" />
            </span>
          ) : null}
        </button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-auto gap-3 p-3"
        onOpenAutoFocus={(event) => event.preventDefault()}
      >
        <div className="flex items-center justify-between">
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label="上个月"
            onClick={() =>
              setViewDate(
                new Date(
                  viewDate.getFullYear(),
                  viewDate.getMonth() - 1,
                  1,
                ),
              )
            }
          >
            <ChevronLeft />
          </Button>
          <span className="text-sm font-medium">
            {viewDate.getFullYear()}年{viewDate.getMonth() + 1}月
          </span>
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label="下个月"
            onClick={() =>
              setViewDate(
                new Date(
                  viewDate.getFullYear(),
                  viewDate.getMonth() + 1,
                  1,
                ),
              )
            }
          >
            <ChevronRight />
          </Button>
        </div>

        <div className="grid grid-cols-7 gap-0.5">
          {WEEKDAYS.map((label) => (
            <div
              key={label}
              className="grid h-7 place-items-center text-xs text-muted-foreground"
            >
              {label}
            </div>
          ))}
          {days.map((day) => {
            const inMonth = day.getMonth() === viewDate.getMonth();
            const isSelected = selected ? sameDay(day, selected) : false;
            const isToday = sameDay(day, today);
            return (
              <button
                type="button"
                key={day.toISOString()}
                onClick={() => handleDayClick(day)}
                className={cn(
                  "grid h-7 w-8 place-items-center rounded-md font-mono text-xs transition-colors",
                  !inMonth && "text-muted-foreground/40",
                  inMonth && !isSelected && "hover:bg-muted",
                  isSelected &&
                    "bg-primary font-medium text-primary-foreground hover:bg-primary/85",
                  !isSelected &&
                    isToday &&
                    "ring-1 ring-inset ring-primary/40",
                )}
              >
                {day.getDate()}
              </button>
            );
          })}
        </div>

        <div className="flex items-center justify-between border-t border-border pt-2.5">
          <span className="text-xs text-muted-foreground">时间</span>
          <div className="flex items-center gap-1 font-mono text-sm">
            <input
              inputMode="numeric"
              aria-label="时"
              value={selected ? pad(selected.getHours()) : "--"}
              onChange={(event) => handleTimeChange("h", event.target.value)}
              className="h-7 w-9 rounded-md border border-input bg-transparent text-center outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            />
            <span className="text-muted-foreground">:</span>
            <input
              inputMode="numeric"
              aria-label="分"
              value={selected ? pad(selected.getMinutes()) : "--"}
              onChange={(event) => handleTimeChange("m", event.target.value)}
              className="h-7 w-9 rounded-md border border-input bg-transparent text-center outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 dark:bg-input/30"
            />
          </div>
        </div>

        <div className="flex items-center justify-between">
          <Button
            type="button"
            variant="ghost"
            size="xs"
            onClick={() => onChange("")}
          >
            清空
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="xs"
            onClick={goToToday}
          >
            此刻
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

export { DateTimePicker };
