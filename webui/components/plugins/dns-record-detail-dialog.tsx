"use client";

import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

export interface DnsQuestionView {
  name: string;
  qtype: string;
  qclass: string;
}

export interface DnsRecordPayloadView {
  name: string;
  class: string;
  ttl: number;
  rr_type: string;
  payload_kind: string;
  payload_text: string;
}

export interface DnsRecordStepView {
  event_index: number;
  sequence_tag: string;
  node_index?: number;
  kind: string;
  tag?: string;
  outcome: string;
}

export interface DnsDetailItem {
  label: string;
  value: ReactNode;
  title?: string;
  mono?: boolean;
  wide?: boolean;
}

export interface DnsRecordSection {
  title: string;
  records: DnsRecordPayloadView[];
  emptyLabel?: string;
}

export interface DnsDetailBlock {
  title: string;
  children: ReactNode;
}

interface DnsRecordDetailDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  subtitle?: string;
  status?: ReactNode;
  summaryItems: DnsDetailItem[];
  questions?: DnsQuestionView[];
  sections?: DnsRecordSection[];
  steps?: DnsRecordStepView[];
  leadingBlocks?: DnsDetailBlock[];
  blocks?: DnsDetailBlock[];
  bottomBlocks?: DnsDetailBlock[];
  error?: string | null;
  wide?: boolean;
}

export function DnsRecordDetailDialog({
  open,
  onOpenChange,
  title,
  subtitle,
  status,
  summaryItems,
  questions = [],
  sections = [],
  steps = [],
  leadingBlocks = [],
  blocks = [],
  bottomBlocks = [],
  error,
  wide = false,
}: DnsRecordDetailDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className={cn(
          "flex max-h-[85vh] flex-col gap-0 overflow-hidden p-0",
          wide ? "sm:max-w-6xl xl:max-w-7xl" : "sm:max-w-4xl",
        )}
      >
        <DialogHeader className="px-4 pt-4 pr-12 pb-3">
          <div className="flex min-w-0 items-start justify-between gap-3">
            <div className="min-w-0">
              <DialogTitle className="truncate">{title}</DialogTitle>
              <DialogDescription className="sr-only">
                {subtitle ? `${title}，${subtitle}` : title}
              </DialogDescription>
              {subtitle && (
                <div className="mt-1 truncate text-xs text-muted-foreground">
                  {subtitle}
                </div>
              )}
            </div>
            {status}
          </div>
        </DialogHeader>

        <div className="oxidns-dialog-scrollbar min-h-0 flex-1 overflow-y-auto px-4 pb-4 pr-2">
          <div className="space-y-4 pr-2 text-sm">
            {summaryItems.length > 0 && (
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {summaryItems.map((item) => (
                  <DetailItem key={item.label} item={item} />
                ))}
              </div>
            )}

            {questions.length > 0 && (
              <DetailBlock title="Question">
                <div className="space-y-2">
                  {questions.map((question, index) => (
                    <div
                      key={`${question.name}-${question.qtype}-${index}`}
                      className="flex min-w-0 flex-wrap items-center gap-2 rounded-md border bg-muted/20 px-3 py-2"
                    >
                      <span
                        className="min-w-0 flex-1 truncate font-mono"
                        title={question.name}
                      >
                        {question.name}
                      </span>
                      <Badge variant="outline" className="font-mono">
                        {question.qclass}
                      </Badge>
                      <Badge variant="secondary" className="font-mono">
                        {question.qtype}
                      </Badge>
                    </div>
                  ))}
                </div>
              </DetailBlock>
            )}

            {leadingBlocks.map((block) => (
              <DetailBlock key={block.title} title={block.title}>
                {block.children}
              </DetailBlock>
            ))}

            {sections.map((section) => (
              <DetailBlock key={section.title} title={section.title}>
                {section.records.length ? (
                  <div className="space-y-2">
                    {section.records.map((record, index) => (
                      <DnsPayloadRow
                        key={`${record.name}-${record.rr_type}-${index}`}
                        record={record}
                      />
                    ))}
                  </div>
                ) : (
                  <span className="text-muted-foreground">
                    {section.emptyLabel ?? "无记录"}
                  </span>
                )}
              </DetailBlock>
            ))}

            {steps.length > 0 && (
              <DetailBlock title="Sequence Steps">
                <div className="space-y-2">
                  {steps.map((step) => (
                    <div
                      key={step.event_index}
                      className="grid gap-2 rounded-md border bg-muted/20 px-3 py-2 font-mono text-xs sm:grid-cols-[4rem_1fr_auto]"
                    >
                      <span className="text-muted-foreground">
                        #{step.event_index}
                      </span>
                      <span className="min-w-0 truncate">
                        {step.sequence_tag}
                        {typeof step.node_index === "number"
                          ? ` / ${step.node_index}`
                          : ""}
                      </span>
                      <span className="flex flex-wrap items-center gap-1">
                        <Badge variant="outline" className="font-mono">
                          {step.kind}
                          {step.tag ? `:${step.tag}` : ""}
                        </Badge>
                        <Badge variant="secondary" className="font-mono">
                          {step.outcome}
                        </Badge>
                      </span>
                    </div>
                  ))}
                </div>
              </DetailBlock>
            )}

            {blocks.map((block) => (
              <DetailBlock key={block.title} title={block.title}>
                {block.children}
              </DetailBlock>
            ))}

            {error && (
              <DetailBlock title="Error">
                <span className="text-destructive">{error}</span>
              </DetailBlock>
            )}

            {bottomBlocks.map((block) => (
              <DetailBlock key={block.title} title={block.title}>
                {block.children}
              </DetailBlock>
            ))}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function DetailItem({ item }: { item: DnsDetailItem }) {
  return (
    <div
      className={cn(
        "min-w-0 rounded-md border bg-muted/20 px-3 py-2",
        item.wide && "sm:col-span-2",
      )}
    >
      <div className="text-xs text-muted-foreground">{item.label}</div>
      <div
        className={cn("mt-1 truncate", item.mono && "font-mono")}
        title={item.title}
      >
        {item.value}
      </div>
    </div>
  );
}

function DetailBlock({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function DnsPayloadRow({ record }: { record: DnsRecordPayloadView }) {
  return (
    <div className="rounded-md border bg-muted/20 px-3 py-2">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 truncate font-mono" title={record.name}>
          {record.name}
        </span>
        <Badge variant="outline" className="font-mono">
          {record.class}
        </Badge>
        <Badge variant="secondary" className="font-mono">
          {record.rr_type}
        </Badge>
        <Badge variant="outline" className="font-mono">
          TTL {record.ttl}s
        </Badge>
      </div>
      <div
        className="mt-1 break-words font-mono text-xs text-muted-foreground"
        title={record.payload_text}
      >
        {record.payload_text || record.payload_kind}
      </div>
    </div>
  );
}
