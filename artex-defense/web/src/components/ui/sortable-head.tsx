"use client";

import { ArrowDownIcon, ArrowUpDownIcon, ArrowUpIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import type * as React from "react";

import { TableHead } from "@/components/ui/table";
import type { SortDirection } from "@/lib/sort-preference";
import { cn } from "@/lib/utils";

// SortableHead is a table header cell that toggles a column's sort on click.
// It renders a neutral up/down glyph when inactive and a directional arrow when
// its field is the active sort, mirroring the pattern first used on the tasks
// table so sortable columns look and behave the same across the app.
export function SortableHead<Field extends string>({
  field,
  label,
  activeField,
  direction,
  align = "left",
  className,
  onSort,
}: {
  field: Field;
  label: string;
  activeField: Field | null;
  direction: SortDirection;
  align?: "left" | "right";
  className?: string;
  onSort: (field: Field) => void;
}) {
  const t = useTranslations("sortableHead");
  const active = activeField === field;
  let ariaSort: React.AriaAttributes["aria-sort"] = "none";
  if (active) ariaSort = direction === "asc" ? "ascending" : "descending";

  let actionLabel = t("sortBy", { label });
  if (active) actionLabel = t("active", { label, direction });

  let icon = <ArrowUpDownIcon className="size-3.5 opacity-40 transition-opacity group-hover/sort:opacity-100" />;
  if (active) icon = direction === "asc" ? <ArrowUpIcon className="size-3.5" /> : <ArrowDownIcon className="size-3.5" />;

  return (
    <TableHead className={className} aria-sort={ariaSort}>
      <button
        type="button"
        className={cn(
          "group/sort inline-flex h-full w-full items-center gap-1 outline-none focus-visible:underline",
          align === "right" && "justify-end",
        )}
        aria-label={actionLabel}
        onClick={() => onSort(field)}
      >
        <span>{label}</span>
        {icon}
      </button>
    </TableHead>
  );
}
