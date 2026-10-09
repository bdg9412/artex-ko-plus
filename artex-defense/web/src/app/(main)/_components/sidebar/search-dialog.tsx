"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { Search } from "lucide-react";
import { useTranslations } from "next-intl";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import type { NavMainItem } from "@/navigation/sidebar/sidebar-items";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";

// 표시 문자열은 데이터에 담지 않고 nav 네임스페이스 키만 담아 둔다. 실제 라벨·헤딩은
// 컴포넌트에서 useTranslations("nav") 로 렌더 시점에 번역한다(사이드바와 같은 메시지 원천).
type SearchItem = {
  id: string;
  headingKey: string; // nav 기준 상대 키 (그룹 헤딩). 예) "group.function"
  labelKey: string; // nav 기준 상대 키 (항목 라벨). 예) "item.dashboard"
  fallbackLabel: string; // 메시지에 키가 없을 때 쓸 원문
  url: string;
  icon?: NavMainItem["icon"];
  disabled?: boolean;
  newTab?: boolean;
};

// 그룹 번호 → nav.group.* 키. nav-main 과 같은 매핑을 쓴다.
const GROUP_MESSAGE_KEY: Record<number, string> = { 1: "function", 2: "system" };
function groupHeadingKey(groupId: number): string {
  const k = GROUP_MESSAGE_KEY[groupId];
  return k ? `group.${k}` : `group.${groupId}`;
}

const searchItems: SearchItem[] = sidebarItems.flatMap((group) => {
  const headingKey = groupHeadingKey(group.id);
  return group.items.flatMap((item) => {
    if (item.subItems) {
      return item.subItems.map((sub) => ({
        id: sub.id,
        headingKey,
        labelKey: `item.${sub.id}`,
        fallbackLabel: sub.title,
        url: sub.url,
        icon: item.icon,
        disabled: sub.disabled,
        newTab: sub.newTab,
      }));
    }
    return [
      {
        id: item.id,
        headingKey,
        labelKey: `item.${item.id}`,
        fallbackLabel: item.title,
        url: item.url,
        icon: item.icon,
        disabled: item.disabled,
        newTab: item.newTab,
      },
    ];
  });
});

function getAvailableItems(items: SearchItem[]) {
  return items.filter((item) => !item.disabled && !item.url.includes("coming-soon"));
}

const recommendations = getAvailableItems(searchItems);

function groupBy(items: SearchItem[]) {
  const headings = [...new Set(items.map((item) => item.headingKey))];
  return headings.map((headingKey) => ({
    headingKey,
    items: items.filter((item) => item.headingKey === headingKey),
  }));
}

export function SearchDialog() {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const router = useRouter();
  const t = useTranslations("search");
  const tNav = useTranslations("nav");
  const labelOf = (item: SearchItem) => (tNav.has(item.labelKey) ? tNav(item.labelKey) : item.fallbackLabel);

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "j" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const handleOpenChange = (value: boolean) => {
    setOpen(value);
    if (!value) setQuery("");
  };

  const handleSelect = (item: SearchItem) => {
    if (item.disabled) return;
    handleOpenChange(false);
    if (item.newTab) {
      window.open(item.url, "_blank", "noopener,noreferrer");
    } else {
      router.push(item.url);
    }
  };

  const renderGroups = (items: SearchItem[]) =>
    groupBy(items).map(({ headingKey, items: groupItems }, index) => {
      const heading = tNav(headingKey);
      return (
        <React.Fragment key={headingKey}>
          {index > 0 && <CommandSeparator />}
          <CommandGroup heading={heading}>
            {groupItems.map((item) => (
              <CommandItem
                disabled={item.disabled}
                key={`${headingKey}-${item.id}`}
                value={`${heading} ${labelOf(item)}`}
                onSelect={() => handleSelect(item)}
              >
                <span className="flex min-w-0 items-center gap-2">
                  {item.icon && <item.icon />}
                  <span className="truncate">{labelOf(item)}</span>
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        </React.Fragment>
      );
    });

  return (
    <>
      <Button
        onClick={() => handleOpenChange(true)}
        variant="link"
        className="px-0! font-normal text-muted-foreground hover:no-underline"
      >
        <Search data-icon="inline-start" />
        {t("button")}
        <kbd className="inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-medium text-[10px]">
          <span className="text-xs">⌘</span>J
        </kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={handleOpenChange}>
        <Command>
          <CommandInput placeholder={t("placeholder")} value={query} onValueChange={setQuery} />
          <CommandList>
            <CommandEmpty>{t("empty")}</CommandEmpty>
            {query ? renderGroups(searchItems) : renderGroups(recommendations)}
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  );
}
