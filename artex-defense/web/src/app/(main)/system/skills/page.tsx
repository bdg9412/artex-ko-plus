"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  ChevronRightIcon,
  FilePlusIcon,
  FileTextIcon,
  FolderIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  PlusIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Agent, MCPServer, MissingSkill, SkillCall, SkillItem } from "@/lib/types";
import { cn } from "@/lib/utils";

function fmtTime(ts: string | undefined, never: string) {
  if (!ts) return never;
  return new Date(ts).toLocaleString("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ── Tree node ──────────────────────────────────────────────────────────────
interface TreeNode {
  name: string;
  path: string; // relative to skill root, dirs WITHOUT trailing slash
  type: "file" | "dir";
  children: TreeNode[];
}

// Backend returns dirs as "scripts/" (trailing slash) and files as "scripts/a.py".
function buildTree(entries: string[]): TreeNode[] {
  const root: TreeNode[] = [];
  const dirMap = new Map<string, TreeNode>();

  function ensureDir(dirPath: string, parentNodes: TreeNode[]): TreeNode[] {
    if (dirMap.has(dirPath)) return dirMap.get(dirPath)!.children;
    const parts = dirPath.split("/");
    let nodes = root;
    let cur = "";
    for (const part of parts) {
      cur = cur ? `${cur}/${part}` : part;
      if (!dirMap.has(cur)) {
        const d: TreeNode = { name: part, path: cur, type: "dir", children: [] };
        nodes.push(d);
        dirMap.set(cur, d);
      }
      nodes = dirMap.get(cur)!.children;
    }
    return nodes;
  }

  for (const entry of [...entries].sort()) {
    if (entry.endsWith("/")) {
      // Explicit directory entry — ensure the node exists (may already be created)
      ensureDir(entry.slice(0, -1), root);
    } else {
      // File — ensure parent dirs exist, then push file node
      const parts = entry.split("/");
      let nodes = root;
      let cur = "";
      for (let i = 0; i < parts.length - 1; i++) {
        cur = cur ? `${cur}/${parts[i]}` : parts[i];
        if (!dirMap.has(cur)) {
          const d: TreeNode = { name: parts[i], path: cur, type: "dir", children: [] };
          nodes.push(d);
          dirMap.set(cur, d);
        }
        nodes = dirMap.get(cur)!.children;
      }
      const fname = parts[parts.length - 1];
      if (fname) nodes.push({ name: fname, path: entry, type: "file", children: [] });
    }
  }
  sortNodes(root);
  return root;
}

// sortNodes orders every level like a file explorer: directories before files,
// then case-insensitive by name. Recurses into children.
function sortNodes(nodes: TreeNode[]): void {
  nodes.sort((a, b) => {
    if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
  });
  for (const n of nodes) {
    if (n.children.length > 0) sortNodes(n.children);
  }
}

// ── State types ───────────────────────────────────────────────────────────
type Selected = { skill: string; path: null } | { skill: string; path: string };

type Creating = {
  skill: string;
  inDir: string;
  kind: "file" | "dir";
} | null;

type PendingDelete =
  | { kind: "skill"; skill: string }
  | { kind: "file"; skill: string; path: string }
  | { kind: "dir"; skill: string; path: string }
  | null;

// ── Overview (empty-state) ──────────────────────────────────────────────────
// Shown when nothing is selected: a library-wide snapshot from data already loaded
// (the skill list carries per-skill usage; missing is fetched alongside). No extra
// requests — this is pure aggregation over props.
function SkillsOverview({
  skills,
  missing,
  onSelect,
}: {
  skills: SkillItem[];
  missing: MissingSkill[];
  onSelect: (name: string) => void;
}) {
  const t = useTranslations("skillsPage");
  const agg = React.useMemo(() => {
    const totalCalls = skills.reduce((n, s) => n + s.calls, 0);
    const used = skills.filter((s) => s.calls > 0);
    const ranked = [...used].sort((a, b) => b.calls - a.calls);
    const neverUsed = skills.filter((s) => s.calls === 0);
    const recent = skills
      .filter((s) => s.last_used)
      .sort((a, b) => (a.last_used! < b.last_used! ? 1 : -1))
      .slice(0, 6);
    const missingCalls = missing.reduce((n, m) => n + m.calls, 0);
    return {
      totalCalls,
      usedCount: used.length,
      ranked,
      topCalls: ranked[0]?.calls ?? 0,
      neverUsed,
      recent,
      missingCalls,
    };
  }, [skills, missing]);

  if (skills.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-muted-foreground">{t("emptyOverview")}</p>
      </div>
    );
  }

  const stats: { label: string; value: React.ReactNode; hint?: string }[] = [
    { label: t("statTotal"), value: skills.length, hint: t("statTotalHint", { count: agg.usedCount }) },
    { label: t("statCalls"), value: agg.totalCalls },
    {
      label: t("statUnused"),
      value: agg.neverUsed.length,
      hint: agg.neverUsed.length > 0 ? t("statUnusedHintSome") : t("statUnusedHintNone"),
    },
    {
      label: t("statMissing"),
      value: agg.missingCalls,
      hint: missing.length > 0 ? t("statMissingHintSome", { count: missing.length }) : t("statMissingHintNone"),
    },
  ];

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6">
      <div>
        <h2 className="text-base font-semibold">{t("overviewTitle")}</h2>
        <p className="text-muted-foreground text-sm">{t("overviewDesc")}</p>
      </div>

      {/* 指标卡 */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {stats.map((s) => (
          <div key={s.label} className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{s.value}</p>
            <p className="text-xs font-medium">{s.label}</p>
            {s.hint && <p className="text-muted-foreground mt-0.5 text-[11px]">{s.hint}</p>}
          </div>
        ))}
      </div>

      {/* 调用排行 */}
      <div className="space-y-2">
        <Label className="text-xs text-muted-foreground">{t("ranking")}</Label>
        {agg.ranked.length === 0 ? (
          <p className="text-muted-foreground rounded-lg border border-dashed p-4 text-center text-xs">
            {t("rankingEmpty")}
          </p>
        ) : (
          <div className="space-y-1.5">
            {agg.ranked.slice(0, 8).map((s) => (
              <button
                key={s.name}
                type="button"
                onClick={() => onSelect(s.name)}
                className="group flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left hover:bg-muted"
              >
                <span className="w-40 shrink-0 truncate font-mono text-xs" title={s.name}>
                  {s.name}
                </span>
                <span className="relative h-2 flex-1 overflow-hidden rounded-full bg-muted">
                  <span
                    className="absolute inset-y-0 left-0 rounded-full bg-primary/70"
                    style={{ width: `${agg.topCalls > 0 ? (s.calls / agg.topCalls) * 100 : 0}%` }}
                  />
                </span>
                <span className="w-16 shrink-0 text-right text-xs tabular-nums text-muted-foreground">
                  {t("callsCount", { count: s.calls })}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="grid gap-6 sm:grid-cols-2">
        {/* 最近调用 */}
        <div className="space-y-2">
          <Label className="text-xs text-muted-foreground">{t("recent")}</Label>
          {agg.recent.length === 0 ? (
            <p className="text-muted-foreground text-xs">{t("recentEmpty")}</p>
          ) : (
            <div className="space-y-1">
              {agg.recent.map((s) => (
                <button
                  key={s.name}
                  type="button"
                  onClick={() => onSelect(s.name)}
                  className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-muted"
                >
                  <span className="min-w-0 flex-1 truncate font-mono text-xs" title={s.name}>
                    {s.name}
                  </span>
                  <span className="shrink-0 text-[11px] tabular-nums text-muted-foreground">
                    {fmtTime(s.last_used, t("neverCalled"))}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 未使用（可清理 / 需曝光） */}
        <div className="space-y-2">
          <Label className="text-xs text-muted-foreground">
            {t("unusedSkills")}
            {agg.neverUsed.length > 0 && <span className="ml-1 font-normal">({agg.neverUsed.length})</span>}
          </Label>
          {agg.neverUsed.length === 0 ? (
            <p className="text-muted-foreground text-xs">{t("allUsed")}</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {agg.neverUsed.map((s) => (
                <button key={s.name} type="button" onClick={() => onSelect(s.name)} title={s.name}>
                  <Badge
                    variant="outline"
                    className="max-w-[12rem] cursor-pointer truncate font-mono text-xs font-normal hover:bg-muted"
                  >
                    {s.name}
                  </Badge>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────
export default function SkillsPage() {
  const t = useTranslations("skillsPage");
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [selected, setSelected] = React.useState<Selected | null>(null);
  const [visibility, setVisibility] = React.useState<Record<string, string[]>>({});
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());

  // file editor
  const [fileContent, setFileContent] = React.useState("");
  const [fileLoading, setFileLoading] = React.useState(false);
  const [dirty, setDirty] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  // inline create — using a ref to avoid stale closure in onBlur
  const [creating, setCreating] = React.useState<Creating>(null);
  const [newEntryName, setNewEntryName] = React.useState("");
  const inlineRef = React.useRef<HTMLInputElement>(null);
  // cancelRef prevents onBlur from committing when Escape was pressed
  const cancelRef = React.useRef(false);

  // new skill dialog
  const [newOpen, setNewOpen] = React.useState(false);
  const [newName, setNewName] = React.useState("");
  const [newDesc, setNewDesc] = React.useState("");
  const [newLicense, setNewLicense] = React.useState("");
  const [newCompat, setNewCompat] = React.useState("");
  const [newInst, setNewInst] = React.useState("");
  const [newMcps, setNewMcps] = React.useState<string[]>([]);
  const [newVisibility, setNewVisibility] = React.useState<string[]>([]);
  const [mcpOptions, setMcpOptions] = React.useState<MCPServer[]>([]);
  const [creatingSkill, setCreatingSkill] = React.useState(false);
  const [uploading, setUploading] = React.useState(false);
  const uploadRef = React.useRef<HTMLInputElement>(null);

  // skill detail — MCP edit state (optimistic, rolls back on error)
  const [detailMcps, setDetailMcps] = React.useState<string[]>([]);

  // delete confirmation
  const [pendingDelete, setPendingDelete] = React.useState<PendingDelete>(null);
  const [deleting, setDeleting] = React.useState(false);

  // 调用统计：列表页的次数/最近调用随 api.skills() 一起回来；选中某个 skill 时再拉它的
  // 最近调用明细。missing = 被点名但不存在的 skill（想用但没有）。
  const [usageCalls, setUsageCalls] = React.useState<SkillCall[]>([]);
  const [usageLoading, setUsageLoading] = React.useState(false);
  const [missing, setMissing] = React.useState<MissingSkill[]>([]);

  // ── Data ──────────────────────────────────────────────────────────────────
  const load = React.useCallback(() => {
    api
      .agents()
      .then(setAgents)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
    api
      .mcpServers()
      .then(setMcpOptions)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
    api
      .missingSkills()
      .then(setMissing)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
    api
      .skills()
      .then((ss) => {
        setSkills(ss);
        ss.forEach((s) => {
          void api
            .skillVisibility(s.name)
            .then((ids) => setVisibility((v) => ({ ...v, [s.name]: ids })))
            .catch(() => {
              /* 가시성 조회 실패는 무시한다 */
            });
        });
      })
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  // ── Upload a .zip skill ───────────────────────────────────────────────────
  async function uploadZip(file: File, overwrite = false) {
    setUploading(true);
    try {
      const r = await api.uploadSkill(file, overwrite);
      toast.success(t("installed", { name: r.name, files: r.files }));
      load();
    } catch (e) {
      const msg = (e as Error).message;
      // offer overwrite when the skill already exists
      // (server_mgmt.go errMgmtSkillExistsPre 와 짝 맞춘 교차 스택 마커)
      if (!overwrite && msg.includes("이미 존재")) {
        if (window.confirm(t("overwriteConfirm", { msg }))) {
          await uploadZip(file, true);
          return;
        }
      } else {
        toast.error(t("uploadFailed", { msg }));
      }
    } finally {
      setUploading(false);
    }
  }
  function onUploadPick(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = ""; // reset so picking the same file again re-fires
    if (f) void uploadZip(f);
  }

  React.useEffect(() => {
    if (creating) {
      // Small timeout so the element is actually in the DOM before focusing
      setTimeout(() => inlineRef.current?.focus(), 20);
    }
  }, [creating]);

  // Sync detail-panel MCP state when the selected skill changes.
  React.useEffect(() => {
    if (!selected || selected.path !== null) return;
    const sk = skills.find((s) => s.name === selected.skill);
    setDetailMcps(sk?.mcps ?? []);
  }, [selected, skills]);

  // Recent calls for the selected skill (detail panel only).
  React.useEffect(() => {
    if (!selected || selected.path !== null) {
      setUsageCalls([]);
      return;
    }
    const name = selected.skill;
    setUsageLoading(true);
    api
      .skillUsage(name, 20)
      .then((calls) => setUsageCalls(calls))
      .catch(() => setUsageCalls([]))
      .finally(() => setUsageLoading(false));
  }, [selected]);

  React.useEffect(() => {
    if (!selected || selected.path === null) {
      setFileContent("");
      setDirty(false);
      return;
    }
    setFileLoading(true);
    api
      .readSkillFile(selected.skill, selected.path)
      .then((c) => {
        setFileContent(c);
        setDirty(false);
      })
      .catch(() => toast.error(t("readFileFailed")))
      .finally(() => setFileLoading(false));
  }, [selected, t]);

  // ── Expand helpers ────────────────────────────────────────────────────────
  function toggleExpanded(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }
  function ensureExpanded(skill: string, dirPath: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.add(skill);
      if (dirPath) {
        let cur = "";
        for (const part of dirPath.split("/")) {
          cur = cur ? `${cur}/${part}` : part;
          next.add(`${skill}:${cur}`);
        }
      }
      return next;
    });
  }

  // ── Inline create ─────────────────────────────────────────────────────────
  function startCreate(skill: string, inDir: string, kind: "file" | "dir") {
    cancelRef.current = false;
    ensureExpanded(skill, inDir);
    setCreating({ skill, inDir, kind });
    setNewEntryName("");
  }

  // Use a ref snapshot so commitCreate reads the latest creating value
  // without depending on potentially stale closure state.
  const creatingRef = React.useRef<Creating>(null);
  React.useEffect(() => {
    creatingRef.current = creating;
  }, [creating]);
  const newEntryRef = React.useRef("");
  React.useEffect(() => {
    newEntryRef.current = newEntryName;
  }, [newEntryName]);

  async function commitCreate() {
    if (cancelRef.current) {
      cancelRef.current = false;
      return;
    }
    const c = creatingRef.current;
    const name = newEntryRef.current.trim();
    setCreating(null);
    setNewEntryName("");
    if (!c || !name) return;

    const fullPath = c.inDir ? `${c.inDir}/${name}` : name;
    try {
      if (c.kind === "dir") {
        await api.createSkillDir(c.skill, fullPath);
        toast.success(t("folderCreated", { path: fullPath }));
        ensureExpanded(c.skill, fullPath);
      } else {
        await api.writeSkillFile(c.skill, fullPath, "");
        toast.success(t("fileCreated", { path: fullPath }));
        setSelected({ skill: c.skill, path: fullPath });
        ensureExpanded(c.skill, c.inDir);
      }
      load();
    } catch (e) {
      toast.error(t("createFailed", { msg: (e as Error).message }));
    }
  }

  function cancelCreate() {
    cancelRef.current = true;
    setCreating(null);
    setNewEntryName("");
  }

  async function deletePath(skill: string, path: string) {
    try {
      await api.deleteSkillPath(skill, path);
      toast.success(t("deleted", { path }));
      if (selected?.skill === skill && selected.path === path) setSelected(null);
      load();
    } catch (e) {
      toast.error(t("deleteFailed", { msg: (e as Error).message }));
    }
  }

  async function deleteSkill(name: string) {
    try {
      await api.deleteSkill(name);
      toast.success(t("skillDeleted", { name }));
      if (selected?.skill === name) setSelected(null);
      load();
    } catch (e) {
      toast.error(t("deleteFailed", { msg: (e as Error).message }));
    }
  }

  async function runPendingDelete() {
    const p = pendingDelete;
    if (!p) return;
    setDeleting(true);
    try {
      if (p.kind === "skill") await deleteSkill(p.skill);
      else await deletePath(p.skill, p.path);
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  }

  async function saveFile() {
    if (!selected || selected.path === null) return;
    setSaving(true);
    try {
      await api.writeSkillFile(selected.skill, selected.path, fileContent);
      toast.success(t("saved"));
      setDirty(false);
    } catch (e) {
      toast.error(t("saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  async function toggleSkillMcp(skillName: string, mcpName: string, mcpOn: boolean) {
    const next = mcpOn ? [...detailMcps, mcpName] : detailMcps.filter((n) => n !== mcpName);
    setDetailMcps(next);
    try {
      await api.updateSkillMeta(skillName, { mcps: next });
      toast.success(mcpOn ? t("mcpLinked", { name: mcpName }) : t("mcpUnlinked", { name: mcpName }));
      load();
    } catch (e) {
      // roll back on error
      setDetailMcps(detailMcps);
      toast.error(t("opFailed", { msg: (e as Error).message }));
    }
  }

  async function toggleVisibility(skillName: string, agentId: string, agentName: string) {
    const on = (visibility[skillName] ?? []).includes(agentId);
    try {
      await api.toggleSkillVisibility(agentId, skillName, !on);
      toast.success(on ? t("visRevoked", { name: agentName }) : t("visGranted", { name: agentName }));
      const ids = await api.skillVisibility(skillName);
      setVisibility((v) => ({ ...v, [skillName]: ids }));
    } catch (e) {
      toast.error(t("opFailed", { msg: (e as Error).message }));
    }
  }

  async function createNewSkill() {
    if (!newName.trim()) {
      toast.error(t("needName"));
      return;
    }
    if (!newDesc.trim()) {
      toast.error(t("needDesc"));
      return;
    }
    setCreatingSkill(true);
    try {
      const name = newName.trim();
      await api.createSkill({
        name,
        description: newDesc.trim(),
        license: newLicense.trim() || undefined,
        compatibility: newCompat.trim() || undefined,
        mcps: newMcps.length ? newMcps : undefined,
        instructions: newInst.trim() || undefined,
      });
      // apply initial visibility (fire-and-forget per agent; best-effort)
      await Promise.all(newVisibility.map((id) => api.toggleSkillVisibility(id, name, true)));
      toast.success(t("skillCreated"));
      setNewOpen(false);
      setNewName("");
      setNewDesc("");
      setNewLicense("");
      setNewCompat("");
      setNewInst("");
      setNewMcps([]);
      setNewVisibility([]);
      load();
    } catch (e) {
      toast.error(t("createFailed", { msg: (e as Error).message }));
    } finally {
      setCreatingSkill(false);
    }
  }

  // ── Inline input JSX helper (NOT a React component — avoids remount on re-render) ──
  // Defined as a plain function returning JSX so React never sees a new component type.
  function inlineInputJSX(indent: number) {
    return (
      <div key="__inline_create__" className="flex items-center gap-1 py-0.5 pr-2" style={{ paddingLeft: indent }}>
        {creating?.kind === "dir" ? (
          <FolderIcon className="size-3.5 shrink-0 text-amber-500" />
        ) : (
          <FileTextIcon className="size-3.5 shrink-0 text-muted-foreground" />
        )}
        <Input
          ref={inlineRef}
          className="h-6 flex-1 px-1 py-0 font-mono text-xs"
          placeholder={creating?.kind === "dir" ? "folder-name" : "filename.py"}
          value={newEntryName}
          onChange={(e) => setNewEntryName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              cancelRef.current = false;
              void commitCreate();
            }
            if (e.key === "Escape") cancelCreate();
          }}
          onBlur={() => {
            void commitCreate();
          }}
        />
      </div>
    );
  }

  // ── Recursive tree renderer ───────────────────────────────────────────────
  function renderTree(nodes: TreeNode[], skill: string, depth: number): React.ReactNode {
    // depth+1: the skill root sits at 8px (px-2); its children indent one step
    // further in so the tree reads as nested under the skill folder.
    const baseIndent = 8 + (depth + 1) * 14;
    return nodes.map((node) => {
      if (node.type === "dir") {
        const key = `${skill}:${node.path}`;
        const open = expanded.has(key);
        return (
          <div key={node.path}>
            <div
              role="treeitem"
              tabIndex={0}
              aria-expanded={open}
              className="group relative flex cursor-pointer select-none items-center gap-1 rounded py-0.5 pr-1 text-sm hover:bg-muted"
              style={{ paddingLeft: baseIndent }}
              onClick={() => toggleExpanded(key)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggleExpanded(key);
                }
              }}
            >
              <ChevronRightIcon className={cn("size-3.5 shrink-0 transition-transform", open && "rotate-90")} />
              {open ? (
                <FolderOpenIcon className="size-3.5 shrink-0 text-amber-500" />
              ) : (
                <FolderIcon className="size-3.5 shrink-0 text-amber-500" />
              )}
              <span className="min-w-0 flex-1 truncate" title={node.path}>
                {node.name}
              </span>
              {/* Absolute so a long name can never push the actions out of view */}
              <span className="absolute inset-y-0 right-1 hidden items-center gap-0.5 rounded bg-muted pl-1 group-hover:flex">
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-5"
                  title={t("newFile")}
                  onClick={(e) => {
                    e.stopPropagation();
                    startCreate(skill, node.path, "file");
                  }}
                >
                  <FilePlusIcon className="size-3 text-muted-foreground" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-5"
                  title={t("newFolder")}
                  onClick={(e) => {
                    e.stopPropagation();
                    startCreate(skill, node.path, "dir");
                  }}
                >
                  <FolderPlusIcon className="size-3 text-muted-foreground" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-5"
                  title={t("deleteFolder")}
                  onClick={(e) => {
                    e.stopPropagation();
                    setPendingDelete({ kind: "dir", skill, path: node.path });
                  }}
                >
                  <Trash2Icon className="size-3 text-destructive" />
                </Button>
              </span>
            </div>
            {open && (
              <>
                {renderTree(node.children, skill, depth + 1)}
                {creating?.skill === skill && creating.inDir === node.path && inlineInputJSX(baseIndent + 14)}
              </>
            )}
          </div>
        );
      }

      // file node
      const isSelected = selected?.skill === skill && selected.path === node.path;
      return (
        <div
          key={node.path}
          role="treeitem"
          tabIndex={0}
          aria-selected={isSelected}
          className={cn(
            "group relative flex cursor-pointer select-none items-center gap-1 rounded py-0.5 pr-1 text-sm",
            isSelected ? "bg-accent text-accent-foreground" : "hover:bg-muted",
          )}
          style={{ paddingLeft: baseIndent + 16 }}
          onClick={() => setSelected({ skill, path: node.path })}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              setSelected({ skill, path: node.path });
            }
          }}
        >
          <FileTextIcon className="size-3.5 shrink-0 text-muted-foreground" />
          <span className="min-w-0 flex-1 truncate font-mono text-xs" title={node.path}>
            {node.name}
          </span>
          <span
            className={cn(
              "absolute inset-y-0 right-1 hidden items-center rounded pl-1 group-hover:flex",
              isSelected ? "bg-accent" : "bg-muted",
            )}
          >
            <Button
              size="icon"
              variant="ghost"
              className="size-5"
              title={t("deleteFile")}
              onClick={(e) => {
                e.stopPropagation();
                setPendingDelete({ kind: "file", skill, path: node.path });
              }}
            >
              <Trash2Icon className="size-3 text-destructive" />
            </Button>
          </span>
        </div>
      );
    });
  }

  const selectedSkill = selected ? (skills.find((s) => s.name === selected.skill) ?? null) : null;

  return (
    <div data-content-padding="false" className="flex flex-1 flex-col overflow-hidden">
      <div className="flex items-center gap-3 border-b px-4 py-2.5 lg:px-6">
        <div className="flex flex-col gap-0.5">
          <h1 className="text-sm font-semibold leading-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-xs">{t("subtitle")}</p>
        </div>
        {/* 缺口清单：agent 点名调用、但库里没有的 skill —— 直接是该补什么的依据。 */}
        {missing.length > 0 && (
          <Popover>
            <PopoverTrigger asChild>
              <Button size="sm" variant="outline" className="ml-auto">
                <AlertTriangleIcon className="size-3.5 text-amber-500" />
                {t("missingCount", { count: missing.length })}
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end" className="w-80">
              <p className="mb-2 text-xs text-muted-foreground">{t("missingHint")}</p>
              <div className="space-y-1">
                {missing.map((m) => (
                  <div key={m.skill} className="flex items-center gap-2 text-sm">
                    <code className="min-w-0 flex-1 truncate font-mono text-xs" title={m.skill}>
                      {m.skill}
                    </code>
                    <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                      {t("callsCount", { count: m.calls })}
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">
                      {fmtTime(m.last_used, t("neverCalled"))}
                    </span>
                  </div>
                ))}
              </div>
            </PopoverContent>
          </Popover>
        )}
      </div>
      <div className="flex flex-1 overflow-hidden">
        {/* ── 左侧文件树 ── */}
        <div className="flex w-64 shrink-0 flex-col border-r">
          <div className="flex flex-col gap-2 border-b p-2">
            <Button size="sm" variant="outline" className="w-full" onClick={() => setNewOpen(true)}>
              <PlusIcon className="size-3.5" />
              {t("newSkill")}
            </Button>
            <input
              ref={uploadRef}
              type="file"
              accept=".zip,application/zip"
              className="hidden"
              onChange={onUploadPick}
            />
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              disabled={uploading}
              onClick={() => uploadRef.current?.click()}
              title={t("uploadTitle")}
            >
              <UploadIcon className="size-3.5" />
              {uploading ? t("uploading") : t("uploadZip")}
            </Button>
          </div>
          {/* Radix viewport wraps children in a display:table div that grows with
              content — force it to block so long names truncate instead of
              widening the rows past the sidebar. */}
          <ScrollArea className="flex-1 [&>[data-slot=scroll-area-viewport]>div]:!block">
            <div className="p-1">
              {skills.map((s) => {
                const isOpen = expanded.has(s.name);
                const tree = buildTree(s.files);
                const isSkillSelected = selected?.skill === s.name && selected.path === null;
                return (
                  <div key={s.name}>
                    {/* skill 根节点 */}
                    <div
                      role="treeitem"
                      tabIndex={0}
                      aria-expanded={isOpen}
                      aria-selected={isSkillSelected}
                      className={cn(
                        "group relative flex cursor-pointer select-none items-center gap-1 rounded px-2 py-1 text-sm",
                        isSkillSelected ? "bg-accent text-accent-foreground" : "hover:bg-muted",
                      )}
                      onClick={() => {
                        toggleExpanded(s.name);
                        setSelected({ skill: s.name, path: null });
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          toggleExpanded(s.name);
                          setSelected({ skill: s.name, path: null });
                        }
                      }}
                    >
                      <ChevronRightIcon
                        className={cn("size-3.5 shrink-0 transition-transform", isOpen && "rotate-90")}
                      />
                      {isOpen ? (
                        <FolderOpenIcon className="size-3.5 shrink-0 text-blue-500" />
                      ) : (
                        <FolderIcon className="size-3.5 shrink-0 text-blue-500" />
                      )}
                      <span className="min-w-0 flex-1 truncate font-semibold" title={s.name}>
                        {s.name}
                      </span>
                      {s.calls > 0 && (
                        <span
                          className="shrink-0 rounded bg-muted px-1 text-[10px] tabular-nums text-muted-foreground"
                          title={t("callCountTitle", { count: s.calls, last: fmtTime(s.last_used, t("neverCalled")) })}
                        >
                          {s.calls}
                        </span>
                      )}
                      <span
                        className={cn(
                          "absolute inset-y-0 right-1 hidden items-center gap-0.5 rounded pl-1 group-hover:flex",
                          isSkillSelected ? "bg-accent" : "bg-muted",
                        )}
                      >
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-5"
                          title={t("newFile")}
                          onClick={(e) => {
                            e.stopPropagation();
                            startCreate(s.name, "", "file");
                          }}
                        >
                          <FilePlusIcon className="size-3 text-muted-foreground" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-5"
                          title={t("newFolder")}
                          onClick={(e) => {
                            e.stopPropagation();
                            startCreate(s.name, "", "dir");
                          }}
                        >
                          <FolderPlusIcon className="size-3 text-muted-foreground" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-5"
                          title={t("deleteSkillAction")}
                          onClick={(e) => {
                            e.stopPropagation();
                            setPendingDelete({ kind: "skill", skill: s.name });
                          }}
                        >
                          <Trash2Icon className="size-3 text-destructive" />
                        </Button>
                      </span>
                    </div>

                    {/* 展开：递归文件树 */}
                    {isOpen && (
                      <>
                        {renderTree(tree, s.name, 0)}
                        {creating?.skill === s.name && creating.inDir === "" && inlineInputJSX(22)}
                      </>
                    )}
                  </div>
                );
              })}

              {skills.length === 0 && <p className="p-3 text-xs text-muted-foreground">{t("emptySidebar")}</p>}
            </div>
          </ScrollArea>
        </div>

        {/* ── 右侧面板 ── */}
        <div className="flex flex-1 flex-col overflow-auto p-4">
          {!selected && (
            <SkillsOverview
              skills={skills}
              missing={missing}
              onSelect={(name) => setSelected({ skill: name, path: null })}
            />
          )}

          {selected && selected.path === null && selectedSkill && (
            <div className="max-w-5xl space-y-5">
              <div>
                <h2 className="font-mono text-base font-semibold">{selectedSkill.name}</h2>
                {selectedSkill.description && (
                  <p className="mt-1 text-sm text-muted-foreground">{selectedSkill.description}</p>
                )}
                <div className="mt-2 flex flex-wrap gap-2">
                  {selectedSkill.license && (
                    <Badge variant="outline" className="text-xs font-normal">
                      License: {selectedSkill.license}
                    </Badge>
                  )}
                  {selectedSkill.compatibility && (
                    <Badge variant="secondary" className="text-xs font-normal">
                      {selectedSkill.compatibility}
                    </Badge>
                  )}
                </div>
              </div>

              {/* 左右分栏：配置（MCP/可见性）在左为主，调用统计在右为辅。
                  lg 以下放不下时用 flex-row-reverse 回落到单列——统计因 DOM 顺序在前，
                  窄屏时自然落到配置上方（与改版前的上下顺序一致）。 */}
              <div className="flex flex-col gap-6 lg:flex-row-reverse lg:items-start">
                {/* ── 右侧：调用统计 ── */}
                <div className="space-y-2 lg:w-80 lg:shrink-0">
                  <Label className="text-xs text-muted-foreground">{t("callStats")}</Label>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="rounded-md border p-2">
                      <p className="text-lg font-semibold tabular-nums">{selectedSkill.calls}</p>
                      <p className="text-xs text-muted-foreground">{t("totalCalls")}</p>
                    </div>
                    <div className="rounded-md border p-2">
                      <p className="text-lg font-semibold tabular-nums">{selectedSkill.tasks}</p>
                      <p className="text-xs text-muted-foreground">{t("coveredTasks")}</p>
                    </div>
                    <div className="rounded-md border p-2">
                      <p
                        className="truncate text-sm font-medium"
                        title={fmtTime(selectedSkill.last_used, t("neverCalled"))}
                      >
                        {fmtTime(selectedSkill.last_used, t("neverCalled"))}
                      </p>
                      <p className="text-xs text-muted-foreground">{t("recent")}</p>
                    </div>
                  </div>
                  {selectedSkill.usage_agents.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-xs text-muted-foreground">{t("callers")}</span>
                      {selectedSkill.usage_agents.map((k) => (
                        <Badge key={k} variant="secondary" className="text-xs font-normal">
                          {k}
                        </Badge>
                      ))}
                    </div>
                  )}
                  {usageLoading ? (
                    <p className="text-xs text-muted-foreground">{t("loadingCalls")}</p>
                  ) : usageCalls.length > 0 ? (
                    <div className="rounded-md border">
                      <div className="border-b px-2 py-1 text-xs text-muted-foreground">
                        {t("recentCallsCount", { count: usageCalls.length })}
                      </div>
                      <div className="max-h-56 overflow-y-auto">
                        {usageCalls.map((c, i) => (
                          <div
                            key={`${c.ts}-${i}`}
                            className="flex items-center gap-2 border-b px-2 py-1 text-xs last:border-b-0"
                          >
                            <span className="tabular-nums text-muted-foreground">
                              {fmtTime(c.ts, t("neverCalled"))}
                            </span>
                            <Badge variant="outline" className="font-normal">
                              {c.agent_key || "—"}
                            </Badge>
                            <span className="ml-auto text-muted-foreground">
                              {c.task_id > 0 ? t("taskRef", { id: c.task_id }) : c.session_id ? t("sessionRef") : "—"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">{t("noCallsYet")}</p>
                  )}
                </div>

                {/* ── 左侧：关联 MCP + 可见性 ── */}
                <div className="space-y-5 lg:min-w-0 lg:flex-1">
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">
                      {t("linkedMcp")}
                      <span className="ml-1 font-normal">{t("linkedMcpHint")}</span>
                    </Label>
                    {mcpOptions.length === 0 ? (
                      <p className="text-xs text-muted-foreground">{t("noMcp")}</p>
                    ) : (
                      <div className="flex flex-wrap gap-x-4 gap-y-2">
                        {mcpOptions.map((m) => (
                          <label key={m.id} className="flex cursor-pointer items-center gap-2 text-sm">
                            <Checkbox
                              checked={detailMcps.includes(m.name)}
                              onCheckedChange={(on) => toggleSkillMcp(selectedSkill.name, m.name, !!on)}
                            />
                            {m.name}
                          </label>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">{t("visibility")}</Label>
                    <div className="space-y-2">
                      {agents.map((a) => (
                        <label key={a.key} className="flex cursor-pointer items-center gap-2 text-sm">
                          <Checkbox
                            checked={(visibility[selectedSkill.name] ?? []).includes(a.id)}
                            onCheckedChange={() => toggleVisibility(selectedSkill.name, a.id, a.name)}
                          />
                          {a.name}
                        </label>
                      ))}
                      {agents.length === 0 && <span className="text-xs text-muted-foreground">{t("noAgents")}</span>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {selected && selected.path !== null && (
            <div className="flex h-full flex-col gap-2">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="font-medium text-foreground">{selected.skill}</span>
                <span>/</span>
                <span className="font-mono">{selected.path}</span>
                <Button size="sm" className="ml-auto" onClick={saveFile} disabled={!dirty || saving}>
                  {saving ? t("saving") : t("save")}
                </Button>
              </div>
              {fileLoading ? (
                <p className="text-xs text-muted-foreground">{t("loading")}</p>
              ) : (
                <Textarea
                  className="flex-1 resize-none font-mono text-xs"
                  value={fileContent}
                  onChange={(e) => {
                    setFileContent(e.target.value);
                    setDirty(true);
                  }}
                />
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── 删除二次确认 ── */}
      <AlertDialog
        open={!!pendingDelete}
        onOpenChange={(o) => {
          if (!o) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pendingDelete?.kind === "skill" && t("deleteSkillQ", { name: pendingDelete.skill })}
              {pendingDelete?.kind === "dir" && t("deleteFolderQ", { path: pendingDelete.path })}
              {pendingDelete?.kind === "file" && t("deleteFileQ", { path: pendingDelete.path })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {pendingDelete?.kind === "skill"
                ? t("deleteSkillDesc")
                : pendingDelete?.kind === "dir"
                  ? t("deleteFolderDesc")
                  : t("irreversible")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleting}
              onClick={(e) => {
                e.preventDefault();
                void runPendingDelete();
              }}
            >
              {deleting ? t("deleting") : t("delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* ── 新建 Skill 对话框 ── */}
      <Sheet open={newOpen} onOpenChange={setNewOpen}>
        <SheetContent side="right" className="flex w-full flex-col gap-0 data-[side=right]:sm:max-w-xl">
          <SheetHeader className="px-4 pt-4">
            <SheetTitle>{t("newSkill")}</SheetTitle>
          </SheetHeader>
          <Tabs defaultValue="basic" className="flex min-h-0 flex-1 flex-col">
            <TabsList className="mx-4 mt-3 shrink-0 justify-start">
              <TabsTrigger value="basic">{t("tabBasic")}</TabsTrigger>
              <TabsTrigger value="mcp">
                {t("linkedMcp")}
                {newMcps.length > 0 && (
                  <span className="ml-1.5 rounded-full bg-primary px-1.5 py-0.5 text-[10px] leading-none text-primary-foreground">
                    {newMcps.length}
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="visibility">
                {t("tabVisibility")}
                {newVisibility.length > 0 && (
                  <span className="ml-1.5 rounded-full bg-primary px-1.5 py-0.5 text-[10px] leading-none text-primary-foreground">
                    {newVisibility.length}
                  </span>
                )}
              </TabsTrigger>
            </TabsList>

            {/* 基本信息 */}
            <TabsContent
              value="basic"
              className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4 pt-4 data-[state=inactive]:hidden"
            >
              <div className="grid gap-1.5">
                <Label htmlFor="sk-name">
                  {t("nameLabel")} <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="sk-name"
                  placeholder="sqli-deepdive"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
                <p className="text-muted-foreground text-xs">{t("nameHint")}</p>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="sk-desc">
                  {t("descLabel")} <span className="text-destructive">*</span>
                </Label>
                <Textarea
                  id="sk-desc"
                  rows={2}
                  className="resize-none"
                  placeholder={t("descPlaceholder")}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">license</Label>
                  <Input
                    placeholder="MIT / Proprietary"
                    value={newLicense}
                    onChange={(e) => setNewLicense(e.target.value)}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">compatibility</Label>
                  <Input
                    placeholder={t("compatPlaceholder")}
                    value={newCompat}
                    onChange={(e) => setNewCompat(e.target.value)}
                  />
                </div>
              </div>
              <div className="flex min-h-0 flex-1 flex-col gap-1.5">
                <Label htmlFor="sk-inst">
                  {t("bodyLabel")} <span className="text-muted-foreground text-xs font-normal">{t("bodyHint")}</span>
                </Label>
                <Textarea
                  id="sk-inst"
                  className="min-h-40 flex-1 resize-none font-mono text-sm leading-relaxed"
                  placeholder={t("bodyPlaceholder")}
                  value={newInst}
                  onChange={(e) => setNewInst(e.target.value)}
                />
              </div>
            </TabsContent>

            {/* 关联 MCP */}
            <TabsContent value="mcp" className="overflow-y-auto px-4 pb-4 pt-4 data-[state=inactive]:hidden">
              <p className="mb-3 text-xs text-muted-foreground">{t("mcpSheetHint")}</p>
              {mcpOptions.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t("noMcp")}</p>
              ) : (
                <div className="flex flex-col gap-2">
                  {mcpOptions.map((m) => (
                    <label key={m.id} className="flex cursor-pointer items-center gap-2 text-sm">
                      <Checkbox
                        checked={newMcps.includes(m.name)}
                        onCheckedChange={(on) =>
                          setNewMcps((cur) => (on ? [...cur, m.name] : cur.filter((n) => n !== m.name)))
                        }
                      />
                      {m.name}
                    </label>
                  ))}
                </div>
              )}
            </TabsContent>

            {/* 可见性 */}
            <TabsContent value="visibility" className="overflow-y-auto px-4 pb-4 pt-4 data-[state=inactive]:hidden">
              <p className="mb-3 text-xs text-muted-foreground">{t("visSheetHint")}</p>
              {agents.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t("noAgents")}</p>
              ) : (
                <div className="flex flex-col gap-2">
                  {agents.map((a) => (
                    <label key={a.key} className="flex cursor-pointer items-center gap-2 text-sm">
                      <Checkbox
                        checked={newVisibility.includes(a.id)}
                        onCheckedChange={(on) =>
                          setNewVisibility((cur) => (on ? [...cur, a.id] : cur.filter((id) => id !== a.id)))
                        }
                      />
                      {a.name}
                    </label>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>

          <SheetFooter className="flex-row justify-end gap-2 border-t px-4 py-3">
            <Button variant="outline" onClick={() => setNewOpen(false)}>
              {t("cancel")}
            </Button>
            <Button onClick={createNewSkill} disabled={creatingSkill}>
              {creatingSkill ? t("creating") : t("create")}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
