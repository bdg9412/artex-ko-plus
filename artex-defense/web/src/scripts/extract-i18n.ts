/**
 * Script: extract-i18n.ts
 *
 * ARTEX 한국어화 — UI 문자열 1차 추출기.
 *
 * `src/` 아래 모든 `.ts`/`.tsx` 를 TypeScript AST 로 파싱해, 사용자에게 노출되는
 * 하드코딩 중국어 문자열만 뽑아낸다. 추출 대상은 세 종류다.
 *   1) 문자열 리터럴            예) title: "仪表盘"
 *   2) 템플릿 리터럴            예) `已删除 ${n} 个对话` → "已删除 {var0} 个对话"
 *   3) JSX 텍스트 노드          예) <span>故障转移</span>
 * 주석(`//`, `/* *\/`)은 AST 노드가 아니므로 저절로 제외된다. 선행·후행 주석에
 * 들어 있는 중국어는 번역 대상이 아니다(BRIEF: 주석 번역은 우선순위 최하).
 *
 * 산출물(web/messages/):
 *   - zh.json          네임스페이스로 중첩된 { 키: "원문 중국어" }  (상류 대조용 원본 보존)
 *   - ko.json          같은 뼈대, 값은 "" (B3 에서 한국어로 채움)
 *   - zh.sources.json  키별 출처(파일:줄)·종류·플레이스홀더 — B2 배선, B3 번역, 드리프트 추적용
 *
 * 재추출은 비파괴적이다. 추출이 만들어 내는 최상위 네임스페이스(파일 경로 기반:
 * app·components·lib 등)만 코드에서 새로 갱신하고, 그 밖의 "큐레이션 네임스페이스"
 * (손으로 번역해 둔 nav·search·header 등)는 기존 파일에서 그대로 보존한다. 규칙:
 * 추출 네임스페이스는 인벤토리라 손으로 고치지 않고, 런타임 번역은 큐레이션
 * 네임스페이스에만 둔다. 그래야 재추출이 번역을 덮어쓰지 않는다.
 *
 * 네임스페이스는 파일 경로에서 얻는다. 예) src/app/(main)/system/llm/page.tsx
 *   → app.main.system.llm.page  (라우트 그룹 괄호 제거, _폴더의 밑줄 제거)
 * 키는 원문의 sha1 앞 8자다. 순서·파일이 바뀌어도 같은 문구는 같은 키를 받아
 * 재실행 diff 가 작다(상류 업데이트 대조에 유리).
 *
 * 실행:  npm run extract:i18n
 */

import * as ts from "typescript";

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SRC_DIR = path.resolve(__dirname, "..");
const MESSAGES_DIR = path.resolve(__dirname, "../../messages");
const REPO_WEB_DIR = path.resolve(__dirname, "../..");

/** 한자(Han) 1자 이상 포함 여부. UI 번역 대상 판별의 유일한 기준. */
const HAN = /\p{Script=Han}/u;

/** 추출에서 제외할 디렉터리(파싱 도구 자신·빌드 산출물). */
const SKIP_DIRS = new Set(["scripts", "node_modules", ".next"]);

type Kind = "string" | "template" | "jsx";

interface Message {
  ns: string;
  key: string;
  text: string;
  kind: Kind;
  placeholders: string[]; // 템플릿의 ${...} 원본 표현식(참고용)
  occurrences: string[]; // "상대경로:줄"
}

/** src 기준 상대경로 → 점으로 이은 네임스페이스. */
function toNamespace(absFile: string): string {
  const rel = path.relative(SRC_DIR, absFile).replace(/\.[tj]sx?$/, "");
  return rel
    .split(path.sep)
    .map((seg) =>
      seg
        .replace(/^\((.*)\)$/, "$1") // (main) → main  (라우트 그룹)
        .replace(/^_/, "") // _components → components
        .replace(/[^A-Za-z0-9가-힣]+/g, "-")
        .replace(/^-+|-+$/g, ""),
    )
    .filter(Boolean)
    .join(".");
}

function hashKey(text: string): string {
  return crypto.createHash("sha1").update(text).digest("hex").slice(0, 8);
}

/** 디렉터리 재귀 순회로 .ts/.tsx 파일 수집. */
function collectFiles(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      collectFiles(path.join(dir, entry.name), out);
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/** 템플릿 리터럴을 "리터럴 부분 + {varN}" 으로 재구성. 반환 null = 리터럴 부분에 한자 없음. */
function reconstructTemplate(node: ts.TemplateExpression): { text: string; placeholders: string[] } | null {
  let text = node.head.text;
  const placeholders: string[] = [];
  node.templateSpans.forEach((span, i) => {
    placeholders.push(span.expression.getText());
    text += `{var${i}}${span.literal.text}`;
  });
  // 한자가 ${} 안에만 있고 고정 문구에는 없으면, 그 한자는 내부 노드로 따로 잡힌다.
  if (!HAN.test(node.head.text) && !node.templateSpans.some((s) => HAN.test(s.literal.text))) {
    return null;
  }
  return { text, placeholders };
}

/** JSX 텍스트 정규화: 양끝 공백 제거 + 내부 연속 공백/줄바꿈을 한 칸으로(브라우저 렌더 규칙과 동일). */
function normalizeJsxText(raw: string): string {
  return raw.replace(/\s+/g, " ").trim();
}

const messages = new Map<string, Message>(); // "ns\u0000key" → Message
const scannedFiles = collectFiles(SRC_DIR).sort();
const capturedLines = new Map<string, Set<number>>(); // 파일 → 추출 노드가 걸린 줄 번호 집합
let fileWithHan = 0;

function record(ns: string, text: string, kind: Kind, placeholders: string[], relFile: string, line: number) {
  const key = hashKey(text);
  const id = `${ns}\u0000${key}`;
  let msg = messages.get(id);
  if (!msg) {
    msg = { ns, key, text, kind, placeholders, occurrences: [] };
    messages.set(id, msg);
  }
  const occ = `${relFile}:${line}`;
  if (!msg.occurrences.includes(occ)) msg.occurrences.push(occ);
}

for (const absFile of scannedFiles) {
  const source = fs.readFileSync(absFile, "utf8");
  if (!HAN.test(source)) continue;
  fileWithHan++;

  const relFile = path.relative(REPO_WEB_DIR, absFile);
  const ns = toNamespace(absFile);
  const scriptKind = absFile.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(absFile, source, ts.ScriptTarget.Latest, true, scriptKind);
  const lineOf = (pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;
  const markLine = (pos: number) => {
    const set = capturedLines.get(relFile) ?? new Set<number>();
    set.add(lineOf(pos));
    capturedLines.set(relFile, set);
  };

  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node) && !ts.isTemplateExpression(node.parent)) {
      // 문자열 리터럴 + 치환 없는 템플릿. (치환 있는 템플릿의 head/middle 은 여기 안 걸림)
      if (HAN.test(node.text)) {
        record(ns, node.text, "string", [], relFile, lineOf(node.getStart(sf)));
        markLine(node.getStart(sf));
      }
    } else if (ts.isTemplateExpression(node)) {
      const r = reconstructTemplate(node);
      if (r) {
        record(ns, r.text, "template", r.placeholders, relFile, lineOf(node.getStart(sf)));
        markLine(node.getStart(sf));
      }
    } else if (ts.isJsxText(node)) {
      const text = normalizeJsxText(node.text);
      if (text && HAN.test(text)) {
        record(ns, text, "jsx", [], relFile, lineOf(node.getStart(sf)));
        markLine(node.getStart(sf));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// --- 중첩 JSON 조립 ---------------------------------------------------------
type Tree = { [k: string]: Tree | string };

function setNested(root: Tree, nsPath: string, key: string, value: string) {
  const segs = nsPath.split(".");
  let node: Tree = root;
  for (const seg of segs) {
    if (typeof node[seg] !== "object") node[seg] = {};
    node = node[seg] as Tree;
  }
  node[key] = value;
}

/** 키를 재귀적으로 정렬해 재실행 diff 를 최소화. */
function sortTree(t: Tree): Tree {
  const out: Tree = {};
  for (const k of Object.keys(t).sort()) {
    const v = t[k];
    out[k] = typeof v === "string" ? v : sortTree(v);
  }
  return out;
}

const zhTree: Tree = {};
const koTree: Tree = {};
const sources: Record<string, { text: string; kind: Kind; placeholders: string[]; occurrences: string[] }> = {};

for (const msg of messages.values()) {
  setNested(zhTree, msg.ns, msg.key, msg.text);
  setNested(koTree, msg.ns, msg.key, "");
  sources[`${msg.ns}.${msg.key}`] = {
    text: msg.text,
    kind: msg.kind,
    placeholders: msg.placeholders,
    occurrences: msg.occurrences.sort(),
  };
}

const sortedSources: typeof sources = {};
for (const k of Object.keys(sources).sort()) sortedSources[k] = sources[k];

fs.mkdirSync(MESSAGES_DIR, { recursive: true });
const write = (name: string, data: unknown) =>
  fs.writeFileSync(path.join(MESSAGES_DIR, name), `${JSON.stringify(data, null, 2)}\n`, "utf8");

/** 기존 메시지 파일을 읽는다. 없거나 깨졌으면 빈 트리. */
function readTree(name: string): Tree {
  try {
    return JSON.parse(fs.readFileSync(path.join(MESSAGES_DIR, name), "utf8")) as Tree;
  } catch {
    return {};
  }
}

/**
 * 비파괴 병합. 추출이 새로 만든 트리(fresh)의 최상위 네임스페이스는 코드가 진실이므로
 * 그대로 쓰고, 기존 파일(existing)에만 있는 최상위 네임스페이스(=손으로 번역한 큐레이션
 * 네임스페이스)는 보존한다. 추출 네임스페이스 안의 오래된(상류에서 사라진) 키는 자연히
 * 빠진다(상류 대조에 유리).
 */
function mergeCurated(fresh: Tree, existing: Tree): Tree {
  const extractedTop = new Set(Object.keys(fresh));
  const out: Tree = { ...fresh };
  for (const [ns, subtree] of Object.entries(existing)) {
    if (!extractedTop.has(ns)) out[ns] = subtree;
  }
  return out;
}

write("zh.json", sortTree(mergeCurated(zhTree, readTree("zh.json"))));
write("ko.json", sortTree(mergeCurated(koTree, readTree("ko.json"))));
write("zh.sources.json", sortedSources);

// --- 요약 리포트 ------------------------------------------------------------
const byKind: Record<Kind, number> = { string: 0, template: 0, jsx: 0 };
const byNs = new Map<string, number>();
let totalOccurrences = 0;
for (const msg of messages.values()) {
  byKind[msg.kind]++;
  byNs.set(msg.ns, (byNs.get(msg.ns) ?? 0) + 1);
  totalOccurrences += msg.occurrences.length;
}

// 커버리지 추정: 한자 포함 소스 줄 중, 추출 노드가 걸린 줄의 비율.
// 나머지는 거의 주석(=번역 비대상)이다.
let hanLines = 0;
let capturedHanLines = 0;
for (const absFile of scannedFiles) {
  const relFile = path.relative(REPO_WEB_DIR, absFile);
  const lines = fs.readFileSync(absFile, "utf8").split(/\r?\n/);
  const capSet = capturedLines.get(relFile) ?? new Set<number>();
  lines.forEach((ln, i) => {
    if (HAN.test(ln)) {
      hanLines++;
      if (capSet.has(i + 1)) capturedHanLines++;
    }
  });
}

const topNs = [...byNs.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15);

console.log("─".repeat(64));
console.log("ARTEX i18n 추출 완료");
console.log("─".repeat(64));
console.log(`스캔한 파일            : ${scannedFiles.length} (src/ 아래 .ts/.tsx, scripts 제외)`);
console.log(`한자 포함 파일         : ${fileWithHan}`);
console.log(`고유 메시지(키)        : ${messages.size}`);
console.log(`  ├─ 문자열 리터럴      : ${byKind.string}`);
console.log(`  ├─ 템플릿 리터럴      : ${byKind.template}`);
console.log(`  └─ JSX 텍스트         : ${byKind.jsx}`);
console.log(`총 출현 위치           : ${totalOccurrences} (중복 사용 포함)`);
console.log(`네임스페이스 수        : ${byNs.size}`);
console.log("");
console.log(`한자 포함 소스 줄       : ${hanLines}`);
console.log(`  └─ 추출로 포착된 줄   : ${capturedHanLines} (${((capturedHanLines / hanLines) * 100).toFixed(1)}%)`);
console.log(`     나머지 ${hanLines - capturedHanLines} 줄은 대부분 코드 주석(번역 비대상)`);
console.log("");
console.log("메시지 많은 네임스페이스 상위 15:");
for (const [ns, n] of topNs) console.log(`  ${String(n).padStart(4)}  ${ns}`);
console.log("");
console.log(`출력: web/messages/{zh.json, ko.json, zh.sources.json}`);
console.log("─".repeat(64));
