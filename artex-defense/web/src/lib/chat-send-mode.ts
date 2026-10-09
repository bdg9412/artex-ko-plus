"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";

// 세션 입력창의 전송/줄바꿈 키 조합. 순수 프런트엔드 환경설정이라 localStorage 에만
// 저장하고 서버에 저장하지 않으며 계정과 동기화되지 않는다. 그래서 브라우저를 바꾸면
// 다시 설정해야 한다. issue #39 참고: 0.3.2 가 Ctrl+Enter 전송을 Enter 전송으로 바꿨고,
// 여기서 옛 키 조합을 선택지로 되살린다.
export type ChatSendMode = "enter" | "ctrl-enter";

export const CHAT_SEND_MODE_KEY = "artex_chat_send_mode";
export const DEFAULT_CHAT_SEND_MODE: ChatSendMode = "enter";

// 설정 화면의 전송 방식 드롭다운에 쓰는 선택지. 라벨은 로케일에 따라 달라지므로 모듈
// 상수가 아니라 훅으로 돌려준다(순수 모듈에 한국어를 하드코딩하면 zh 로케일이 한국어로
// 깨진다). value 는 안정 식별자라 localStorage 키·동작 판정에 그대로 쓴다.
export function useChatSendModeOptions(): { value: ChatSendMode; label: string }[] {
  const t = useTranslations("chatSendMode.option");
  return [
    { value: "enter", label: t("enter") },
    { value: "ctrl-enter", label: t("ctrlEnter") },
  ];
}

function parseMode(raw: string | null): ChatSendMode {
  return raw === "ctrl-enter" || raw === "enter" ? raw : DEFAULT_CHAT_SEND_MODE;
}

// 같은 탭 안의 구독자 집합. localStorage 의 storage 이벤트는 "다른" 탭에서만 발생하므로,
// 현재 탭에서 설정을 바꾼 뒤에는 emit 으로 같은 탭의 입력창에 알려야 한다. 그러지 않으면
// 새로고침해야 반영된다.
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  window.addEventListener("storage", listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", listener);
  };
}

// 문자열 리터럴을 돌려주므로 Object.is 가 값으로 비교해 useSyncExternalStore 가 무한
// 루프에 빠지지 않는다.
function getSnapshot(): ChatSendMode {
  return parseMode(getLocalStorageValue(CHAT_SEND_MODE_KEY));
}

// 서버에는 localStorage 가 없으므로 먼저 기본값을 렌더하고, hydrate 후 getSnapshot 이
// 값을 바로잡는다.
function getServerSnapshot(): ChatSendMode {
  return DEFAULT_CHAT_SEND_MODE;
}

export function useChatSendMode(): ChatSendMode {
  return React.useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
}

export function setChatSendMode(mode: ChatSendMode) {
  setLocalStorageValue(CHAT_SEND_MODE_KEY, mode);
  for (const listener of listeners) listener();
}

// shouldSubmitOnKey 는 한 번의 키 입력이 전송에 해당하는지 판단한다.
// isComposing / keyCode 229 는 한국어·중국어 등 입력기가 글자를 조합 중인 상태이므로
// 반드시 통과시킨다. 그러지 않으면 Enter 로 글자를 확정할 때 잘못 전송된다.
// enter 모드는 Shift 만 제외해 0.3.2 의 동작과 글자 하나까지 똑같이 유지한다(설정을
// 바꾸지 않은 사용자의 조작감이 변하지 않는다). ctrl-enter 모드는 Ctrl 과 Cmd(macOS)를
// 함께 받는다.
export function shouldSubmitOnKey(e: React.KeyboardEvent, mode: ChatSendMode): boolean {
  if (e.key !== "Enter") return false;
  if (e.nativeEvent.isComposing || e.nativeEvent.keyCode === 229) return false;
  if (mode === "ctrl-enter") return e.ctrlKey || e.metaKey;
  return !e.shiftKey;
}
