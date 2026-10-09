// 지원 locale 과 기본값. 이 저장소는 ARTEX 한국어판이므로 기본 locale 은 "ko" 이고,
// 원문 대조(상류 업데이트 비교)를 위해 중국어 "zh" 를 함께 둔다.
export const LOCALES = ["ko", "zh"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "ko";

// 활성 locale 을 빌드 시점에 결정한다. 정적 내보내기(next.config 의 output: "export")와
// 호환되어야 하므로 cookies()·headers() 같은 동적 API 를 쓰지 않고 환경변수만 읽는다.
// NEXT_PUBLIC_LOCALE 이 비었거나 지원 목록 밖이면 기본값(ko)으로 떨어진다.
export function resolveLocale(): Locale {
  const raw = process.env.NEXT_PUBLIC_LOCALE;
  return LOCALES.includes(raw as Locale) ? (raw as Locale) : DEFAULT_LOCALE;
}
