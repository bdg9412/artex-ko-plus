# OrcaRouter Cyber Inference 프로필

`OrcaRouter Cyber Inference`는 AegisLoop의 **일반 제공자(named provider)** 입니다. 별도의
사용자 지정(custom) 엔드포인트 옵션이 아니라, 형식 목록·DB 스키마·모델 카탈로그·문서에
`orcarouter` 키워드로 등록되는 독립된 연결 형식입니다. 허가된 범위에서 방어 검증·침해
조사·자율헌팅을 수행하는 보안 팀이 모델 호출을 [OrcaRouter](https://www.orcarouter.ai)
게이트웨이로 라우팅할 때 사용합니다.

## 연결 정보

| 항목 | 값 |
| --- | --- |
| 형식(provider id) | `orcarouter` |
| 표시 이름 | `OrcaRouter Cyber Inference` |
| API 기준 주소 | `https://api.orcarouter.ai/v1` |
| 인증 기준 주소 | `https://www.orcarouter.ai` |
| API 키 환경 변수 | `ORCAROUTER_API_KEY` |
| 키 형식 | `sk-orca-…` |
| 와이어 형식 | OpenAI Chat Completions (기존 OpenAI 어댑터 재사용) |

추론과 모델 조회는 항상 API 기준 주소(`api.orcarouter.ai`)로만 나갑니다. 자격 증명
발급은 인증 기준 주소(`www.orcarouter.ai`)에서 이루어지며, 두 주소를 서로 유도하지
않습니다.

## 모델

- 기본값: `orcarouter/auto`
- 일반 대체 모델: `orcarouter/fusion`
- 보안 팀 권장(비즈니스 인증 계정): `orcacyber-ultra-1.0` (OrcaCyber Ultra),
  `orcacyber-zero-1.5` (OrcaCyber Zero)

권장 보안 모델은 **권장 표시**일 뿐 기본값이 아닙니다. 실제 호출 가능 여부는 계정에
내려오는 카탈로그가 결정합니다. 보안 팀 대상 안내는
[OrcaRouter Cyber](https://www.orcarouter.ai/cyber)와
[Cyber 모델 카탈로그](https://www.orcarouter.ai/models?tier=cyber)를 참고하세요.

## 모델 목록은 실시간 카탈로그에서 가져옵니다

모델 목록을 코드에 하드코딩하지 않습니다. 단일 기준은 다음 호출의 응답입니다.

```
GET https://api.orcarouter.ai/v1/models?capability=chat
Authorization: Bearer sk-orca-…
```

프로필 화면의 **모델** 입력은 자유 입력 대신 이 카탈로그로 채워진 드롭다운입니다.

적용 규칙:

1. `supported_endpoint_types`(또는 `endpoint_capabilities`)에 텍스트 계열
   (`openai`, `anthropic`, `gemini`, `openai-response`)이 하나도 없는 항목은 제외합니다.
2. `image-generation`, `openai-video`, `jina-rerank`, `embeddings` 전용 항목은
   채팅 카탈로그에 섞여 있어도 제외합니다.
3. 능력 정보가 비어 있는 항목은 추측하지 않고 제외합니다(fail-closed).
4. 카탈로그 조회가 실패하거나 비어 있으면 코드에 검증된 소량의 시드 목록으로
   대체하고, 화면에 **저하(degraded)** 상태를 명시합니다. 시드 목록은 실시간
   카탈로그와 섞이지 않습니다.
5. 이미 선택된 모델이 호환 목록에서 빠지면 선택을 비웁니다(오래된 값 유지 금지).

백엔드는 `GET /api/llm/models`(관리 API)에서 같은 카탈로그를 조회합니다. 브라우저가
키를 직접 다루지 않도록 API 키는 서버에서만 사용합니다.

## API 키

- 저장된 키는 화면에서 마스킹되어 표시되며(`sk-orca-…` 입력 예시), 전체 값은 다시
  노출하지 않습니다.
- 키에 개행 등 헤더를 깨뜨리는 문자가 있으면 요청 헤더로 전달하지 않습니다.
- 키는 URL·로그·증적·Git 기록에 남기지 않습니다.
- `401` 응답은 자격 증명 재발급이 필요하다는 뜻입니다.

## 확인 방법

1. **시스템 → LLM → 새 프로필**에서 형식을 `OrcaRouter Cyber Inference`로 선택합니다.
2. 연결 주소는 기본값 `https://api.orcarouter.ai/v1`을 그대로 사용합니다.
3. 발급받은 `sk-orca-…` 키를 입력하고 **모델** 드롭다운이 실제 카탈로그 항목으로
   채워지는지 확인합니다.
4. **연결 테스트**로 실제 응답을 확인한 뒤 저장합니다.

허가되지 않은 대상에 대한 실행은 하지 않습니다. 이 프로필은 승인된 범위의 보안
검증 작업을 위한 추론 연결입니다.
