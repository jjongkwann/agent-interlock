# Provider 운영 정책

설정형 실행기는 `ANTHROPIC` 및 `OPENAI` 모델을 지원한다. 도구 실행은 기존 승인·인수·권한 검사 경로를
사용한다. 모델 제공자 전환은 추론 요청에만 적용되며, 도구 쓰기를 재시도하지 않는다.

아래 설정을 agent의 `interlock.runtime`에 추가한다. 기존 `kind`, `model`, `credentialRef`,
`providerActorId`가 첫 번째 제공자이며, `fallbacks` 순서가 전환 순서다.

```json
{
  "providerPolicy": {
    "maxAttempts": 2,
    "retryDelaySeconds": 0.2,
    "onError": {
      "RATE_LIMIT": "RETRY_THEN_FAILOVER",
      "SERVER": "FAILOVER",
      "TIMEOUT": "FAILOVER",
      "CONNECTION": "RETRY_THEN_FAILOVER",
      "AUTH": "BLOCK"
    },
    "fallbacks": [
      {
        "kind": "OPENAI",
        "model": "reviewed-model-name",
        "providerActorId": "provider.openai",
        "credentialRef": "openai-production",
        "policy": {
          "maxAttempts": 1,
          "onError": {"RATE_LIMIT": "BLOCK", "SERVER": "BLOCK"}
        }
      }
    ]
  }
}
```

각 후보는 검토된 `EXTERNAL` actor 및 source agent로부터의 `REL-07` 연결이 있어야 한다.
허용 도메인은 Anthropic의 `api.anthropic.com` 또는 OpenAI의 `api.openai.com`이다. 고정된 HTTPS
endpoint와 pinned transport를 사용하며 redirect, proxy 환경변수, SDK 자체 재시도를 허용하지 않는다.
자격 증명은 호스트의 credential mapping에서만 가져온다.

모든 후보의 `REL-07` 정책은 첫 제공자와 동일해야 한다. 정책 ID와 버전 표기를 제외한 필드를 비교하며,
실행 모드는 `ENFORCE`여야 한다. 매 시도마다 전체 system prompt, messages, tool 정의에 원래 purpose,
dataClasses, export 제한 및 secret 검사를 적용한다. 제공자의 `dataAccess`도 동일한 분류를 허용해야 한다.
사전 검사를 통과하더라도 호출 시의 정책 위반은 즉시 차단된다. 다음 제공자로 우회하지 않는다.

시도 횟수는 제공자당 최대 3회, fallback은 최대 3개다. `maxAttempts`에는 최초 호출이 포함된다.
추가 정책이 없으면 각 제공자는 한 번만 호출되고 모든 오류에서 중단한다. 후보의 `policy`는 공통 운영
설정을 덮어쓰며, `onError`를 지정하면 오류 규칙 전체를 교체한다. 명시하지 않은 오류는 `BLOCK`이다.
`RETRY`는 해당 제공자 안에서만 재시도하고, `FAILOVER`는 바로 다음 후보로 이동한다.
`RETRY_THEN_FAILOVER`는 횟수를 소진한 뒤 이동한다. 지연은 최대 2초이며 task deadline을 넘기지 않는다.
`POLICY`, `INVALID_RESPONSE`, `UNKNOWN` 오류는 항상 중단한다. 한 task의 다음 모델 turn과 승인 후 재개는
첫 제공자부터 시작하므로, 회로 차단기나 제공자 상태를 프로세스 밖에 유지하지 않는다.

각 시도는 `PROVIDER_CALL_RECORDED` ledger event로 추적한다. 제공자/actor/model, 시도 ID와 순서,
workflow/task, step, bundle digest, 지연, 오류 분류, HTTP status와 적용한 조치가 기록된다.
사용량은 `usage.unit = "tokens"`, `inputCount`, `outputCount`와 가능한 cache count로 남는다.
응답을 받지 못했거나 제공자가 사용량을 반환하지 않으면 `status = "UNKNOWN"`과 null을 기록한다.
이를 사용량 0 또는 과금 없음으로 해석하면 안 된다. prompt, 응답 원문, credential 및 SDK 예외 원문은
운영 event에 기록하지 않는다.

검증: `python -m pytest tests/test_provider_policy.py tests/test_configurable_runtime.py -q`.
fault injection 검사는 Anthropic 503 → OpenAI 전환, 정확한 도구 호출 승인 대기 → 승인 → 1회 쓰기 →
모델 완료, rate limit 재시도 상한, 정책 위반 전송 차단, 후보별 규칙, 사용량 보존과 예외 비밀정보 제외를
확인한다. 테스트의 모델 응답은 통제된 HTTP/SDK fixture이며 실제 제공자의 품질 또는 가용성 측정은 아니다.

OpenAI의 `tool_calls`, `tool_call_id`, `max_completion_tokens`, `parallel_tool_calls` 및 usage 필드는
[공식 Chat Completions API 문서](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)를
기준으로 작성했다. API 형식 확인과 실제 계정·모델 실행 검증은 별개다.
