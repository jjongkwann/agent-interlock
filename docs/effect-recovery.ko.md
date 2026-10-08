# 외부 실행 결과 확인과 안전한 재개

`RUN-EFFECT-UNCERTAIN`은 요청이 실패했다는 뜻이 아니다. 외부 저장은 끝났지만 응답·worker·상태 저장 중
하나를 잃었을 수 있다. 새 복구 경로는 외부의 영수증과 요청 지문을 확인한 뒤 기존 run을 재개한다.

| 확인 결과 | 필요한 근거 | 이후 동작 |
|---|---|---|
| `COMPLETED` | 동일 idempotency key와 invocation digest에 대응하는 외부 결과 | 결과를 기존 출력 검사에 넣고 이어서 실행. 쓰기 전송 없음 |
| `NOT_EXECUTED` | 이전 키가 이후에도 커밋되지 못하도록 외부 시스템이 원자적으로 차단했다는 근거 | 기존 승인과 업무 인수를 유지하고 새 실행 세대·전송 키로 재개 |
| `UNKNOWN` | 영수증 없음, 조회 오류, 지문 불일치, 불완전한 응답, 차단 근거 없음 | 실패 상태 유지. 자동 재실행 없음 |

일반 조회에서 영수증이 없다는 사실만으로 `NOT_EXECUTED`를 반환하면 안 된다. 아직 처리 중이거나
네트워크에 남은 요청이 나중에 커밋될 수 있다. resolver의 `fenced`는 실제 boolean `True`여야 한다.
이 표의 근거를 보장하지 못하는 외부 서비스는 `UNKNOWN`을 유지한다.

## 실행 경계

`EffectJournal`은 승인·정책을 통과한 쓰기 직전에 정확한 invocation, 요청 digest, 전송 키와
`STARTED`를 저장한다. 전송 키는 tenant, run 생성 시각, task, 실행 세대, invocation에 묶인다.
설정형 HTTP POST는 `Idempotency-Key` 헤더를 사용한다. 외부 API가 이 헤더를 처리하는지는 별도
계약이며 헤더를 보냈다는 사실만으로 중복 방지를 보장하지 않는다.

정상 응답은 gateway의 기존 출력 검사 후 `COMPLETED`로 저장한다. 쓰기 이후 발생한 도구 오류,
모델 오류, 결과 검증 실패는 작업 전체를 다시 시도하지 않는다. HTTP POST·모델 task의 `maxAttempts=1`
제약도 유지한다. 다른 adapter도 쓰기가 있는 경우 같은 journal을 사용해야 이 복구 근거를 남길 수 있다.

모델 task의 checkpoint에는 도구 호출 ID, 이전 메시지, 다음 step을 함께 저장한다. 재개는 마지막
호출 위치를 복원한다. 이전 도구들을 처음부터 다시 실행하지 않는다. 이후에 승인 대기 중인 더 새로운
호출이 있으면 그 호출을 유지한다. 인수가 같더라도 별도 tool-use ID로 요청한 호출은 별개의 승인이다.

worker는 coordinator의 원자적 `checkpoint` 요청으로 기록한다. lease·fence·tenant·task 범위를
검사하며, 일반 snapshot 저장은 effect checkpoint를 덮어쓸 수 없다. 병렬 task의 checkpoint와
동시에 도착한 승인도 보존한다. lease가 만료된 worker는 결과 저장과 재실행 권한을 잃는다.

SQLite workflow store v3은 기존 run JSON에 선택적 checkpoint 필드를 추가한다. 입력·출력·승인·revision을
유지한다. 이전 실행에 checkpoint가 없다면 과거 효과를 추측해서 재실행하지 않는다.

## 연결과 API

호스트는 `RunControlService(..., effect_resolver=resolver)` 또는
`serve_local(..., effect_resolver=resolver)`로 신뢰할 수 있는 제품별 resolver를 주입한다.
resolver는 `(run, task_id, checkpoint)`를 받고 `EffectResolution`을 반환한다. 모델이나 API 요청자가
완료 여부를 선언하는 인터페이스가 아니다. resolver는 승인된 고정 서비스에만 접근하고,
인증된 계정·클라이언트·요청 지문을 검증해야 한다. 비밀키는 checkpoint나 영수증 evidence에 넣지 않는다.

```python
from agent_interlock.effects import EffectResolution, EffectStatus

def resolver(run, task_id, checkpoint):
    # 제품별 인증된 고정 API로 조회하고 요청 지문/계정 범위를 검사한다.
    receipt = lookup_verified_receipt(run, task_id, checkpoint)
    return EffectResolution(
        status=EffectStatus.COMPLETED,
        idempotency_key=checkpoint["idempotencyKey"],
        invocation_digest=checkpoint["invocationDigest"],
        evidence=receipt.reference,
        result=receipt.output,
    )
```

`POST /v1/runs/{runId}/reconcile`는 빈 JSON `{}`만 받는다. `run:approve`와 해당 프로젝트의
`deploy`·`read` 권한을 요구한다. 반환값은 `{run, effects}`이다. 완료 근거를 호출자가 본문에 넣으면
거절한다. resolver가 없으면 미확인 효과는 `UNKNOWN`으로 남는다.

모든 불확실한 task가 해결되면 run은 `PENDING`이 된다. 이후 기존
`POST /v1/runs/{runId}/resume`으로 실행한다. reconciliation 자체는 도구 실행이나 승인을 하지 않는다.
원래 bundle, 입력, 승인, 완료한 task는 유지한다. 명시적인 복구 시도의 task `attempts`는 0부터 시작하며,
이전 횟수는 `previousAttempts`와 ledger에 남는다. 메시지 사용량은 초기화하지 않는다.

`WORKFLOW_TASK_STATUS_UPDATED` 이벤트의 `effectPhase`, `effectState`, `idempotencyKey`,
`invocationDigest`로 dispatch·확인·복원을 연결한다. 원문 인수와 외부 결과는 보호된 run DB에 있고,
복구 이벤트에는 넣지 않는다. 기존 `securityMet` 집계에는 이전 제어 실패/차단도 남는다.
복구 완료 여부와 승인 밖 실제 전송 여부는 영수증·dispatch·control 이벤트를 함께 확인해야 한다.

## 실행 검증

```sh
uv run pytest tests/test_effect_recovery.py tests/test_distributed_failure.py \
  tests/test_distributed_model.py tests/test_provider_policy.py
```

분산 검사는 실제 worker subprocess를 외부 POST 직후 종료한다. coordinator를 재시작해도 두 번째
worker가 재실행하지 않는지, 이전 fence가 거절되는지, 인증된 결과 조회 후 쓰기 없이 완료하는지 확인한다.
잘못된 영수증·문자열 fencing 값·다른 tenant·취소·동시 갱신·병렬 checkpoint·출력 격리도 검사한다.

[실제 모델 평가](model-evaluation.ko.md)와 [provider 운영 정책](provider-operations.ko.md)은 별도 검증 축이다.
