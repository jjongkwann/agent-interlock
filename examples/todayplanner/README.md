# todayPlanner 일정 변경과 장애 복구

실제 todayPlanner의 Express API, OAuth 인증, SQLite 저장소를 무작위 loopback 포트에서 실행한다. 폐기 가능한 인증 계정과 일정 한 개를 생성하며 개인 일정이나 운영 서버에는 접근하지 않는다. 제품 저장소에 이 작업의 영수증 API 변경이 있어야 한다.

```sh
PYTHONPATH=src python -m examples.todayplanner.run \
  --todayplanner ../todayPlanner \
  --evidence-dir /tmp/interlock-planner-evidence
```

Node 24 이상과 todayPlanner의 설치된 npm 의존성이 필요하다. `--evidence-dir`에는 새 디렉터리를 지정한다. 실행 후 `report.json`, `runs.sqlite3`, `ledger.sqlite3`에 결과와 증거를 남기고, 제품의 임시 계정·일정 DB와 서버는 정리한다. 옵션을 생략하면 Interlock 증거도 임시 디렉터리와 함께 정리한다. 보고서와 ledger에 OAuth 토큰을 기록하지 않는다.

1. DAG가 일정을 읽고 변경 승인을 기다린다. 승인 전에는 HTTP 변경 요청이 없다.
2. 정확한 일정 ID·revision·시각 변경을 승인한다. `operationId`는 모델 인수가 아닌 Interlock의 영속 실행 세대에서 생성한다.
3. 프록시가 제품의 커밋 후 HTTP 연결을 끊는다. 실행은 `RUN-EFFECT-UNCERTAIN`으로 멈춘다. SQLite run/ledger를 다시 열고 같은 계정·클라이언트·요청 지문의 영수증으로 `COMPLETED`를 확인한다. 쓰기를 반복하지 않고 결과 검사와 뒤의 읽기 검증을 재개한다.
4. 다음 변경에서는 커밋 전 연결을 끊는다. 영수증 부재는 `UNKNOWN`으로 남겨 재개하지 않는다. 제품의 원자적 resolve가 이전 키를 영구 차단한 후 `NOT_EXECUTED`를 반환한다. 동일하게 승인된 변경을 새 전송 키로 실행하고 읽어서 확인한다.
5. 승인 없는 호출·허용하지 않은 목적은 gateway에서 차단한다. 읽기 전용 OAuth 토큰의 쓰기, 다른 계정 일정 변경, 다른 계정 영수증 조회, 다른 요청 지문, 봉인한 키의 늦은 요청, 완료한 키의 재전송도 검사한다. 각 승인된 변경은 revision을 정확히 한 번 증가시켜야 한다.

제품 영수증은 `GET /api/operations/:operationId?fingerprint=<sha256>`로 조회한다. `POST /api/operations/:operationId/resolve`의 `{fingerprint}`는 저장 결과가 없는 요청을 `not_executed`로 봉인한다. 누락된 영수증을 미실행으로 간주하지 않는다. API의 SHA-256은 `JSON.stringify(['PATCH', '/api/tasks/'+taskId, expectedRevision, parsedPatch])`로 계산하며 이 연결기는 `startMinute` 한 필드만 허용한다.

```sh
TODAYPLANNER_ROOT=../todayPlanner uv run pytest tests/test_example_todayplanner.py
```

검증 범위는 로컬 제품 API와 영속 실행 복구다. 운영 배포, 브라우저 화면, 모바일 동기화, 알림은 이 예제에서 검증하지 않는다.
