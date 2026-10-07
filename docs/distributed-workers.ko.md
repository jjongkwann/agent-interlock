# 여러 서버에서 worker 실행하기

Control Plane 하나가 배포 저장소·SQLite 실행 상태·승인·작업 배정을 소유하고, 여러 서버의 worker가 인증된 API를 통해 작업을 가져간다. worker는 공유 파일 시스템에 접근하지 않는다. 하나의 run 전체를 한 worker가 맡으며, 서로 다른 run은 여러 worker에서 실행할 수 있다. run 안의 task 병렬성은 기존 실행 정책을 따른다.

이 구성은 여러 worker 서버를 지원한다. Control Plane 자체는 하나이며, 여러 Control Plane의 동시 쓰기나 자동 장애 조치를 제공하지 않는다. worker는 실행 입력과 자신의 credential을 처리하는 신뢰된 운영 서버다.

## 중앙 서버 설정

[Studio builder 시작 가이드](studio-builder.ko.md)에 따라 전용 디렉터리를 초기화한다. 중앙 서버의 `config.json`, 검토 키, 배포 bundle 및 SQLite 파일은 이 디렉터리에 유지한다. worker에 이 디렉터리를 복사하거나 네트워크 드라이브로 연결하지 않는다.

중앙 디렉터리에 권한 `0600`의 `workers.json`을 만든다. 각 worker에는 별도 토큰 환경변수와 실행 가능한 project ID를 지정한다.

```json
[
  {"subject":"worker-a","tokenEnv":"INTERLOCK_WORKER_A_TOKEN","projects":["my-project"]},
  {"subject":"worker-b","tokenEnv":"INTERLOCK_WORKER_B_TOKEN","projects":["my-project"]}
]
```

모든 project를 맡기는 경우 `projects`에 `"*"`를 지정한다. 토큰 값은 파일에 넣지 않고 운영 환경의 비밀 관리 수단으로 중앙 프로세스에 주입한다. 두 worker에 같은 토큰이나 subject를 사용하지 않는다. worker 토큰은 작업 실행 전용이며, 사람의 배포·실행 승인 권한이나 operator 토큰을 대신하지 않는다.

```sh
chmod 600 ./coordinator-data/workers.json
uv run interlock serve --data-dir ./coordinator-data --dispatch remote --port 8787
```

`--dispatch remote`에서는 중앙 프로세스가 run을 로컬 adapter로 실행하지 않는다. 실행할 수 있는 worker가 없으면 작업은 대기한다. worker 실패 시 로컬 실행으로 전환하지 않는다. Studio의 생성·검토·서명·ENFORCE 승격 및 호출별 승인 흐름은 유지된다.

중앙 HTTP 서버는 loopback에 둔다. 다른 서버에서 접속할 때는 `https://interlock.example.com` 같은 전용 HTTPS 주소를 reverse proxy로 연결하고, proxy가 `127.0.0.1:8787`로 전달하게 한다. 인증서 검증을 끄지 않으며 `Authorization` 헤더를 중앙 서버에 전달한다. 웹 Studio를 다른 origin에서 사용한다면 기존 `--origin` 설정도 적용한다. worker의 서버 간 통신에는 브라우저 CORS 설정이 필요하지 않다.

중앙 서버에서 다음 파일의 공개 식별자를 확인한다.

```sh
cat ./coordinator-data/bundles/deploy/target.json
```

이 파일의 `targetId`와 `tenantId`를 worker 시작 옵션에 고정한다. 저장소 복사는 target identity도 복사하므로, 독립된 배포 목적지에는 새 저장소 identity를 준비한다.

## worker 서버 설정

각 서버에 같은 AgentInterlock 버전과 필요한 실행 extra를 설치한다. worker A에는 `INTERLOCK_WORKER_A_TOKEN`, worker B에는 `INTERLOCK_WORKER_B_TOKEN`을 비밀 환경변수로 주입한다. 해당 값은 중앙 서버에 설정한 값과 일치해야 한다.

```sh
uv run interlock worker \
  --coordinator https://interlock.example.com \
  --token-env INTERLOCK_WORKER_A_TOKEN \
  --target-id '<target.json의 targetId>' \
  --tenant '<target.json의 tenantId>'
```

worker B는 별도 서버에서 같은 coordinator·target·tenant와 자신의 `--token-env INTERLOCK_WORKER_B_TOKEN`으로 실행한다. worker가 coordinator에 outbound 요청을 보내므로 worker 서버에 공개 수신 포트를 열 필요가 없다. worker를 먼저 켠 뒤 Studio에서 실행 준비 상태를 확인하고 배포를 승격한다. 원격 실행 준비 검사는 해당 project와 필요한 credential reference를 모두 처리할 수 있는 온라인 worker를 요구하며, 중앙 서버에 provider credential 값을 요구하지 않는다.

JSON_TRANSFORM만 실행한다면 provider credential이 필요 없다. HTTP 또는 Anthropic task는 검토된 `credentialRef`를 worker 로컬 환경변수에 연결한다.

```sh
uv run interlock worker \
  --coordinator https://interlock.example.com \
  --token-env INTERLOCK_WORKER_A_TOKEN \
  --target-id '<targetId>' --tenant '<tenantId>' \
  --credential-env crm=CRM_API_TOKEN \
  --credential-env anthropic=ANTHROPIC_API_KEY
```

위 옵션은 manifest의 `crm`, `anthropic` reference를 worker 환경변수에 연결하는 예다. worker는 reference 이름만 coordinator에 알리고 credential 값을 전송하지 않는다. 같은 reference는 모든 해당 worker에서 같은 tenant·외부 계정 권한을 의미해야 한다. 실제 credential이 필요한 작업은 해당 reference를 제공하는 worker에 배정한다.

로컬 통합 확인에만 `--coordinator http://127.0.0.1:8787 --allow-loopback-http`를 사용할 수 있다. 일반 서버 주소는 HTTPS여야 한다. `--poll-seconds`는 작업 조회 간격을 조절하며, `--once`는 한 번의 작업 조회/처리 후 종료하는 운영 확인에 사용한다.

## 충돌·승인·장애 처리

동시에 여러 worker가 같은 run을 요청해도 중앙 SQLite transaction에서 하나의 lease만 부여한다. 이후 start·heartbeat·저장·event 전송·finish는 worker identity, worker session, lease generation과 서버의 만료 시간을 확인한다. 오래된 worker의 결과는 최신 실행 상태를 덮어쓸 수 없다.

worker는 engine과 adapter를 실행하기 전에 중앙 서버에 시작을 영속 기록한다. 시작 전 lease가 만료된 작업은 다시 배정할 수 있다. 시작 후 lease가 만료되면 run은 `FAILED`와 `RUN-EFFECT-UNCERTAIN`으로 남고 자동으로 다시 실행하지 않는다. 이 규칙은 JSON 작업에도 적용된다. 외부 쓰기뿐 아니라 모델 요청이나 HTTP GET도 이미 전송되었을 수 있기 때문이다.

정상적인 호출 승인 대기는 다르게 처리한다. worker가 정확한 pending call과 model continuation을 저장하고 마지막 event를 전송한 뒤 lease를 해제한다. 사람이 승인하면 다음 worker는 저장된 인수·도구·definition digest·continuation을 이어서 사용한다. 앞선 모델 요청이나 완료한 도구를 다시 호출해 문맥을 재구성하지 않는다. 승인과 finish가 교차하더라도 승인된 대기 작업이 큐에서 사라지지 않도록 처리한다.

취소와 lease 상실은 후속 작업 시작 및 중앙 저장을 막는다. 이미 외부 서버로 보낸 요청을 취소하거나 되돌렸다는 뜻은 아니다. 응답을 잃은 run은 외부 서비스의 실제 상태를 확인한 뒤 운영자가 처리해야 한다. 자동 재시도나 정확히 한 번의 외부 실행을 보장하지 않는다.

lease 확인 직후 worker 프로세스가 정지했다가 늦게 다시 실행되는 상황까지 임의의 외부 endpoint에서 강제로 막을 수는 없다. 이 구현은 신뢰된 worker가 만료·통신 실패를 확인하면 작업을 중단한다는 전제를 사용하고, 시작된 작업을 다른 worker에 자동 재배정하지 않아 불확실한 중복 실행을 피한다.

## 작업 경계와 변경 적용

worker API는 `/v1/workers/claim`, `/start`, `/heartbeat`, `/get`, `/save`, `/append`, `/trace`, `/finish`의 POST 요청을 사용한다. worker에게 일반 배포 API나 실행 승인 API 권한을 추가하지 않는다. 작업의 tenant·project·bundle·run·trace와 사람의 승인 정보는 중앙 서버가 정한다.

구현을 병렬 수정할 때도 운영 디렉터리를 공유 작업 공간으로 사용하지 않는다. 개발자는 별도 Git worktree에서 맡은 파일만 수정하고, 통합 전에 patch에 `git apply --check`를 실행해 다른 작업의 미커밋 변경을 보존한다. 이 개발용 worktree 분리는 운영 worker가 동일 SQLite/Git 저장소를 공유한다는 뜻이 아니다.
