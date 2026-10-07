# Studio에서 만들고 실행하기

이 경로는 Python adapter를 새로 작성하지 않고 Studio에서 runtime을 구성하고, 검토·서명한 bundle을 로컬 host에서 실행한다. 먼저 외부 호출이 없는 JSON 변환 starter로 전체 흐름을 확인한다. 지원 runtime은 JSON 변환, 고정 HTTPS JSON 요청, Anthropic agent다. 그 밖의 protocol이나 임의의 Python 코드는 이 host의 실행 대상이 아니다.

## 1. 처음 한 번 준비하기

Python 3.11+, Node 22.13+, Git이 필요하다. 로컬 host는 macOS/Linux의 파일 잠금을 사용한다. 저장소 루트에서 실행한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[jwt]'
interlock serve --data-dir ../agent-interlock-local --port 8787 --origin http://localhost:3102
```

`--data-dir`은 명시적으로 선택한 전용 디렉터리다. 새 디렉터리는 0700으로, 설정·token·key·SQLite 파일은 0600으로 만든다. 기존 디렉터리가 다른 사용자에게 열려 있으면 시작을 거부하므로 전용 위치의 권한을 먼저 확인한다. Host는 `127.0.0.1`에만 bind한다.

Host가 출력하는 것은 API URL, tenant ID, 다음 파일의 **경로**다. Token이나 private key 값은 출력하지 않는다.

| 파일 | 용도 |
| --- | --- |
| `operator.token` | Studio의 Bearer token 칸에 입력할 로컬 운영 token |
| `reviewers/reviewer-1.key`, `reviewer-2.key` | 서로 다른 reviewer의 Ed25519 seed, 각각 64자리 hex 텍스트 |
| `trusted-approvers.json` | Host가 검증에 사용하는 공개키와 reviewer ID |
| `config.json` | 고정 tenant ID와 credential reference→환경변수 이름 설정 |
| `ledger.sqlite3` | 판정·실행·결과 이벤트 |
| `runs.sqlite3` | Run 상태·입출력·bundle digest·workflow 승인 |
| `bundles/` | 제안한 bundle, active 배포, 서명된 승인 metadata를 보존하는 Git 저장소 |

두 key를 같은 사람이 가지고 있으면 **두 사람의 검토를 증명하지 않는다**. Bootstrap은 로컬 흐름을 확인하기 위한 두 신원이다. 실제 운영에서는 서로 다른 reviewer에게 key를 나눠 보관하고 공개 trust를 관리한다. 서버에는 서명용 HTTP API가 없으며 reviewer key 파일은 HTTP로 제공하지 않는다. 재시작 때에도 private reviewer key를 읽지 않는다.

별도 터미널을 저장소 루트에서 열어 Studio를 시작한다.

```bash
cd studio
npm ci
npm run dev -- --port 3102
```

브라우저에서 `http://localhost:3102`를 연다. 다른 Origin을 쓰려면 host의 `--origin`을 정확한 값으로 바꾼다. 여러 Origin은 `--origin`을 반복한다.

## 2. 외부 호출 없이 첫 실행

1. **Projects → Working local starter**에서 Project name과 Input field를 입력하고 **Create working starter**를 누른다. Agent, JSON 변환 Tool, 정책 edge, workflow task가 함께 만들어진다.
2. **Deploy**에서 Control plane URL을 `http://127.0.0.1:8787`로 설정한다. `operator.token` 파일을 직접 열어 Bearer token에 입력하고 **Refresh status**를 누른다. Tenant 기본값은 `tenant-local`이다.
3. **Compile current draft**를 누른다. 서버가 manifest와 runtime 설정을 검사하고 tool definition digest를 고정한다. Readiness에서 누락된 설정이 있으면 Design으로 돌아가 수정한다. **Propose to review store**로 검토 대상 bundle을 저장한다.
4. 현재 배포와의 변경점 및 서버가 발급한 승인 context를 읽고 검토 확인란을 선택한다. Trusted approver에서 `reviewer-1`을 선택하고 그 사람의 key 파일로 브라우저에서 서명한 뒤 승인을 제출한다. `reviewer-2`도 동일한 bundle/context를 검토·서명·제출한다. Private seed는 브라우저 메모리에서만 사용하고 서버로 보내지 않는다.
5. **Promote**로 ENFORCE 배포를 활성화한다. 단순히 선을 그리거나 compile에 성공한 상태는 실행 중인 배포가 아니다.
6. **Runs**에서 입력 필드를 채우고 run을 시작한다. 완료 상태와 task 결과를 확인하고 **Runtime** 또는 **Statistics**에서 해당 run의 trace와 판정·실행 이벤트를 살펴본다.

입력 `message`를 만든 starter는 그 값을 JSON 결과로 변환한다. 이 경로는 API key, 외부 model 호출, 별도의 Python handler가 필요 없다. 설계를 고치면 다시 compile→검토→서명→promote한다. 이미 시작한 run은 원래 승인한 bundle을 계속 사용한다.

## 3. 다른 runtime 구성

Actor의 **Runtime** 설정에서 실행 종류와 필요한 값을 채운다.

- **JSON 변환:** JSON template과 입력 매핑을 지정한다. 값 참조는 `{"$path":"input.message"}`처럼 정해진 입력 경로만 사용하며 Python·JavaScript 표현식을 실행하지 않는다.
- **HTTPS JSON:** 고정 HTTPS endpoint, GET/POST, 인자 매핑, purpose, data class를 지정한다. Endpoint host는 Tool의 허용 domain에도 있어야 한다. POST에는 실제 부작용과 필요한 승인 정책을 선언한다. 런타임은 검토한 endpoint를 사용하고 사설·loopback 목적지를 허용하지 않는다.
- **Anthropic agent:** 사용하려는 model, system prompt, token·step 상한, credential reference, provider Actor, purpose·data class를 지정한다. Agent→provider REL-07과 Agent→Tool REL-05 관계 및 workflow task도 구성한다. 기본값은 task의 대상 Tool 하나이며, **Choose tools explicitly**로 `toolActorIds`에 검토한 Tool을 최대 20개 선택할 수 있다. 선택한 도구마다 REL-05와 목적·데이터 범위를 검사하고 한 turn에 하나씩 호출한다. 최종 결과는 `{ "text": "..." }`다. Model은 사용자의 API 계정에서 사용할 수 있는 값을 선택한다.

도구 입력은 기본적으로 `input.tasks.<taskId>`에서 받는다. JSON 변환·HTTPS 도구는 `arguments` 매핑으로 `input.<field>` 또는 `dependencies.<taskId>.<field>`를 선택할 수 있다. Model task 입력은 `input.tasks.<taskId>`와 직접 선행 task의 결과다. Model 제공자에게 보내는 요청과 도구 결과도 REL-07 정책을 거친다. 외부 쓰기 승인은 대기 화면의 실제 인수·목적지·definition digest·request ID에만 적용된다. Model이 다음에 요청한 호출은 별도 승인 대상이다.

Model task와 HTTP POST task의 maxAttempts는 1이어야 한다. 응답 시간 초과 뒤 이미 발생한 외부 쓰기를 자동 반복하지 않는다. 실제 model·HTTPS 실행은 구성한 외부 시스템에 요청한다. 로컬 JSON starter와 달리 provider 사용량 또는 외부 부작용이 발생할 수 있다. Runtime 종류를 고르는 것만으로 충분하지 않으며, host readiness가 사용하는 task·정책·credential reference를 함께 검사한다.

## 4. Credential은 host에서 연결하기

브라우저와 manifest에는 API secret을 입력하지 않는다. Host를 중지하고 `config.json`의 `credentialEnv`에 reference와 **환경변수 이름**만 추가한다.

```json
{
  "version": 1,
  "tenantId": "tenant-local",
  "credentialEnv": {"anthropic-main": "ANTHROPIC_API_KEY"}
}
```

실제 값은 host를 실행하는 환경에 설정한다. Anthropic runtime을 사용할 때는 해당 가상환경에 `python -m pip install -e '.[anthropic,jwt]'`로 adapter extra를 설치한다. Host를 다시 시작하면 Studio에서 `anthropic-main` reference를 선택할 수 있다. Host status에는 reference와 설정된 환경변수 이름, 로드 여부가 나오며 secret 값은 나오지 않는다. 누락된 reference는 config.json의 매핑과 host 시작 환경을 확인한 뒤 재시작한다. 설정 파일에 없는 reference로 임의의 환경변수를 읽을 수 없다. 환경변수가 비어 있으면 해당 reference는 unavailable 상태다.

## 5. 저장·재시작과 운영 경계

Projects의 로컬 저장은 브라우저에 남는다. **공동 프로젝트 / Shared projects**에서는 연결된 host에 초안을 저장하고 최신 revision을 열 수 있다. 동시 저장은 revision 충돌로 거부하며, 먼저 로컬 저장·export로 작업을 보존한 뒤 최신 공동 초안에 변경을 합친다. 승인 bundle과 run·ledger는 host의 `--data-dir`에 별도로 보존된다. Host는 데이터 디렉터리와 bundle repository를 잠그므로 동일 저장소를 두 host가 동시에 실행하지 못한다.

Host 종료는 새 실행을 막고 worker 종료를 최대 10초 기다린다. 임의의 in-process adapter를 강제 중단하거나 이미 발생한 외부 효과를 되돌리는 보장은 없다. 재시작 시 저장된 RUNNING run은 `RUN-INTERRUPTED`인 FAILED가 되며 부작용을 자동 재실행하지 않는다. PENDING·WAITING_APPROVAL run은 원래 bundle로 명시적으로 resume한다. 완료·실패·취소 run은 active 용량을 차지하지 않고 명시적으로 prune할 때까지 조회 가능하다.

SQLite Ledger는 이벤트를 append-only로 저장하고 읽을 때 canonical integrity hash를 검증한다. 로컬 파일을 소유한 운영자가 파일 전체를 바꿀 수 있으므로 외부 WORM 보관을 대체하지 않는다. Gateway의 호출 승인과 멱등 실행 결과 cache는 process-local이다. Durable Ledger만으로 재시작을 넘는 exactly-once 외부 실행이 보장되지는 않는다. Run 입력·출력도 보존하므로 데이터 디렉터리와 backup을 비공개로 관리한다.

Control Plane은 단일 배포 owner를 가진다. 기본 모드는 로컬 실행이며, 여러 서버에서 실행하려면 [원격 worker 운영 가이드](distributed-workers.ko.md)의 `--dispatch remote`를 사용한다. Tenant로 조회를 나누는 API가 공유 SaaS의 tenant별 독립 배포를 제공하지는 않는다. Control Plane HA와 tenant별 독립 배포는 별도 작업이다. 저작한 control, 설치된 hook, 실제 관측한 판정 이벤트를 구분해서 coverage를 읽는다.

이미 준비된 PostgreSQL Ledger를 사용하려면 `--postgres-dsn-env INTERLOCK_POSTGRES_DSN`을 추가하고 기존 tenant 범위 DSN을 환경에 설정한다. Host는 연결·조회만 확인하며 schema 생성이나 migration을 자동 실행하지 않는다. Migration은 [PostgreSQL 운영 문서](12-postgresql-ledger-api.ko.md)에 따라 별도로 관리한다. SQLite run 저장은 그대로 사용한다.

문제가 생기면 Bearer token, tenant, 정확한 Origin, runtime readiness 순서로 확인한다. 기존 [SDK 도입](16-adding-interlock-to-an-agent.ko.md)은 직접 작성한 Python 도구를 연결하는 경로이며 이 Studio builder 경로와 구분된다.

후보 비교, target 서명 migration, 팀원 설정과 공동 초안은 [팀 검토 안내](studio-team-review.ko.md)를 참고한다.
