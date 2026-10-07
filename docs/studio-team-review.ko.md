# 후보 검토와 팀 초안

## 배포 대상과 기존 저장소

`GitBundleStore`는 `deploy/target.json`에 target ID와 tenant를 한 번 저장한다. 승인 statement에는 이 두 값과 bundle·현재 active digest·mode·승인자·key ID가 포함된다. Studio의 연결 URL과 승인 context를 함께 확인한다. CLI 서명은 `interlock studio approve --repo <bundle-repository> ...`로 같은 저장소의 context를 사용한다.

CLI로 저장소를 처음 준비할 때 기본 `tenant-local`이 아닌 환경은 `--tenant <tenant-id>`를 지정한다. 기존 저장소에서는 생략해도 저장된 tenant를 사용하며 다른 tenant를 지정하면 거부한다. 예제 support host는 `--tenant tenant-acme`를 사용한다.

기존 저장소를 열면 target identity가 생성되며 기존 bundle·활성 배포·기록은 보존된다. 이전 형식의 대기 서명은 Git metadata의 `interlock-legacy-approvals-*.json`으로 보존하고 새 context로 다시 서명해야 한다. 기존 활성 배포는 계속 사용할 수 있다. target tenant와 다른 인증 주체는 Control Plane에 접근할 수 없다.

저장소 backup은 target identity도 보존한다. 서로 독립적인 배포 환경을 만들 때 기존 `target.json`까지 복제하지 않는다. 별도 저장소를 초기화하고 검토할 bundle을 다시 제안한다.

## 승격 전 비교

Deploy에서 초안을 compile·propose한 다음 대표 입력으로 후보 비교를 실행한다. 현재 active가 있으면 같은 입력으로 양쪽 task의 상태·출력·정책 판정을 비교한다. 활성 버전이 없으면 후보만 확인한다. 비교 결과의 input과 두 digest를 확인한다. 서버는 요청의 base digest가 현재 배포와 다르면 비교를 거부한다.

현재 비교는 **LOCAL JSON_TRANSFORM** 작업만 지원한다. HTTP·모델 작업은 어느 쪽도 실행하기 전에 거부한다. 별도 메모리의 orchestration과 정책 엔진을 ENFORCE로 실행하며 승인 대기는 자동 허용하지 않는다. 호스트의 활성 배포·실제 run·ledger·대기 서명은 바꾸지 않는다. 비교 결과는 임시이며 실제 운영 실행 기록이나 배포 승인으로 취급하지 않는다.

## 공동 초안과 권한

기본 로컬 호스트는 `projects.sqlite3`에 공동 초안을 저장한다. Studio에서 Deploy 연결을 설정하고 Projects → 공동 프로젝트에서 목록을 갱신한다. 기존 프로젝트는 서버의 최신 revision을 열고 수정한다. 저장 시 연결된 target ID와 읽었던 revision을 전송하며 먼저 저장한 다른 변경이 있으면 `PROJECT-REVISION-CONFLICT`로 거부한다. 현재 작업을 로컬 저장·export로 보존한 뒤 최신 초안과 합친다. 충돌 시 자동 덮어쓰기나 자동 병합은 하지 않는다.

별도 팀원은 데이터 디렉터리의 비공개 `principals.json`에 설정한다. 실제 bearer token은 지정한 환경변수에서 읽는다. 설정을 바꾼 뒤 host를 재시작한다.

```json
[
  {
    "subject": "designer-alice",
    "tokenEnv": "INTERLOCK_ALICE_TOKEN",
    "scopes": ["deploy:read", "project:read", "project:write"],
    "projects": {"refund-agent": ["read", "write"]}
  }
]
```

파일 권한은 `0600`으로 설정한다. subject와 실제 token은 서로 달라야 하며 `local-operator`를 재사용할 수 없다. 프로젝트의 `read`, `write`, `deploy` 권한과 API scope를 모두 검사하며 각 권한은 다른 권한을 자동 포함하지 않는다. `*`는 모든 프로젝트를 뜻한다. 배포에는 해당 프로젝트의 `deploy` 권한이 필요하며 run 생성·재개·승인·취소에는 `read`와 `deploy`가 모두 필요하다. 한 활성 배포를 다른 프로젝트로 바꾸려면 현재 프로젝트와 후보 프로젝트 모두의 배포 권한이 필요하다.

Ledger API는 tenant 전체를 조회하므로 전역 ledger scope는 모든 프로젝트를 읽을 수 있는 주체에만 허용한다. 제한된 팀원은 권한이 있는 run의 이벤트 API를 사용한다. 로컬 bootstrap의 서로 다른 두 signing key를 같은 사람이 갖고 있으면 두 사람의 독립 검토를 증명하지 않는다.

프로젝트가 제한된 주체의 실행 trace ID는 서버가 생성한다. 다른 프로젝트의 trace ID를 지정하여 이벤트를 섞을 수 없다. `interlock serve`는 loopback에만 바인딩하므로 다른 컴퓨터의 팀원은 관리자가 준비한 보안 터널이나 TLS reverse proxy로 같은 host에 연결해야 한다. Studio 공개 게시와 네트워크 접근 설정은 이 구현에서 수행하지 않는다.

팀은 중앙 Control Plane 하나의 tenant·활성 배포를 공유한다. 여러 서버의 실행은 [원격 worker 운영 가이드](distributed-workers.ko.md)를 따른다. lease와 revision으로 작업 소유권과 저장 충돌을 처리하며, 시작 후 결과가 불명확한 작업은 자동 재실행하지 않는다. 실시간 공동 커서·자동 병합·tenant별 독립 배포·Control Plane HA는 포함하지 않는다.
