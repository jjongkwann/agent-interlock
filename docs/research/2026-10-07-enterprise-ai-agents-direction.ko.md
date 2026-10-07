# 대기업 AI Agent 활용과 Agent Interlock 방향 점검

조사 기준일: **2026-10-07, Asia/Seoul**. 공개 기술 자료·공식 저장소·mini의 채용공고 원문·현재 로컬 코드를 대조했다. 이 문서는 조사와 제안이며 구현 변경이나 운영 적합성 인증이 아니다.

## 1. 판단

**Agent Interlock이 다루는 실행 권한·승인·증거 문제는 기업 수요와 맞는다. 개발 범위는 기존 에이전트 시스템에 연결하는 정책 집행과 검증으로 좁히는 편이 낫다.**

현재 시장에서는 에이전트 루프, 다중 에이전트, 세션, 도구 연결, tracing뿐 아니라 신원·정보 흐름·시간 순서 기반 정책·정확한 호출에 결합된 승인까지 기본 제품에 들어오고 있다. 따라서 “에이전트 프레임워크에는 보안이 없으니 전체 플랫폼을 만든다”는 설명은 유지하기 어렵다.

권고하는 제품 가설은 다음과 같다.

> 서로 다른 에이전트 실행 환경에서 기업의 업무 정책이 실제로 적용되는지 검증하고, 승인한 동작·실행 결과·외부 효과·재시도 판단을 연결해서 보여준다.

이 가설의 차별성도 아직 증명되지 않았다. 기존 제품만으로 같은 업무를 해결하는 기준선을 먼저 만들고, Interlock을 추가했을 때의 이익을 측정해야 한다. 독립 플랫폼의 구매 수요는 채용 공고만으로 확인할 수 없다.

| 판단 대상 | 권고 | 이유 |
|---|---|---|
| 정책·승인·검사 커버리지·실행 증거 | 유지하고 실제 업무에서 검증 | 현재 코드에 축적된 자산이며 기업 요구와 직접 연결 |
| 범용 Agent Builder·모델 실행기·분산 orchestrator 확장 | 신규 범위 확대를 보류 | SDK·관리형 플랫폼·LangGraph와 중복, 통합 비용 증가 |
| MCP/A2A transport·OS sandbox·일반 인증 | 기존 구현과 OSS를 활용하는 방향 평가 | 이미 강력한 공개 구현과 플랫폼 기능 존재 |
| Studio | 승인·원인 조사·불확실 결과 처리 중심 | 그래프와 일반 trace만으로는 차별성이 약함 |
| 독립 제품 사업화 | 조건부 | 실제 사용자·대체재 대비 가치·도입 비용 검증 필요 |
| 채용 포트폴리오 | 활용 가치가 높음 | SDK 통합·IAM·평가·장애 재현·운영 증거를 함께 보여줄 수 있음 |

## 2. 조사 범위와 근거 구분

- **공개 기능:** 공식 문서나 코드가 제공한다고 밝힌 능력. 이번에 모든 제품을 설치하거나 집행 동작을 재현한 것은 아니다.
- **실제 활용:** 기업이 공개한 내부 사용·제품 적용 사례. 성과 수치는 대체로 기업 자체 측정이며 회사 간 생산성 순위로 비교하지 않았다.
- **채용 수요:** 해당 팀이 공고에 적은 필수·우대·담당 업무. 전사 기술 스택이나 도입 완료의 증거로 확대하지 않았다.
- **프로젝트 사실:** 현재 로컬 코드·문서로 확인한 구현과 경계. 기존 미커밋 변경을 포함하며 공개 GitHub HEAD와 동일하다고 가정하지 않았다.
- **제안:** 위 근거를 종합한 판단. 경쟁 제품의 기능 부재나 고객 구매 의사로 단정하지 않았다.

최신성 확인에서 중요한 변경은 OpenAI Agents API의 **2026-09-10 public beta**, Google·Microsoft 보안 문서의 **2026-10-06 갱신**, Llama Stack의 **2026-04-28 OGX 전환**, 현재 Strands 저장소의 `harness-sdk` 통합이다. 발표일·문서 갱신일·저장소 확인일은 서로 다르다. [OpenAI changelog](https://developers.openai.com/api/docs/changelog), [OGX 전환](https://ogx-ai.github.io/blog/from-llama-stack-to-ogx), [Strands 현재 저장소](https://github.com/strands-agents/harness-sdk)

## 3. 빅테크는 어디에 에이전트를 쓰는가

| 기업 | 확인된 활용 | 기술과 운영 방식 | 근거의 범위 |
|---|---|---|---|
| OpenAI | 사내 데이터 분석, 연구 코드·실험·인프라 지원, 소프트웨어 개발 | 데이터·코드·조직 문맥을 RAG로 제공, 사용자 데이터 권한 상속, MCP 진입점, eval; 연구자는 목표·판단·배포 결정 유지 | 2026-01-29 데이터 agent와 09-06 연구 활용 자체 보고. 내부 데이터 agent 자체는 공개 제품이 아님. [데이터 agent](https://openai.com/index/inside-our-in-house-data-agent/), [연구 활용](https://openai.com/index/research-acceleration-view-inside-openai/) |
| Anthropic | 내부 연구개발·코딩 작업을 대규모 agent로 수행 | 실행 전 online monitor와 실행 후 offline monitor, 격리 환경, 인간 감독 | 2026-09-17 공개, 8월 측정. 동시 약 3만 agent와 10억여 결정은 자체 집계. 완전 자율 AL5 사례는 없다고 보고. [측정 보고](https://www.anthropic.com/institute/measuring-pace-of-ai-development) |
| Google | Agentspace·Customer Engagement 제품, 사내 기술 문서·개발 절차용 skills | ADK 기반 agent 제작, 도구·문맥·평가·배포 통합; skill 유무 비교와 제출 시/주간 eval | ADK의 실제 제품 사용과 내부 DevRel workflow 공개. 전사 직원 채택률은 이 자료에서 확인하지 않음. [ADK 발표](https://developers.googleblog.com/agent-development-kit-easy-to-build-multi-agent-applications/), [2026-08-04 Skills 운영](https://cloud.google.com/blog/topics/developers-practitioners/behind-the-scenes-how-we-build-test-and-scale-google-agent-skills) |
| Meta | 광고 ranking ML 실험, 성능 회귀 조사와 개선 PR 작성 | REA의 계획·실행·지속 메모리·compute budget; 성능 업무는 MCP tools + domain skills, 사람이 PR 검토 | 실제 내부 운영 사례. 모든 내부 framework가 공개 OSS인 것은 아님. [2026-03-17 REA](https://engineering.fb.com/2026/03/17/developer-tools/ranking-engineer-agent-rea-autonomous-ai-system-accelerating-meta-ads-ranking-innovation/), [2026-04-16 인프라 효율](https://engineering.fb.com/2026/04/16/developer-tools/capacity-efficiency-at-meta-how-unified-ai-agents-optimize-performance-at-hyperscale/) |
| AWS | Amazon Q Developer·Glue·VPC Reachability Analyzer에 Strands 사용 | 모델 중심 tool loop, 필요한 도구 retrieval, 실행 환경·신원·관측·정책을 AgentCore로 제공 | 2025-05-16 발표에서 실서비스 적용 명시. 전 직원 개인 비서 사용과 구분. [Strands 발표](https://aws.amazon.com/blogs/opensource/introducing-strands-agents-an-open-source-ai-agents-sdk/) |
| NVIDIA | 사내 취약점 triage와 보안 분석 | 검색·분석 tools, NeMo Agent Toolkit/blueprint, profiling·평가, 사람이 결과 사용 | 2025-04-28 사내 scale deployment 보고. 5~30분 절감은 분석가 추정. [공식 엔지니어링 사례](https://developer.nvidia.com/blog/advancing-cybersecurity-operations-with-agentic-ai-systems/) |
| Microsoft | 기업용 agent 제작·workflow·보안 기반 제공 | Agent Framework, typed workflow, middleware, OpenTelemetry, FIDES | 이번 근거는 공개 SDK·제품 설계 중심이다. 특정 Microsoft 내부 업무의 사용량은 확인하지 않았다. [AutoGen 이행 가이드](https://learn.microsoft.com/en-us/agent-framework/migration-guide/from-autogen/), [FIDES](https://learn.microsoft.com/en-us/agent-framework/agents/security) |

공통적으로 구체적인 도구와 데이터, 반복 가능한 평가가 있는 업무부터 확장한다. 단일 답변 생성에 머물지 않고 코드·실험·SQL·티켓·PR처럼 확인할 수 있는 결과를 낸다. 사람이 담당하는 목표 설정·승인·검토는 여전히 중요하다. OpenAI는 성공한 4~8시간 수준 과제의 절반 이상에 사람의 개입이 있었다고 밝혔고, Meta 성능 agent의 PR은 원인 변경 작성자에게 검토를 요청한다. 이런 보고를 무감독 전면 자동화의 증거로 읽으면 안 된다.

## 4. 공개 소프트웨어와 관리형 제품을 구분해야 한다

아래 라이선스는 해당 코드 구성요소 기준이다. 연결된 모델·외부 API·배포 서비스의 이용 조건까지 같은 것은 아니다. 주요 저장소는 공식 GitHub API의 현재 canonical URL과 라이선스도 대조했다. [9개 저장소 메타데이터](2026-10-07-agent-oss-repositories.json)의 `pushed_at`은 릴리스일이나 기능 안정화 시점을 뜻하지 않는다.

| 주체 | 공개 프로젝트 | 용도·상태 |
|---|---|---|
| OpenAI | [Agents SDK Python](https://github.com/openai/openai-agents-python) — MIT | agent loop·handoff·tools·guardrails·tracing·sandbox integration. 애플리케이션이 저장·배포·승인을 소유 |
| OpenAI | [Codex](https://github.com/openai/codex) — Apache-2.0 | 로컬 coding agent 코드. 상용 모델과 cloud 제품 전체 공개를 뜻하지 않음 |
| OpenAI | [Symphony](https://github.com/openai/symphony) — Apache-2.0 | 작업 보드에서 격리된 coding run을 운영하는 spec·reference. trusted environment용 engineering preview |
| Google | [ADK Python](https://github.com/google/adk-python) — Apache-2.0 | 도구·multi-agent·평가·배포 framework |
| Google | [Gemini CLI](https://github.com/google-gemini/gemini-cli) — Apache-2.0 | coding CLI와 native tool policy. 현재 Google CLI 전략에는 Antigravity 전환도 포함 |
| Google | [AX](https://github.com/google/ax) — Apache-2.0 | Task·Workspace·Model과 격리 실행을 다루는 개발 중 runtime. 대규모 목표를 운영 실적으로 간주하면 안 됨 |
| Anthropic | [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) — MIT | Claude Code 기반 harness를 프로그래밍으로 사용. SDK 공개와 Claude Code 전체 OSS는 다른 주장 |
| Anthropic | [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) — Apache-2.0 | OS 격리·network 제어를 위한 Beta Research Preview |
| Anthropic 기원 | [MCP](https://www.anthropic.com/news/donating-the-model-context-protocol-and-establishing-of-the-agentic-ai-foundation), [Agent Skills](https://agentskills.io/home) | 공개 연결 표준과 절차·지식 패키지 형식. MCP는 AAIF에 기부됨. 그 자체가 업무 승인·강제 격리를 완성하지는 않음 |
| Google 기원 | [A2A](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/) | agent 간 발견·작업·메시지·artifact 상호운용 표준 |
| Meta 기원 생태계 | [OGX](https://github.com/ogx-ai/ogx) — MIT | Llama Stack의 후속 명칭·방향. 여러 공급자 API와 MCP/RAG를 제공하는 server-side agentic API server. 재단 이전까지 확인된 것은 아님 |
| Meta | [LlamaFirewall](https://github.com/meta-llama/PurpleLlama/blob/main/LlamaFirewall/README.md), [CyberSecEval](https://github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/README.md) — 각 컴포넌트 MIT | scanner·정렬 검사·코드 검사와 보안 평가. 루트 저장소·모델 가중치 라이선스와 구별 |
| Meta | [ARE](https://github.com/facebookresearch/meta-agents-research-environments) — MIT | 시간에 따라 상태가 바뀌는 연구용 agent 평가 환경 |
| Microsoft | [Agent Framework](https://github.com/microsoft/agent-framework) — MIT | AutoGen·Semantic Kernel 팀의 후속 통합 방향. Python/.NET, workflow와 middleware |
| AWS 기원 | [Strands](https://github.com/strands-agents/harness-sdk) — Apache-2.0 | 현재 Python/TypeScript SDK·harness 통합 저장소. 예전 `sdk-python` URL은 이곳으로 이동 |
| NVIDIA | [NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit), [OpenShell](https://github.com/NVIDIA/OpenShell) — Apache-2.0 | agent workflow 분석·평가와 OS 수준 실행 격리 |
| IBM 저장소·커뮤니티 | [ContextForge](https://github.com/IBM/mcp-context-forge) — Apache-2.0 | MCP/A2A/API registry·proxy·plugin·인증·관측. IBM의 공식 지원·SLA가 있는 제품이라는 뜻은 아님 |
| Linux Foundation 생태계 | [agentgateway](https://github.com/agentgateway/agentgateway) | agent/MCP용 proxy·연결·보안 기반. 범용 gateway를 만들 때 비교해야 할 대체재 |

OpenAI **Agents API**, Anthropic **Managed Agents**, Google **Gemini Enterprise Agent Platform**, AWS **AgentCore**는 위 OSS와 구분할 관리형 서비스다. 관리형 agent는 세션·격리·복구·신원까지 제공하므로 직접 runtime을 개발할 이유를 더 좁혀야 한다. [OpenAI runtime 비교](https://developers.openai.com/api/docs/guides/agents), [Anthropic Managed Agents](https://www.anthropic.com/engineering/managed-agents)

최신 명칭에도 주의가 필요하다. Google은 2026-05-19 Gemini CLI의 consumer 경로를 Antigravity CLI로 옮기는 방향을 발표했고, Standard/Enterprise·paid API key 지원은 유지한다고 설명한다. AutoGen의 과거 인지도만으로 새 도입의 기본값을 결정하기도 어렵다. [Google 전환 안내](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli/), [Microsoft migration](https://learn.microsoft.com/en-us/agent-framework/migration-guide/from-autogen/)

Meta의 Confucius는 REA 내부 사용과 연구 논문을 확인했지만 공식 공개 SDK 저장소는 확인하지 못했다. Llama 모델 가중치의 Community License도 MIT/Apache 소프트웨어와 구분해야 한다. [현재 논문](https://arxiv.org/abs/2512.10398), [Llama4 라이선스](https://github.com/meta-llama/llama-models/blob/main/models/llama4/LICENSE)

## 5. Interlock과 직접 겹치는 보안 기능

| 대상 | 이미 제공하는 것 | 경계와 Interlock에 대한 의미 |
|---|---|---|
| OpenAI Agents SDK | input/output/tool guardrails, approval interruption, 직렬화 가능한 resume state, trace | agent-level 검사가 모든 tool에 적용되는 것은 아니다. function tool 경계와 hosted/MCP 경계를 각각 확인해야 함. [공식 범위](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals) |
| Claude Agent SDK | permission modes, hooks, 도구 승인 | `allowed_tools`는 자동 승인 목록이며 `canUseTool`을 건너뛸 수 있음. 전 호출 통제를 주장하려면 `PreToolUse`와 실제 tool/server 경계를 검사해야 함. [permissions](https://code.claude.com/docs/en/agent-sdk/permissions) |
| Google Agent Platform | SPIFFE 기반 agent identity, 단기 인증서·bound token, 위임, default-deny IAM gateway, audit, 외부 authorization extension | Cloud runtime 등 문서에 명시된 적용 경계가 있음. “신원·gateway가 없다”는 주장은 불가. [Identity](https://docs.cloud.google.com/iam/docs/agent-identity-overview), [Gateway](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview) |
| Google Semantic Governance | 자연어 constraints로 실행 전 tool call 판단 | preview이고 LLM 판정 오류 가능성을 명시. 이는 IAM의 결정적 정책 계층과 별개임. [문서](https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/semantic-governance-overview) |
| Microsoft FIDES | 신뢰·기밀 라벨 전파, 실행 전 결정적 차단, 정확한 호출·principal에 묶인 일회성 승인, session audit | **Interlock의 핵심 설명과 직접 겹침.** experimental·Python-only, 적용 설정과 UI 제약은 별도. 유일한 기능이라고 홍보할 수 없음. [2026-10-06 문서](https://learn.microsoft.com/en-us/agent-framework/agents/security) |
| AWS AgentCore Policy | Cedar-compatible Dogwood temporal policy, 이전 승인·인자/결과 매칭, count/sum·순서·freshness, LOG_ONLY/ENFORCE | 같은 account/Region, WAT 전파, 최대 24시간 창·session 범위 조건. 응답 기록에 의존하는 순차 호출 제약. “다른 제품은 stateless”라는 설명은 틀림. [temporal policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html) |
| OGX | tenant SQL 분리, OIDC·JWKS·ABAC, streaming guardrails | guardrails의 raw tool result·tool-call argument 검사 제외가 명시됨. tool authorization과 moderation을 분리해야 함. [멀티테넌트](https://ogx-ai.github.io/blog/ogx-multi-tenant-capabilities), [guardrails 범위](https://ogx-ai.github.io/blog/guardrails-responses-api) |
| NVIDIA OpenShell / Anthropic sandbox | 파일·process·network 격리, credential 노출 제한 | SDK wrapper가 제공할 수 없는 OS 경계는 기존 격리 runtime을 활용해야 함. [OpenShell](https://github.com/NVIDIA/OpenShell), [Claude containment](https://www.anthropic.com/engineering/how-we-contain-claude) |
| ContextForge | 인증·RBAC·SSO, schema/PII/secrets plugins, pre/post hook, OPA plugin, 관측 | 단순 MCP proxy·guardrail plugin은 이미 경쟁이 많음. 통합·기여가 자체 구축보다 나을 수 있음. [보안 기능](https://github.com/IBM/mcp-context-forge/blob/main/docs/docs/architecture/security-features.md), [지원 경계](https://github.com/IBM/mcp-context-forge/blob/main/SECURITY.md) |

따라서 **모델 중립·정책·로그·승인이라는 단어만으로는 차별성을 입증하지 못한다.** 실제 고객의 두 실행 환경에서 같은 금지 행위가 차단되고 같은 업무가 완료되는지, 실패 후 사람이 판단하는 시간이 줄어드는지를 보여줘야 한다.

## 6. 수집한 채용공고에서 확인한 수요

공개 채용공고의 비공개 로컬 수집본(`jobs.jsonl`) 누적 **5,294행**에서 관련 **공고·직무 기록 13건(고유 공식 공고 URL 11개)**을 선별해 검토했다. 원본의 회사명 라벨은 7개이며 NAVER와 NAVER Cloud는 같은 라벨로 묶여 있다. 최초 수집일 범위는 2026-07-27~10-07이고 파일 수정 시각은 10-07 09:23 KST였다. 후보 평가·지원서류는 읽지 않았으며 원격 데이터를 변경하지 않았다.

`found`는 게시일이 아니다. 동일 공고의 여러 직무·여러 수집 경로가 있을 수 있으며, 이 표는 시장 통계 표본이 아니다. 공식 상세 페이지/API를 대조했지만 모집 상태 확인 강도는 다르다. 아래 요약과 확인 방법은 [채용 근거 데이터](2026-10-07-enterprise-ai-agents-jobs.json)에 보존했다. 원문 전체를 재배포하지 않고 메타데이터와 요약만 남겼다.

| 기업·공고 | 확인한 요구 | 시점·확인 범위 |
|---|---|---|
| [SK AX 플랫폼 아키텍트 R261940](https://www.skcareers.com/Recruit/Detail/R261940) | 필수는 시스템·클라우드 운영과 AI 구조 이해. 업무에 A2A/MCP 연결, 인증·권한 전파, 관측·장애 대응. 비동기 큐·폐쇄망 경험 우대 | 공식 본문·Apply 버튼, 접수 09-11~11-20 |
| [SK AX Agent 개발자 R261939](https://www.skcareers.com/Recruit/Detail/R261939) | Python API·데이터·외부 연동 필수. Agent 개발 경험은 필수 아님. LangGraph/MCP·권한 기반 검색·정량평가·Tracing 우대 | 공식 본문, 같은 접수기간 |
| [SK AX Agent 엔지니어 R261936](https://www.skcareers.com/Recruit/Detail/R261936) | 비동기 API·tool calling/RAG·평가/디버깅 필수. Tool 권한·injection·guardrail·benchmark 우대 | 공식 본문, 같은 접수기간 |
| [LG CNS AI Architect 1001432](https://careers.lg.com/apply/detail?id=1001432) | Agent Architecture·Ontology·Graph DB·RAG/Python·REST. 공통 개발 플랫폼과 안정성·확장성 담당 | 공식 `recAvail=1`, `applyAvailable=Y`. 접수 시작 **03-11**, 마감 10-31; found 09-15와 구분 |
| [현대오토에버 210269](https://career.hyundai-autoever.com/ko/o/210269) | Agent orchestration·시스템 연계·MLOps. MCP 채널 연결 담당, A2A/MCP 개발 경험 우대 | 공식 상세 읽힘, 마감 10-29. 명시적 open flag와 같은 증거는 아님 |
| [삼성생명 솔루션 아키텍트 23284/14006](https://www.samsungcareers.com/hr/?no=23284) | API 연계와 **OAuth2/IAM/RBAC 설계 필수**. MCP 서버·Agent 플랫폼 우대. 승인·호출량·장애 추적·보안 감사 담당 | 공식 `isOpened=1`, 접수 10-02 09:00~10-12 17:00 |
| [삼성생명 AI 서비스 개발 23284/14008](https://www.samsungcareers.com/hr/?no=23284) | Python backend·LangChain/LangGraph multi-agent·MongoDB/Redis·context engineering. 금융 workflow와 모니터링 | 같은 공식 공고의 별도 직무 |
| [삼성생명 데이터 엔지니어 23284/14005](https://www.samsungcareers.com/hr/?no=23284) | 데이터 품질·검색·답변 정확도·메타데이터·Vector DB. 오답 분석과 검증 기준 운영 | 같은 공식 공고의 별도 직무 |
| [NAVER Agent 엔지니어 30005508](https://recruit.navercorp.com/rcrt/view.do?annoId=30005508) | planning/tool/memory·RAG·자동 eval harness·지표·CI/CD·Codex/Claude Code workflow 필수. observability·multi-agent·production 운영 우대 | 공식 원문 대조, 접수 09-30~10-12 10:00 |
| [NAVER Cloud AI Security 30005520](https://recruit.navercorp.com/rcrt/view.do?annoId=30005520) | 여러 직무: 학습데이터는 큐레이션·라벨링, RL환경은 sandbox/verifier/IaC, 공격·방어 agent는 orchestration/tool calling, Security-for-AI는 guardrail·LLM 보안, FDE는 현장 연동 | **5개 직무 묶음**, 한 사람의 필수요건으로 합치면 안 됨. 접수 09-30~10-14 17:00 |
| [쿠팡 AI Security Architect 8224844](https://www.coupang.jobs/kr/jobs/8224844/staff-ai-security-architect/) | AI/ML·클라우드·분산 시스템 위협모델, prompt injection/data poisoning, 보안 아키텍처·위험지표 | 공식 본문, 10-01 업데이트. 명시적 모집 중 상태는 미확인 |

추가 검토한 두 공고는 해석을 제한했다. [현대차 로봇 운영 2026_N2_347](https://talent.hyundai.com/apply/applyView.hc?recuYy=2026&recuType=N2&recuCls=347)은 로봇·통신·예외 처리 채용이며 LLM Agent는 우대사항이므로 일반 사무 agent 도입 증거로 쓰지 않았다. [LG CNS 신입 1002127](https://careers.lg.com/apply/detail?id=1002127)은 마감된 과거 사례다.

이 표에서 읽히는 수요는 **업무·데이터 연결, 신뢰할 수 있는 실행, 정량 평가, 운영·보안**이다. 기업이 외부 독립 Interlock 제품을 구매하겠다는 근거까지는 아니다. 채용 직무가 연구형·백엔드형·보안형으로 갈리므로 포트폴리오 설명도 지원 역할에 맞춰야 한다.

## 7. 현재 Agent Interlock의 자산과 부족한 증거

| 항목 | 현재 로컬에서 확인한 사실 | 판단 |
|---|---|---|
| 기존 코드 도입 | `define/connect/wrap`, Anthropic Tool Runner `guard_tools`·`bind_architecture` | 이미 있는 가벼운 도입 경로를 살릴 것. **Anthropic Tool Runner 지원은 Claude Agent SDK 지원과 다름** |
| 정확한 승인 | tenant·source/target·revision·policy·intent·arguments를 해시에 결합, 실행 직전 원자적 일회 소비 | 강한 구현 자산. FIDES와 직접 비교할 수 있으나 독점 기능은 아님 |
| 감사 증거 | 요청·정책 판단·집행·결과를 분리하고 coverage를 기록, SQLite/PostgreSQL·서명 audit 지원 | 일반 trace와 업무 증거를 연결하는 데 활용 가능. 모든 배포의 내구성·위변조 방지 보장은 별도 |
| 실패 처리 | 원격 worker가 시작한 작업의 lease 만료 시 `RUN-EFFECT-UNCERTAIN`, 자동 재실행 금지 | 결과 불확실성을 숨기지 않는 장점. 실제 외부 시스템 조회·조정과 연결해야 효용 입증 |
| 승인·멱등성 저장 | Gateway 호출 승인과 `_idempotency` 결과는 process-local | Ledger가 영속이라고 restart를 넘는 exactly-once가 되는 것은 아님 |
| 탐지 | tool description과 secret의 일부 탐지가 정규식 기반 | 특정 fixture 통과를 보편적 prompt injection 방어·DLP 성능으로 확대하면 안 됨 |
| 업무 평가 | `executed`, `goalMet`, `securityMet` 분리; 기본 acceptance는 구조적 문법 | 방향은 좋지만 실제 업무 품질, 정상 호출 오차단, 지연·검토시간 비교가 부족 |
| 통합 범위 | 설정 runtime은 JSON_TRANSFORM·HTTP_JSON·ANTHROPIC. 타 SDK adapter는 문서상 미완료 | framework 범용성을 주장하기 전에 실제 SDK 두 개에서 같은 업무 실행 필요 |
| 운영 규모 | 단일 Control Plane owner, 협력적 취소, 임의 in-process 작업 강제 중단 한계 | 엔터프라이즈 HA·대규모 멀티테넌트 제품으로 부르기에는 증거 부족 |

근거: [SDK](../../src/agent_interlock/sdk.py), [adapter](../../src/agent_interlock/adapters/anthropic_tools.py), [approval binding](../../src/agent_interlock/approvals.py), [Gateway](../../src/agent_interlock/gateway.py), [registry](../../src/agent_interlock/registry.py), [security helpers](../../src/agent_interlock/security.py), [acceptance](../../src/agent_interlock/orchestration.py), [도입 경계](../16-adding-interlock-to-an-agent.ko.md), [분산 worker](../distributed-workers.ko.md), [구현 상태](../06-implementation-status.ko.md).

바로 앞 프로젝트 확인 단계에서는 외부 전송 없는 email 예제와 core/support/refund 관련 **38개 테스트 통과**를 관찰했다. 이번 조사는 이를 전 제품 보안 감사, 실 API 성능, 브라우저 검증, 운영 배포 완료로 확대하지 않는다.

## 8. 권고하는 기술 구성과 개발 순서

### 유지할 구성

기존 agent가 작업을 계획하고 tool을 선택하는 구조를 유지한다. Interlock은 검증된 호출 신원과 입력을 받아 설치된 통제의 적용 범위·판정·승인을 기록하고, 실제 실행기/업무 시스템의 결과와 연결한다. native security를 무시하거나 그 위에 무조건 allow를 덮어쓰면 안 된다.

```text
기존 Agent SDK / 업무 애플리케이션
  → native tool hook·MCP server의 강제 검사 지점
  → 인증된 사용자·agent·위임 범위 + 업무 정책 + 필요한 승인
  → 기존 gateway / sandbox / 업무 API 실행
  → trace와 연결된 결정·실행 시작·결과·외부 receipt
  → Studio에서 결과 불확실성·재시도 가능 여부 조사
```

첫 검증의 보장 범위는 **등록된 도구 실행 경로에서의 정책·증거 의미 일치**다. SDK hook만 설치하고 다른 네트워크·쉘 경로를 열어 두면 우회 불가를 주장할 수 없다. 해당 업무의 credential과 endpoint를 실제 강제 경계에 묶어야 한다. MCP의 보안 지침과 native sandbox를 함께 사용한다. [MCP security practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)

공통 정책은 지원 가능한 작은 부분집합부터 명시한다. 한 플랫폼의 정보 흐름 label이나 temporal policy를 다른 플랫폼으로 손실 없이 옮길 수 있다고 가정하지 않는다. 지원하지 않는 조건은 `unsupported` 또는 관측 전용으로 표시하고 자동 완화하지 않는다. OpenTelemetry 연결도 버전이 바뀌는 semantic convention을 고정해 검증한다. [OpenTelemetry GenAI](https://opentelemetry.io/docs/specs/semconv/gen-ai/)

### 단계별 완료 조건

| 순서 | 작업 | 완료로 볼 증거 |
|---|---|---|
| 1 | 현재 미커밋 기준을 정리하고 통제별 적용 지점·우회 가능 경로·저장 범위를 문서화 | 코드·테스트·실행 경로가 연결된 coverage 표. 기능 개수 대신 어디에서 실제 검사하는지 확인 |
| 2 | 기존 Anthropic Tool Runner 예제 유지 + **OpenAI Agents SDK 어댑터 하나** | 같은 두 업무를 양쪽 실제 SDK dispatch로 실행. 입력 변경 승인 무효화·권한 차단·정상 완료를 재현 |
| 3 | native-only와 Interlock 추가 구성을 비교 | 같은 모델·도구·데이터·정책으로 task success, 금지 효과, 오차단, 지연, 승인 시간·복구 작업량 측정. 비교군에는 해당 업무에 필요한 native IAM·gateway·sandbox·승인까지 포함 |
| 4 | 호출별 승인·멱등성·effect 상태의 내구성 강화 | crash 위치별 복구 시험. 외부 완료 후 응답 유실 시 중복 실행 없이 확인·보류. 대상 API의 idempotency/receipt 한계 명시 |
| 5 | Studio를 조사·판단 화면으로 정리 | 승인한 인자, 사용 정책, 적용 검사, 실행 결과, 실제 효과, 현재 재시도 판단을 한 작업에서 추적 |
| 6 | 사용자 요구에 따라 LangGraph 또는 ADK 중 하나 추가 | 실제 통합 요청과 비교 효과가 있을 때만 추가. 모든 framework·언어를 한꺼번에 지원하지 않음 |

OpenAI SDK를 첫 추가 대상으로 삼는 이유는 현재 Anthropic 경로와 다른 실제 SDK에서 이식성을 검증하기 쉽기 때문이다. 국내 채용에서는 LangGraph 수요도 확인했으므로 목적이 특정 채용 포트폴리오라면 LangGraph를 앞당길 수 있다. LangGraph는 이미 durable execution·human-in-the-loop·state를 제공하므로 기존 workflow engine을 확대하기 전에 역할을 나눠야 한다. [공식 개요](https://docs.langchain.com/oss/python/langgraph/overview)

### 먼저 검증할 두 업무

1. **사내 문서·고객지원 티켓 업무:** 먼저 권한이 다른 문서 검색·답변 초안·티켓 분류를 완결한다. 다음으로 통제된 테스트 시스템에 티켓 생성 한 가지를 추가한다. RAG prompt injection, 개인정보 반출, 대상 변경, 중복 작성, approval 변경을 시험한다.
2. **제한된 IT 운영 업무:** 먼저 로그·지표 조회와 장애 원인 제안을 완결한다. 다음으로 승인된 테스트 환경의 설정 변경 한 가지와 결과 확인을 추가한다. 승인 대기 중 설정 변화, timeout, worker crash, 취소 이후 지연 완료를 시험한다.

현재 support/refund 예제는 회귀 기준으로 유지할 수 있다. 초기 비교에서 실제 결제·의료 판단까지 범위를 넓힐 필요는 없다. 그 영역은 별도의 도메인 품질·운영 요구가 크다.

### 직접 만들기 전에 비교할 것

- transport·registry·SSO: ContextForge/agentgateway와 기존 사내 API gateway 확장.
- agent loop·상태·장기 실행: 현재 사용하는 SDK/관리형 API/LangGraph의 기능.
- OS 격리·egress: OpenShell/sandbox-runtime/이미 배포한 플랫폼의 통제.
- scanner·보안 평가 corpus: LlamaFirewall/CyberSecEval/ARE 재사용 가능성과 라이선스 확인.
- authz 엔진: 요구가 커질 경우 OPA 또는 Cedar 계열과의 연결을 평가하되, 현 단계에서 새 정책 DSL을 먼저 만들지 않는다.

## 9. 성과 측정과 중단 기준

| 측정 | 확인할 질문 |
|---|---|
| 업무 성공률 | 정상 업무가 실제로 끝나는가? 안전을 이유로 전부 막아 점수를 높이지 않았는가? |
| 금지된 실제 효과 | 막았다는 로그 외에 대상 시스템에서 금지된 쓰기가 발생하지 않았는가? |
| 정상 호출 오차단 | 승인된 정상 업무 중 무엇을 잘못 막았는가? |
| 검사 적용률 | 주장한 통제가 모든 해당 호출에서 실제 실행됐는가? 미설치와 통과를 구분했는가? |
| 판단·실행·결과 일치 | 허용/차단 결정, tool dispatch, 최종 결과와 외부 receipt가 맞는가? |
| 재시작·중복·불확실성 | crash/timeout/retry 뒤 외부 효과가 한 번인지, 모르면 모른다고 남기는가? |
| 운영 부담 | 추가 p50/p95 지연, 모델 호출량, 승인 빈도·검토 시간, 조사 시간이 얼마나 늘거나 줄었는가? |
| 도입 노력 | 기존 agent 수정량·필수 인프라·정책 유지보수·타 SDK 이식 작업이 얼마인가? |

fixture 기반 결정적 회귀와 실제 모델 실행 평가는 분리한다. 모델·SDK 버전·도구 목록·데이터·seed/반복수·분모를 기록하고 보안/품질 judge의 판정 기준을 공개한다. 정책 통과율은 보안 정확도가 아니며, 모니터 적용률도 공격 탐지율이 아니다. 무오류 몇 회를 보편적 안전성으로 보고하지 않는다.

**중단 또는 전환 기준:** native 기능+ContextForge/FIDES/AgentCore/Google Agent Gateway 등으로 요구사항을 충족하고 Interlock 추가가 조사 시간·정책 이식·실제 오류를 줄이지 못하면 독립 제품 확대를 중단한다. 해당 생태계의 extension, 통합 예제, conformance test, upstream 기여로 전환하는 편이 타당하다.

사업화 검토를 진행하려면 서로 다른 두 조직 또는 팀이 같은 미충족 문제를 확인하고, 기존 시스템 유지 조건으로 도입할 의사가 있는지 확인해야 한다. 이는 후속 검증 제안이며 이번 조사에서 고객 인터뷰·구매 검증을 수행한 것은 아니다.

## 10. 검증 범위와 남은 불확실성

- 공식 기술 문서·저장소·기업 엔지니어링 사례를 읽고, 현재 로컬 코드와 비교했다. 웹 검색 요약만으로 결론을 정하지 않았다.
- 채용공고는 공개 내용만 읽었고 가능한 경우 공식 HTML/API 원문과 모집 정보를 대조했다. 현재 페이지 열림만으로 모두 모집 중이라고 표시하지 않았다.
- OSS 라이선스·저장소 이동을 확인했지만 구성요소 전체의 법률 검토를 수행한 것은 아니다.
- 벤더의 보안 기능·성능·격리 보장은 이번에 직접 설치·공격·부하 시험으로 검증하지 않았다.
- 경쟁사 내부 구현 전체, cross-cloud 효과 조정 기능의 존재 여부, 유료 고객 수요는 확인되지 않았다.
- 조사 결과만 추가했다. 기존 제품 코드, mini 서비스, 지원 상태, 배포 설정은 변경하지 않았다.
