# Managed support host

The managed path loads the full architecture from the exact GitBundleStore bundle promoted to `ENFORCE`. Tool definitions must match its reviewed digest. It records that bundle digest in invocation, control, result, and workflow evidence. `examples.support_agent.build.build()` remains the local-manifest example; it does not imply deployment approval.

The host executes the actual `lookup_order` and `send_email` Python callables through guarded tools. Its business data is simulated: orders come from a dictionary, and email appends to an in-memory outbox. PostgreSQL evidence, HTTP authentication, run persistence, policy decisions, and operator approval are real. Restarting loses the example outbox; replacing those business callables with real services is an application integration task.

## Prepare a reviewed bundle

Run from the repository checkout:

```sh
uv sync --extra postgres --extra jwt --extra anthropic
uv run python -m examples.support_agent.managed support-managed.json
uv run interlock architecture compile --shadow support-managed.json > support-bundle.json
uv run interlock studio propose --repo ./support-deploy --tenant tenant-acme support-bundle.json
```

Review this pinned manifest and bundle. Use the existing Studio deployment approval workflow or `interlock studio approve support-bundle.json --repo ./support-deploy` and `interlock studio promote` with two distinct trusted Ed25519 approvers and their required signing options. The first proposal binds the store to `tenant-acme`; later commands may omit `--tenant` to reopen that binding. An explicit different tenant is rejected. The host can start before promotion, but run creation requires the active `ENFORCE` deployment. Promotion must use the same `--bundle-repo` directory as the host.

The generated workflow runs a lookup, then waits for a human before sending email. Input contains exact argument objects under `lookup_order` and `send_email`. An operator approves the send task after inspecting those arguments. Run Control stores the operator identity; the support adapter uses that identity to grant a gateway approval bound to the exact tenant, source, tool revision, policy, intent, and arguments. A destination denial still blocks after approval.

## Configure durable evidence and authentication

Apply the packaged PostgreSQL migrations and provision a login bound to `tenant-acme` as described in [PostgreSQL Ledger operations](12-postgresql-ledger-api.md). The application login must be `NOSUPERUSER NOBYPASSRLS`, mapped in `interlock.role_tenant`, and inherit `interlock_event_api`. Inject its connection string through `INTERLOCK_POSTGRES_DSN`. The host checks connectivity and tenant binding at startup; it never replaces an unavailable PostgreSQL Ledger with memory.

Create `principals.json` with identities and token environment variable names, without secrets:

```json
[
  {"subject":"support-operator","tokenEnv":"SUPPORT_OPERATOR_TOKEN","scopes":["run:create","run:read","run:approve","run:cancel","deploy:read","events:read","statistics:read"]},
  {"subject":"deploy-operator","tokenEnv":"DEPLOY_OPERATOR_TOKEN","scopes":["deploy:read","deploy:propose","deploy:approve","deploy:promote"]}
]
```

Inject distinct bearer secrets through those variables. Supply `trusted-approvers.json` containing the public keys used for two-person bundle promotion:

```json
{
  "security-key": {"approverId":"security-reviewer","publicKeyHex":"<32-byte Ed25519 public key as 64 hex characters>"},
  "platform-key": {"approverId":"platform-reviewer","publicKeyHex":"<different 32-byte Ed25519 public key as 64 hex characters>"}
}
```

```sh
uv run python -m examples.support_agent.host \
  --bundle-repo ./support-deploy \
  --run-db ./support-state/runs.sqlite \
  --trusted-approvers trusted-approvers.json \
  --principals principals.json \
  --origin http://localhost:3000
```

Control Plane and Run Control listen on loopback port 8787; Ledger HTTP listens on 8788. Pass these URLs and the operator credential to Studio Live Attach. All HTTP requests need `Authorization: Bearer …`. Ledger HTTP also requires `X-Interlock-Tenant-Id: tenant-acme`; Control Plane derives the tenant from the authenticated principal. Browser origins must match `--origin`. Network deployment requires a separately configured HTTPS reverse proxy and application authentication policy.

Create and inspect a run:

```sh
curl -sS http://127.0.0.1:8787/v1/runs \
  -H "Authorization: Bearer $SUPPORT_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"input":{"lookup_order":{"order_id":"1001"},"send_email":{"to":"dana@customer.example","subject":"Order status","body":"Your order shipped."}}}'
```

Use the returned `run.id` to retrieve `/v1/runs/<id>`. When it reaches `WAITING_APPROVAL`, POST `{}` to `/v1/runs/<id>/tasks/send-email/approve` with the same headers. Review events at `/v1/runs/<id>/events`. Changing the recipient to `attacker@evil.example` demonstrates a blocked side effect, including after operator approval.

Run state, exact workflow inputs, dependency outputs, bundle digest, and approvals persist in SQLite. The database is private to one dedicated host process; POSIX file locks reject a second owner of either the same database or deployment repository. Deploy one host per deployment repository and run database. This is not a multiworker execution service. Only unfinished runs count toward the 1024-run capacity. Terminal runs remain available until explicitly pruned with `SQLiteWorkflowRunStore.prune(tenant_id=..., before=<UTC timestamp>)`; do not prune active runs. Interrupted executions recover conservatively instead of blindly replaying a possibly completed side effect.

## Tool Runner integration and installed hooks

```python
from agent_interlock.postgres_ledger import PostgreSQLLedger
from agent_interlock.studio_deploy import GitBundleStore
from examples.support_agent.managed import build

ledger = PostgreSQLLedger.from_dsn(dsn, bound_tenant_id="tenant-acme")
gateway, tools = build(store=GitBundleStore("support-deploy"), ledger=ledger)
runner = client.beta.messages.tool_runner(
    model=model, max_tokens=4096, tools=list(tools), messages=messages,
)
```

The returned tools stay pinned to that bundle for their lifetime. Rebuild them for a new promoted bundle. Without an explicit operator approval hook, external writes remain held. The managed host's workflow adapter supplies persisted human approval; it does not automatically approve Tool Runner requests.

Each `ToolBinding` accepts three host-owned hooks:

| Hook | Contract | Evidence |
|---|---|---|
| `classify(arguments)` | Nonempty collection of `D1`…`D8` classes | Invocation policy uses those classes |
| `estimate_export(arguments)` | Nonnegative integer `(record_count, byte_count)` | Record/byte cap checks use these estimates |
| `result_provenance(result)` | Mapping containing nonempty `dataClasses`; optional source metadata | Result evidence includes classification and provenance |

Managed construction requires all three hooks. The support hooks label known customer data `D3`, estimate one record and its canonical JSON byte size, and explicitly identify the local simulated business source. Application integrations must replace these declarations with their actual classification, export-size, and provenance knowledge.

Local adapters preserve the existing conservative `D3` input default when no classifier is installed and emit `installedHooks.classification: false`. Results without a provenance hook are explicitly `UNCLASSIFIED`; they are never inferred to be `D1`. Control events expose installed hook flags separately from policy coverage. Full graph registration, authored controls, and a present hook do not prove that uncalled external edges, arbitrary output DLP, downstream receipts, or business data classification accuracy are enforced.

Verify the managed path without external model calls:

```sh
uv run pytest -q tests/test_managed_runtime.py
```

These checks exercise actual support callables, signed two-person promotion, allowed/denied calls, exact digest mismatch rejection, export estimation, unclassified result evidence, SQLite-backed human approval, and the host ownership lock. PostgreSQL connectivity requires the configured database and is checked separately at host startup.
