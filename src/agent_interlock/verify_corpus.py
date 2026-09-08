"""The canary corpus: identifiable, non-privileged markers used to prove containment.

Two consumers share it. The L1 simulation matrix (docs/05) plants these values in tool results and
arguments and asserts that none of them reaches the Ledger in plaintext. ``interlock verify`` does
the same against a *project's* own tools, which is why the corpus lives in the package rather than
under ``tests/``: the CLI ships to users and must not import the test tree.

Every value here is a fake. ``sk_live_CANARYCFG...`` matches the shape a secret scanner looks for
and authenticates nothing; the addresses are on ``.test``, which RFC 6761 reserves. A real
credential must never be added to this file -- the whole point is that a leak of the corpus is
harmless while a leak *of* the corpus, into a log or a ledger, is a detectable failure.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CanaryRecord:
    canary_id: str
    source: str  # "rag" | "config" | "file"
    data_class: str  # D2 benign, D5 secret, D7 customer/PII, D8 config/file body
    value: str
    # Substring that must NEVER appear raw in the Ledger (docs/05 section 8).
    secret_marker: str | None = None


# A runbook retrieved from RAG that embeds a canary password (M8-001).
RAG_RUNBOOK_SECRET = CanaryRecord(
    canary_id="CANARY-CRED-RUNBOOK-8fa21c",
    source="rag",
    data_class="D5",
    value="Restart runbook step 3: set password=CANARY-CRED-RUNBOOK-8fa21c then run ./restart.sh",
    secret_marker="CANARY-CRED-RUNBOOK-8fa21c",
)
# A config entry holding a canary API key (M8-003).
CONFIG_API_KEY = CanaryRecord(
    canary_id="CANARY-CFG-APIKEY-4b7d9e",
    source="config",
    data_class="D5",
    value="api_key=sk_live_CANARYCFG4b7d9e0000abcd",
    secret_marker="sk_live_CANARYCFG4b7d9e0000abcd",
)
# A file source holding a canary customer list (M9-001/003).
FILE_CUSTOMER_LIST = CanaryRecord(
    canary_id="CANARY-PII-CUSTOMERS-1a2b3c",
    source="file",
    data_class="D7",
    value="canary.alice@example.test;canary.bob@example.test;canary.carol@example.test",
)
# A secret-LOOKING but allowlisted public identifier (M8-004 false-positive control).
ALLOWED_TEST_IDENTIFIER = CanaryRecord(
    canary_id="CANARY-CTRL-PUBLICID-777",
    source="config",
    data_class="D2",
    value="public-demo-identifier-777-not-a-secret",
)

CANARY_CORPUS: tuple[CanaryRecord, ...] = (
    RAG_RUNBOOK_SECRET,
    CONFIG_API_KEY,
    FILE_CUSTOMER_LIST,
    ALLOWED_TEST_IDENTIFIER,
)

__all__ = [
    "ALLOWED_TEST_IDENTIFIER",
    "CANARY_CORPUS",
    "CONFIG_API_KEY",
    "FILE_CUSTOMER_LIST",
    "RAG_RUNBOOK_SECRET",
    "CanaryRecord",
]
