# LOAD01 market bootstrap batch round

Scope: add a bounded `market.bootstrap_many` operation to the Gateway market hub and its focused tests. The batch keeps per-key authorization, capacity, snapshot/head cursors, and subscription state; partial acquisition is rolled back with clean rejection distinguished from uncertain remote state. The SDK client uses batching only when the registered capability advertises it and retains the legacy path only for an explicit capability omission.

Gateway source pins at review: `src/bt_api_gateway/market_hub.py` 75,420 bytes, SHA-256 `52f1c9995fbc650d2e84534d8f26bf4e93795b7861ed08ef2cd04f3565324010`; `tests/test_market_hub.py` 44,585 bytes, SHA-256 `2c304c0f734170022124d8ac4d20b524ea2dcf0a6bfc6a80a8d8d7a51977bc25`. Independent static review found the batch controls sound. The previously run focused Gateway selection passed five tests; it was not rerun for this record. No Host or 100-process LOAD01 test ran. This is focused synthetic coverage, not formal LOAD01 acceptance.

The SDK-side required-descriptor epoch regression was separately reviewed after its fixture was corrected to make both batch head and snapshot epochs agree with each other while disagreeing with the required descriptor. That focused node passed once; it is not included in this child-package commit.
