"""Journal payload encoding shares the neutral Base contract."""

import pytest
from bt_api_base.gateway_direct_protocol import canonical_gateway_payload, gateway_payload_digest

from bt_api_gateway.direct_command_journal import DirectCommandJournalError, _json, payload_digest


def test_nested_canonical_bytes_and_digest_match_base():
    payload = {"中": [True, None, {"b": "值", "a": 1}], "a": 3}
    assert _json(payload) == canonical_gateway_payload(payload)
    assert payload_digest(payload) == gateway_payload_digest(payload)


@pytest.mark.parametrize("value", [{}, [], {"a": [1]}, {"a": {"b": 1}}])
def test_scalar_map_remains_nonempty_and_flat(value):
    with pytest.raises(DirectCommandJournalError, match="INVALID_PAYLOAD"):
        _json(value, scalar_map=True)


def test_gateway_retains_redaction_while_base_is_neutral():
    payload = {"api_key": "synthetic"}
    assert canonical_gateway_payload(payload)
    with pytest.raises(DirectCommandJournalError, match="INVALID_PAYLOAD"):
        _json(payload)


def test_scalar_map_accepts_flat_supported_values():
    payload = {"text": "中", "integer": 1, "flag": True, "missing": None}
    assert _json(payload, scalar_map=True) == canonical_gateway_payload(payload)
