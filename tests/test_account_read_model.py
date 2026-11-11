"""Local owner-published account model; no native provider or account access."""

import os
import signal
import threading
from dataclasses import replace

import pytest
from bt_api_base.service_protocol import WireScope

from bt_api_gateway import GatewayCommandKind, GatewayEventJournal, GatewayPrincipal
from bt_api_gateway.account_read_model import GatewayAccountReadModel
from bt_api_gateway.account_session_worker import GatewayAccountSessionWorkerError
from bt_api_gateway.service_component import (
    GatewayReadService,
    GatewayServiceAccountScope,
    GatewayServiceError,
)
from test_account_session_worker import Clocks, _identity, _observation, _resource


def _setup(tmp_path, clocks=None):
    clocks = clocks or Clocks()
    journal = GatewayEventJournal(tmp_path / "readmodel.db", clock=clocks.utc)
    authority = {"generation": "gen-1", "calls": []}

    def check(generation):
        authority["calls"].append(threading.current_thread())
        if authority["generation"] != generation:
            raise GatewayAccountSessionWorkerError("SESSION_OWNERSHIP_LOST")

    model = GatewayAccountReadModel(
        journal,
        account_key=_identity(),
        journal_account_scope="account:shared",
        state_scope="strategy:account-facts",
        required_coverage=(_resource(),),
        assert_current_generation=check,
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
    )
    model.start_generation("gen-1")
    return model, journal, clocks, authority, check


def test_cross_thread_reads_are_cache_only_and_invalidated_before_query(tmp_path):
    model, _, clocks, authority, _ = _setup(tmp_path)
    token = model.begin_refresh()
    observation = _observation(clocks, observation_id="obs-1")
    snapshot = model.finish_refresh(token, observation)
    assert model.ready and model.latest_snapshot is snapshot
    owner_checks = len(authority["calls"])
    result = []

    def read():
        result.append((model.latest_snapshot, dict(model.read_status())))
        with pytest.raises(GatewayAccountSessionWorkerError, match="WRONG_THREAD"):
            model.begin_refresh()

    thread = threading.Thread(target=read)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive() and result[0][0] is snapshot and result[0][1]["ready"]
    assert len(authority["calls"]) == owner_checks
    token2 = model.begin_refresh()
    result.clear()
    thread = threading.Thread(target=read)
    thread.start()
    thread.join(timeout=2)
    assert result[0][1]["ready"] is False
    assert model.finish_refresh(token2, observation) is snapshot
    assert model.ready
    with pytest.raises(GatewayAccountSessionWorkerError, match="TOKEN_INVALID"):
        model.finish_refresh(token2, observation)
    model.close()
    assert model.read_status()["ready"] is False


def test_same_observation_cannot_refresh_ttl_or_rewind_time(tmp_path):
    model, _, clocks, _, _ = _setup(tmp_path)
    observation = _observation(clocks, observation_id="obs-1")
    model.finish_refresh(model.begin_refresh(), observation)
    first = model.read_status()["fresh_for_seconds"]
    clocks.advance(1)
    before = model.read_status()["fresh_for_seconds"]
    assert 0 < before < first
    model.finish_refresh(model.begin_refresh(), observation)
    assert model.read_status()["fresh_for_seconds"] <= before
    clocks.monotonic -= 0.5
    assert model.read_status()["ready"] is False
    clocks.monotonic += 0.5
    assert model.read_status()["ready"] is False


def test_failed_read_generation_change_and_reopen_are_not_current(tmp_path):
    model, journal, clocks, authority, check = _setup(tmp_path)
    observation = _observation(clocks, observation_id="obs-1")
    first = model.finish_refresh(model.begin_refresh(), observation)
    token = model.begin_refresh()
    model.fail_refresh(token)
    assert model.read_status()["ready"] is False
    token = model.begin_refresh()
    authority["generation"] = "gen-2"
    model.start_generation("gen-2")
    assert model.latest_snapshot == first and model.read_status()["ready"] is False
    with pytest.raises(GatewayAccountSessionWorkerError, match="TOKEN_INVALID"):
        model.finish_refresh(token, observation)
    model.close()
    authority["generation"] = "gen-3"
    reopened = GatewayAccountReadModel(
        journal,
        account_key=_identity(),
        journal_account_scope="account:shared",
        state_scope="strategy:account-facts",
        required_coverage=(_resource(),),
        assert_current_generation=check,
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
    )
    reopened.start_generation("gen-3")
    assert reopened.latest_snapshot == first and reopened.read_status()["ready"] is False
    with pytest.raises(GatewayAccountSessionWorkerError, match="INVALID_SESSION_GENERATION"):
        model.start_generation("gen-2")


def test_incomplete_or_stale_observation_and_lost_authority_never_publish_current(
    tmp_path, monkeypatch
):
    model, journal, clocks, authority, _ = _setup(tmp_path)
    observation = _observation(clocks, observation_id="obs-1")
    token = model.begin_refresh()
    with pytest.raises(GatewayAccountSessionWorkerError, match="OBSERVATION_INCOMPLETE"):
        model.finish_refresh(token, replace(observation, positions_complete=False))
    assert model.read_status()["ready"] is False
    token = model.begin_refresh()
    original_replace = journal.replace_state_snapshot

    def lose_authority(*args, **kwargs):
        result = original_replace(*args, **kwargs)
        authority["generation"] = "other"
        return result

    monkeypatch.setattr(journal, "replace_state_snapshot", lose_authority)
    with pytest.raises(GatewayAccountSessionWorkerError, match="SESSION_OWNERSHIP_LOST"):
        model.finish_refresh(token, observation)
    assert model.read_status()["ready"] is False
    assert model.latest_snapshot is not None  # durable but diagnostic only
    authority["generation"] = "gen-1"
    monkeypatch.setattr(journal, "replace_state_snapshot", original_replace)
    with pytest.raises(GatewayAccountSessionWorkerError, match="OBSERVATION_REPLAYED"):
        model.finish_refresh(model.begin_refresh(), observation)
    assert model.read_status()["ready"] is False
    model.finish_refresh(model.begin_refresh(), replace(observation, observation_id="obs-2"))
    assert model.read_status()["ready"] is True


class _OwnerLinkError(Exception):
    """Stands for an owner's own finding, such as a session that became unavailable."""


@pytest.mark.parametrize("when", ["before_the_state_write", "after_the_state_write"])
def test_the_owners_own_authority_error_is_handed_back_unrenamed(tmp_path, monkeypatch, when):
    """I63-E148: the owner's authority callback can fail because its link dropped. The refresh
    used to rename that to OBSERVATION_INVALID or STATE_WRITE_FAILED, which an owner cannot tell
    from a broken read model."""
    clocks = Clocks()
    journal = GatewayEventJournal(tmp_path / "readmodel.db", clock=clocks.utc)
    state = {"error": None}

    def check(_generation):
        if state["error"] is not None:
            raise state["error"]

    model = GatewayAccountReadModel(
        journal, account_key=_identity(), journal_account_scope="account:shared",
        state_scope="strategy:account-facts", required_coverage=(_resource(),),
        assert_current_generation=check, clock=clocks.utc, monotonic_clock=clocks.mono)
    model.start_generation("gen-1")
    observation = _observation(clocks, observation_id="obs-1")
    dropped = _OwnerLinkError("the link dropped")
    token = model.begin_refresh()
    if when == "before_the_state_write":
        state["error"] = dropped
    else:
        original_replace = journal.replace_state_snapshot

        def drop_after_write(*args, **kwargs):
            result = original_replace(*args, **kwargs)
            state["error"] = dropped
            return result
        monkeypatch.setattr(journal, "replace_state_snapshot", drop_after_write)
    with pytest.raises(_OwnerLinkError) as caught:
        model.finish_refresh(token, observation)
    assert caught.value is dropped                              # the very error, not a renamed one
    assert model.read_status()["ready"] is False                # and nothing is offered as current
    # Once the owner's check passes again a new read makes the model ready.
    state["error"] = None
    if when == "after_the_state_write":
        monkeypatch.setattr(journal, "replace_state_snapshot", original_replace)
    model.finish_refresh(model.begin_refresh(), replace(observation, observation_id="obs-2"))
    assert model.read_status()["ready"] is True


def test_an_authority_callback_that_answers_instead_of_passing_is_refused(tmp_path):
    clocks = Clocks()
    journal = GatewayEventJournal(tmp_path / "readmodel.db", clock=clocks.utc)
    answers = [None]
    model = GatewayAccountReadModel(
        journal, account_key=_identity(), journal_account_scope="account:shared",
        state_scope="strategy:account-facts", required_coverage=(_resource(),),
        assert_current_generation=lambda _generation: answers[0], clock=clocks.utc, monotonic_clock=clocks.mono)
    model.start_generation("gen-1")
    token = model.begin_refresh()
    answers[0] = False                                           # anything but None is not a pass
    with pytest.raises(GatewayAccountSessionWorkerError, match="^SESSION_OWNERSHIP_UNAVAILABLE$"):
        model.finish_refresh(token, _observation(clocks, observation_id="obs-1"))
    assert model.read_status()["ready"] is False


def test_other_failures_of_a_refresh_keep_their_finite_codes(tmp_path, monkeypatch):
    model, journal, clocks, _, _ = _setup(tmp_path)
    observation = _observation(clocks, observation_id="obs-1")

    def broken_write(*_args, **_kwargs):
        raise _OwnerLinkError("not raised by the authority callback")
    monkeypatch.setattr(journal, "replace_state_snapshot", broken_write)
    with pytest.raises(GatewayAccountSessionWorkerError, match="^STATE_WRITE_FAILED$") as caught:
        model.finish_refresh(model.begin_refresh(), observation)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True
    monkeypatch.undo()

    def broken_validation(*_args, **_kwargs):
        raise _OwnerLinkError("not raised by the authority callback either")
    monkeypatch.setattr(model, "_validate_observation", broken_validation)
    with pytest.raises(GatewayAccountSessionWorkerError, match="^OBSERVATION_INVALID$"):
        model.finish_refresh(model.begin_refresh(), observation)


def test_fork_rejects_before_inherited_read_lock(tmp_path):
    model, _, _, _, _ = _setup(tmp_path)
    ready, release = threading.Event(), threading.Event()

    def hold():
        with model._view_lock:
            ready.set()
            release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert ready.wait(2)
    pid = os.fork()
    if pid == 0:
        signal.alarm(2)
        try:
            model.read_status()
        except GatewayAccountSessionWorkerError:
            os._exit(0)
        os._exit(1)
    _, status = os.waitpid(pid, 0)
    release.set()
    holder.join(timeout=2)
    assert os.waitstatus_to_exitcode(status) == 0


def test_read_service_accepts_only_six_operations_and_enforces_acl(tmp_path):
    model, journal, clocks, _, _ = _setup(tmp_path)
    model.finish_refresh(model.begin_refresh(), _observation(clocks, observation_id="obs-1"))
    account = GatewayServiceAccountScope(
        account_ref="account-a",
        execution_domain_ref="paper-a",
        journal_account_scope="account:shared",
        account_read_strategy_scope="strategy:account-facts",
    )
    principal = GatewayPrincipal(
        principal_id="principal-a",
        account_scopes=frozenset({"account:shared"}),
        strategy_scopes=frozenset({"strategy:account-facts"}),
        allowed_kinds=frozenset({GatewayCommandKind.READ}),
    )
    service = GatewayReadService(
        journal,
        accounts={"account-a": account},
        principals={"principal-a": principal},
        state_worker=model,
    )
    assert service.state_source is model
    assert service.accounts["account-a"] == account
    with pytest.raises(TypeError):
        service.accounts["other"] = account
    with pytest.raises(TypeError):
        service.accounts["account-a"].strategy_scope_map["other"] = "scope"
    assert service.supported_operations == frozenset(
        {
            "account.snapshot",
            "account.snapshot.typed",
            "account.head",
            "account.read_after",
            "account.ack",
            "account.progress",
        }
    )
    scope = WireScope("paper-a", account_ref="account-a")
    result = service.handle(
        "account.snapshot", principal_ref="principal-a", scope=scope, arguments={}
    )
    assert result["state_status"]["ready"] is True
    with pytest.raises(GatewayServiceError, match="UNSUPPORTED_OPERATION"):
        service.handle(
            "account.configuration", principal_ref="principal-a", scope=scope, arguments={}
        )
    with pytest.raises(GatewayServiceError, match="UNSUPPORTED_OPERATION"):
        service.handle(
            "account.head",
            principal_ref="principal-a",
            scope=scope,
            arguments={"stream": "execution"},
        )
    with pytest.raises(GatewayServiceError):
        service.handle("account.snapshot", principal_ref="unknown", scope=scope, arguments={})


def test_reopen_rejects_same_id_even_if_payload_is_identical(tmp_path):
    model, journal, clocks, authority, check = _setup(tmp_path)
    observation = _observation(clocks, observation_id="persisted-id")
    old = model.finish_refresh(model.begin_refresh(), observation)
    model.close()
    authority["generation"] = "gen-2"
    reopened = GatewayAccountReadModel(
        journal,
        account_key=_identity(),
        journal_account_scope="account:shared",
        state_scope="strategy:account-facts",
        required_coverage=(_resource(),),
        assert_current_generation=check,
        clock=clocks.utc,
        monotonic_clock=clocks.mono,
    )
    reopened.start_generation("gen-2")
    with pytest.raises(GatewayAccountSessionWorkerError, match="OBSERVATION_REPLAYED"):
        reopened.finish_refresh(reopened.begin_refresh(), observation)
    assert reopened.latest_snapshot == old and not reopened.ready
    changed = replace(observation, balances=(replace(observation.balances[0], total="101"),))
    with pytest.raises(GatewayAccountSessionWorkerError, match="OBSERVATION_ID_REUSED"):
        reopened.finish_refresh(reopened.begin_refresh(), changed)
    fresh = replace(observation, observation_id="new-id")
    new_snapshot = reopened.finish_refresh(reopened.begin_refresh(), fresh)
    assert new_snapshot != old and reopened.ready


def test_authority_callback_reentry_does_not_corrupt_new_generation(tmp_path):
    model, _, clocks, authority, original_check = _setup(tmp_path)
    observation = _observation(clocks, observation_id="obs-1")
    token = model.begin_refresh()
    invoked = []

    def switch(generation):
        if not invoked:
            invoked.append(True)
            authority["generation"] = "gen-2"
            model.start_generation("gen-2")
        else:
            original_check(generation)

    model._assert_generation = switch
    with pytest.raises(GatewayAccountSessionWorkerError, match="PROVIDER_RESULT_GENERATION_STALE"):
        model.finish_refresh(token, observation)
    assert model.session_generation == "gen-2" and not model.ready
    model.finish_refresh(model.begin_refresh(), replace(observation, observation_id="obs-2"))
    assert model.ready and model.session_generation == "gen-2"


def test_commit_then_lost_reply_does_not_reauthorize_old_baseline(tmp_path, monkeypatch):
    model, journal, clocks, authority, _ = _setup(tmp_path)
    first = _observation(clocks, observation_id="obs-old")
    original_snapshot = model.finish_refresh(model.begin_refresh(), first)
    second = _observation(clocks, observation_id="obs-new")
    original_replace = journal.replace_state_snapshot

    def committed_then_lost(*args, **kwargs):
        original_replace(*args, **kwargs)
        raise RuntimeError("synthetic lost post-commit response")

    monkeypatch.setattr(journal, "replace_state_snapshot", committed_then_lost)
    with pytest.raises(GatewayAccountSessionWorkerError, match="STATE_WRITE_FAILED"):
        model.finish_refresh(model.begin_refresh(), second)
    assert model.latest_snapshot == original_snapshot and not model.ready
    monkeypatch.setattr(journal, "replace_state_snapshot", original_replace)
    with pytest.raises(GatewayAccountSessionWorkerError, match="OBSERVATION_REPLAYED"):
        model.finish_refresh(model.begin_refresh(), first)
    assert not model.ready
    authority["generation"] = "gen-2"
    model.start_generation("gen-2")
    assert model.latest_snapshot.cursor == original_snapshot.cursor + 1
    fresh = _observation(clocks, observation_id="obs-after-recovery")
    model.finish_refresh(model.begin_refresh(), fresh)
    assert model.ready
