"""Local process/thread ownership tests for provider account sessions."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from bt_api_gateway import session_guard as session_guard_module
from bt_api_gateway.session_guard import (
    LocalAccountSessionGuard,
    LocalAccountSessionGuardError,
)


def _child_env() -> dict[str, str]:
    environment = os.environ.copy()
    source_root = str(Path(__file__).resolve().parents[1] / "src")
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root if not existing else os.pathsep.join((source_root, existing))
    )
    return environment


def _run_child(tmp_path: Path, program: str, account_key: str = "canonical-account:one"):
    return subprocess.run(  # noqa: S603 -- fixed local guard fixture; no shell or provider code.
        [sys.executable, "-c", program, str(tmp_path), account_key],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        env=_child_env(),
    )


def test_guard_excludes_duplicate_local_owner_and_allows_clean_handoff(tmp_path: Path) -> None:
    first = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    generation = first.acquire()
    assert first.acquire() == generation
    first.assert_owned()

    duplicate = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:second")
    with pytest.raises(LocalAccountSessionGuardError) as blocked:
        duplicate.acquire()
    assert blocked.value.code == "SESSION_ALREADY_OWNED"

    metadata = first._read_record()
    assert metadata is not None
    assert metadata["status"] == "active"
    assert metadata["generation"] == generation
    assert metadata["owner_ref"] == "owner:first"
    assert "pid" not in metadata
    assert "canonical-account:one" not in first.lock_path.name
    assert set(metadata) == {
        "account_digest",
        "generation",
        "owner_ref",
        "status",
        "version",
    }
    assert metadata["account_digest"] != "canonical-account:one"
    os.lseek(first._fd, 0, os.SEEK_SET)
    assert b"canonical-account:one" not in os.read(first._fd, 4096)

    first.release()
    first.release()
    with pytest.raises(LocalAccountSessionGuardError) as no_longer_owned:
        first.assert_owned()
    assert no_longer_owned.value.code == "SESSION_NOT_OWNED"

    second = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:second")
    next_generation = second.acquire()
    assert next_generation != generation
    second.assert_owned()
    second.release()


def test_guard_claims_one_consumer_identity_before_io_and_after_release(tmp_path: Path) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    first_consumer = object()
    second_consumer = object()

    guard.bind_consumer(first_consumer)
    guard.bind_consumer(first_consumer)
    assert not guard.lock_path.exists()

    with pytest.raises(LocalAccountSessionGuardError) as conflict:
        guard.bind_consumer(second_consumer)
    assert conflict.value.code == "SESSION_CONSUMER_CONFLICT"
    assert not guard.lock_path.exists()
    assert guard._phase == "idle"
    assert guard._fd is None
    assert guard._generation is None

    wrong_owner_codes: list[str] = []

    def bind_from_another_thread() -> None:
        try:
            guard.bind_consumer(second_consumer)
        except LocalAccountSessionGuardError as exc:
            wrong_owner_codes.append(exc.code)

    worker = threading.Thread(target=bind_from_another_thread)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert wrong_owner_codes == ["SESSION_WRONG_OWNER"]

    guard.acquire()
    guard.release()
    closed_record = guard.lock_path.read_bytes()
    guard.bind_consumer(first_consumer)
    assert guard.lock_path.read_bytes() == closed_record
    with pytest.raises(LocalAccountSessionGuardError) as retained_conflict:
        guard.bind_consumer(second_consumer)
    assert retained_conflict.value.code == "SESSION_CONSUMER_CONFLICT"
    assert guard.lock_path.read_bytes() == closed_record


def test_account_key_digest_is_stable_read_only_and_requires_no_lock_file_io(
    tmp_path: Path,
) -> None:
    account_key = "canonical-account:one"
    guard = LocalAccountSessionGuard(tmp_path, account_key, "owner:first")

    expected = hashlib.sha256(account_key.encode("utf-8")).hexdigest()
    assert guard.account_key_digest == expected
    assert account_key not in guard.account_key_digest
    with pytest.raises(AttributeError):
        guard.account_key_digest = "different-account"
    assert guard.account_key_digest == expected
    assert not guard.lock_path.exists()
    assert guard._fd is None
    assert guard._phase == "idle"


def test_independent_process_cannot_acquire_active_session(tmp_path: Path) -> None:
    owner = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:parent")
    owner.acquire()
    result = _run_child(
        tmp_path,
        """
from pathlib import Path
import sys
from bt_api_gateway.session_guard import LocalAccountSessionGuard, LocalAccountSessionGuardError
guard = LocalAccountSessionGuard(Path(sys.argv[1]), sys.argv[2], 'owner:child')
try:
    guard.acquire()
except LocalAccountSessionGuardError as exc:
    print(exc.code)
else:
    guard.release()
    raise SystemExit('second process acquired an active session')
""",
    )
    try:
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "SESSION_ALREADY_OWNED"
    finally:
        owner.release()


def test_crashed_owner_leaves_active_record_for_reconciliation(tmp_path: Path) -> None:
    result = _run_child(
        tmp_path,
        """
import os
from pathlib import Path
import sys
from bt_api_gateway.session_guard import LocalAccountSessionGuard
guard = LocalAccountSessionGuard(Path(sys.argv[1]), sys.argv[2], 'owner:crashed')
guard.acquire()
os._exit(0)
""",
    )
    assert result.returncode == 0, result.stderr

    next_owner = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:next")
    with pytest.raises(LocalAccountSessionGuardError) as blocked:
        next_owner.acquire()
    assert blocked.value.code == "SESSION_RECONCILIATION_REQUIRED"
    assert next_owner._fd is None


def test_failed_release_keeps_lock_for_owner_thread_retry(tmp_path: Path, monkeypatch) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    generation = guard.acquire()
    original_unlock = LocalAccountSessionGuard._unlock_file
    attempts = 0

    def fail_once(current: LocalAccountSessionGuard) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("synthetic unlock failure")
        original_unlock(current)

    monkeypatch.setattr(LocalAccountSessionGuard, "_unlock_file", fail_once)
    with pytest.raises(LocalAccountSessionGuardError) as failed:
        guard.release()
    assert failed.value.code == "SESSION_RELEASE_FAILED"
    assert guard._fd is not None
    assert guard._os_locked is True
    metadata = guard._read_record()
    assert metadata is not None
    assert metadata["status"] == "closed"

    competitor = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:second")
    with pytest.raises(LocalAccountSessionGuardError) as blocked:
        competitor.acquire()
    assert blocked.value.code == "SESSION_ALREADY_OWNED"

    guard.release()
    assert guard._fd is None
    assert guard._generation is None
    handoff = competitor.acquire()
    assert handoff != generation
    competitor.release()


def test_failed_descriptor_close_remains_retryable_after_unlock(
    tmp_path: Path, monkeypatch
) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    guard.acquire()
    original_close = os.close
    held_fd = guard._fd
    attempts = 0

    def fail_once(fd: int) -> None:
        nonlocal attempts
        if fd == held_fd and attempts == 0:
            attempts += 1
            raise OSError("synthetic descriptor close failure")
        original_close(fd)

    monkeypatch.setattr(session_guard_module.os, "close", fail_once)
    with pytest.raises(LocalAccountSessionGuardError) as failed:
        guard.release()
    assert failed.value.code == "SESSION_CLEANUP_REQUIRED"
    assert guard._fd == held_fd
    assert guard._os_locked is False
    os.fstat(held_fd)

    competitor = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:second")
    competitor_generation = competitor.acquire()
    assert competitor_generation
    guard.release()
    assert guard._fd is None
    competitor.assert_owned()
    competitor.release()


def test_acquire_cleanup_failure_retains_descriptor_for_release_retry(
    tmp_path: Path, monkeypatch
) -> None:
    owner = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    owner.acquire()
    duplicate = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:second")
    original_close = os.close
    duplicate_fd = -1
    failed = False

    def fail_duplicate_close(fd: int) -> None:
        nonlocal failed
        if fd == duplicate_fd and not failed:
            failed = True
            raise KeyboardInterrupt
        original_close(fd)

    monkeypatch.setattr(session_guard_module.os, "close", fail_duplicate_close)
    # Remember the descriptor immediately before the OS lock fails.
    original_lock = LocalAccountSessionGuard._lock_file

    def remember_fd(current: LocalAccountSessionGuard) -> None:
        nonlocal duplicate_fd
        if current is duplicate:
            duplicate_fd = current._fd
        original_lock(current)

    monkeypatch.setattr(LocalAccountSessionGuard, "_lock_file", remember_fd)
    with pytest.raises(LocalAccountSessionGuardError) as cleanup_required:
        duplicate.acquire()
    assert cleanup_required.value.code == "SESSION_CLEANUP_REQUIRED"
    assert duplicate._fd == duplicate_fd
    assert duplicate._phase == "pending_close"

    duplicate.release()
    assert duplicate._fd is None
    owner.assert_owned()
    owner.release()


def test_guard_methods_are_restricted_to_creating_thread(tmp_path: Path) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    guard.acquire()
    observed: list[str] = []

    def wrong_thread() -> None:
        for operation in (guard.assert_owned, guard.release):
            try:
                operation()
            except LocalAccountSessionGuardError as exc:
                observed.append(exc.code)

    worker = threading.Thread(target=wrong_thread)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert observed == ["SESSION_WRONG_OWNER", "SESSION_WRONG_OWNER"]
    guard.assert_owned()
    guard.release()


def test_lock_path_redirect_fails_identity_check_and_can_be_restored(tmp_path: Path) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    guard.acquire()
    original_path = guard.lock_path
    replacement_path = tmp_path / "replacement.lock"
    replacement_path.write_text("replacement", encoding="utf-8")
    try:
        # Windows byte-range locking prevents renaming the held file. Redirect
        # the path reference to a different regular file to exercise the same
        # identity check on every supported platform.
        guard._lock_path = replacement_path
        with pytest.raises(LocalAccountSessionGuardError) as changed:
            guard.assert_owned()
        assert changed.value.code == "SESSION_PATH_CHANGED"
    finally:
        guard._lock_path = original_path
        guard.release()


def test_invalid_persisted_metadata_blocks_acquisition(tmp_path: Path) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    guard.lock_path.write_bytes(b'{"status":"active"')

    with pytest.raises(LocalAccountSessionGuardError) as invalid:
        guard.acquire()
    assert invalid.value.code == "SESSION_STATE_INVALID"
    assert guard._fd is None


def test_symbolic_link_lock_path_is_rejected_before_open(tmp_path: Path) -> None:
    guard = LocalAccountSessionGuard(tmp_path, "canonical-account:one", "owner:first")
    target = tmp_path / "target"
    target.write_text("", encoding="utf-8")
    try:
        guard.lock_path.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"filesystem cannot create a symlink in this test environment: {exc}")

    with pytest.raises(LocalAccountSessionGuardError) as changed:
        guard.acquire()
    assert changed.value.code == "SESSION_PATH_CHANGED"
