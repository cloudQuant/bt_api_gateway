"""Local OS-backed ownership for one provider account session.

This guard excludes competing processes on one host when they share the same
trusted ownership directory. It is not a distributed lock and does not fence
provider connections that ignore it. An active record left after a crash needs
explicit reconciliation; elapsed time never grants another owner a takeover.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import stat
import threading
from pathlib import Path
from typing import Any, Optional

if os.name == "nt":
    import msvcrt
else:
    import fcntl


_MAX_RECORD_BYTES = 4096
_UNBOUND_CONSUMER = object()


class LocalAccountSessionGuardError(RuntimeError):
    """A local account-session ownership operation failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class LocalAccountSessionGuard:
    """Hold a nonblocking local lock while one provider session is open.

    ``account_key`` must be the stable canonical account identity chosen by
    the caller, not a product label or API-key value. Its value is hashed for
    the filename and record; the raw key is never written. Every process using
    one account must use the same directory. The directory itself must be
    trusted and shared by those local processes.

    Bind one guard instance to its local worker with :meth:`bind_consumer`;
    create a separate guard instance for each worker. This is a trusted local
    composition invariant, not cross-host coordination or distributed fencing.

    The guard does not connect to or close a provider session. The caller must
    confirm provider close before calling :meth:`release`.
    """

    def __init__(self, directory: Path, account_key: str, owner_ref: str) -> None:
        self._owner_thread_id = threading.get_ident()
        self._owner_process_id = os.getpid()
        self._directory = _trusted_directory(directory)
        self._directory_identity = _identity(os.stat(self._directory))
        account_bytes = _bounded_text(account_key, "account_key", 4096)
        self._account_digest = hashlib.sha256(account_bytes).hexdigest()
        self._owner_ref = _bounded_text(owner_ref, "owner_ref", 512).decode("utf-8")
        self._lock_path = self._directory / f"account-{self._account_digest}.session-lock"
        self._fd: Optional[int] = None  # noqa: UP045 -- Python 3.9 support.
        self._file_identity: Optional[tuple[int, int]] = None  # noqa: UP045
        self._generation: Optional[str] = None  # noqa: UP045
        self._phase = "idle"
        self._os_locked = False
        self._closed_record_durable = False
        self._consumer: object = _UNBOUND_CONSUMER

    @property
    def lock_path(self) -> Path:
        """Return the deterministic local lock path for diagnostics."""
        return self._lock_path

    @property
    def account_key_digest(self) -> str:
        """Return the stable account-key digest without exposing the raw key."""
        return self._account_digest

    def acquire(self) -> str:
        """Acquire local ownership and return its fresh opaque generation.

        Repeated calls on the owning object return its current generation. A
        persisted ``active`` record from an owner that is no longer holding the
        OS lock blocks acquisition for reconciliation; this API has no reset or
        stale-session takeover operation.
        """
        self._check_owner()
        if self._phase == "active":
            assert self._generation is not None
            self._verify_owned_record(active_only=True)
            return self._generation
        if self._phase != "idle":
            raise LocalAccountSessionGuardError(
                "SESSION_CLEANUP_REQUIRED",
                "retry release to finish cleaning up this guard before acquiring",
            )

        try:
            self._verify_directory()
            self._open_lock_file()
            self._verify_file_identity()
            self._lock_file()
            self._os_locked = True
            self._phase = "acquire_cleanup"
            self._verify_file_identity()
            prior = self._read_record()
            if prior is not None and prior["status"] == "active":
                raise LocalAccountSessionGuardError(
                    "SESSION_RECONCILIATION_REQUIRED",
                    "a prior account session is still recorded active and needs reconciliation",
                )
            generation = secrets.token_hex(16)
            record = self._record("active", generation)
            self._write_record(record)
            self._generation = generation
            self._closed_record_durable = False
            self._phase = "active"
            return generation
        except BaseException as exc:
            cleanup_error = self._cleanup_failed_acquire()
            if cleanup_error is not None:
                raise LocalAccountSessionGuardError(
                    "SESSION_CLEANUP_REQUIRED",
                    "acquisition failed and owned file resources need release retry",
                ) from cleanup_error
            if isinstance(exc, LocalAccountSessionGuardError):
                raise
            if isinstance(exc, OSError):
                raise LocalAccountSessionGuardError(
                    "SESSION_IO_ERROR", "account session ownership storage failed"
                ) from exc
            raise

    def bind_consumer(self, consumer: object) -> None:
        """Permanently bind this local guard to one in-process consumer object.

        This prevents trusted local composition from sharing one guard object
        between distinct account-session workers. It does not coordinate
        consumers on another host or provide distributed fencing.
        """
        self._check_owner()
        if self._consumer is _UNBOUND_CONSUMER:
            self._consumer = consumer
            return
        if self._consumer is consumer:
            return
        raise LocalAccountSessionGuardError(
            "SESSION_CONSUMER_CONFLICT",
            "this guard is already bound to a different local consumer",
        )

    def assert_owned(self) -> None:
        """Verify this owner thread still holds the matching active record."""
        self._check_owner()
        if self._phase != "active" or self._fd is None or not self._os_locked:
            raise LocalAccountSessionGuardError(
                "SESSION_NOT_OWNED", "this guard does not hold active account-session ownership"
            )
        self._verify_owned_record(active_only=True)

    def release(self) -> None:
        """Close a confirmed provider session and durably release local ownership.

        A caller must first establish that the provider session has closed.
        Failures leave the descriptor and state available for an owner-thread
        retry; this method never turns an uncertain close into success.
        """
        self._check_owner()
        if self._phase == "idle":
            return
        if self._phase == "pending_close":
            self._close_descriptor()
            return
        if self._phase == "unlocked_pending_close":
            self._close_descriptor()
            return
        if self._phase == "acquire_cleanup":
            self._cleanup_unpublished_or_raise()
            return
        if self._phase not in {"active", "releasing"}:
            raise LocalAccountSessionGuardError(
                "SESSION_CLEANUP_REQUIRED", "guard cleanup state is not recognized"
            )

        try:
            self._verify_file_identity()
            record = self._read_record()
            if record is None or not _record_matches_owner(
                record, self._account_digest, self._generation, self._owner_ref
            ):
                raise LocalAccountSessionGuardError(
                    "SESSION_STATE_CHANGED", "account session record no longer matches this owner"
                )
            if record["status"] == "active" or not self._closed_record_durable:
                self._write_record(self._record("closed", self._generation))
                self._closed_record_durable = True
            self._phase = "releasing"
            self._unlock_file()
            self._os_locked = False
            self._phase = "unlocked_pending_close"
            self._close_descriptor()
        except LocalAccountSessionGuardError:
            raise
        except OSError as exc:
            raise LocalAccountSessionGuardError(
                "SESSION_RELEASE_FAILED", "account session release needs an owner-thread retry"
            ) from exc

    def _check_owner(self) -> None:
        if os.getpid() != self._owner_process_id or threading.get_ident() != self._owner_thread_id:
            raise LocalAccountSessionGuardError(
                "SESSION_WRONG_OWNER",
                "guard operations are restricted to the creating process and thread",
            )

    def _verify_directory(self) -> None:
        try:
            info = self._directory.lstat()
            _reject_reparse_point(info, "session directory")
            if not stat.S_ISDIR(info.st_mode) or _identity(info) != self._directory_identity:
                raise LocalAccountSessionGuardError(
                    "SESSION_PATH_CHANGED", "session ownership directory identity changed"
                )
            if self._directory.resolve(strict=True) != self._directory:
                raise LocalAccountSessionGuardError(
                    "SESSION_PATH_CHANGED", "session ownership directory was redirected"
                )
        except LocalAccountSessionGuardError:
            raise
        except (OSError, RuntimeError) as exc:
            raise LocalAccountSessionGuardError(
                "SESSION_PATH_CHANGED", "session ownership directory cannot be verified"
            ) from exc

    def _verify_file_identity(self) -> None:
        if self._fd is None or self._file_identity is None:
            raise LocalAccountSessionGuardError(
                "SESSION_NOT_OWNED", "session lock file descriptor is unavailable"
            )
        self._verify_directory()
        try:
            path_info = self._lock_path.lstat()
            _reject_reparse_point(path_info, "session lock file")
            descriptor_info = os.fstat(self._fd)
            if not stat.S_ISREG(path_info.st_mode) or not stat.S_ISREG(descriptor_info.st_mode):
                raise LocalAccountSessionGuardError(
                    "SESSION_PATH_CHANGED", "session lock path no longer names a regular file"
                )
            if (
                _identity(path_info) != self._file_identity
                or _identity(descriptor_info) != self._file_identity
            ):
                raise LocalAccountSessionGuardError(
                    "SESSION_PATH_CHANGED", "session lock path no longer names the held file"
                )
        except LocalAccountSessionGuardError:
            raise
        except OSError as exc:
            raise LocalAccountSessionGuardError(
                "SESSION_PATH_CHANGED", "session lock path cannot be verified"
            ) from exc

    def _open_lock_file(self) -> None:
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            existing = self._lock_path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise LocalAccountSessionGuardError(
                "SESSION_PATH_CHANGED", "session lock path cannot be inspected"
            ) from exc
        if existing is not None:
            _reject_reparse_point(existing, "session lock file")
            if not stat.S_ISREG(existing.st_mode):
                raise LocalAccountSessionGuardError(
                    "SESSION_PATH_CHANGED", "session lock path is not a regular file"
                )
        try:
            self._fd = os.open(self._lock_path, flags, 0o600)
            descriptor_info = os.fstat(self._fd)
            self._file_identity = _identity(descriptor_info)
            if not stat.S_ISREG(descriptor_info.st_mode) or self._file_identity[1] == 0:
                raise LocalAccountSessionGuardError(
                    "SESSION_PATH_CHANGED", "session lock descriptor has no stable file identity"
                )
            self._phase = "pending_close"
            self._verify_file_identity()
        except BaseException:
            if self._fd is not None:
                self._phase = "pending_close"
            raise

    def _lock_file(self) -> None:
        assert self._fd is not None
        os.lseek(self._fd, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if _is_lock_busy(exc):
                raise LocalAccountSessionGuardError(
                    "SESSION_ALREADY_OWNED", "another local process owns this account session"
                ) from exc
            raise

    def _unlock_file(self) -> None:
        assert self._fd is not None
        os.lseek(self._fd, 0, os.SEEK_SET)
        if os.name == "nt":
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _read_record(self) -> Optional[dict[str, Any]]:  # noqa: UP045 -- Python 3.9 support.
        assert self._fd is not None
        size = os.fstat(self._fd).st_size
        if size == 0:
            return None
        if size < 0 or size > _MAX_RECORD_BYTES:
            raise LocalAccountSessionGuardError(
                "SESSION_STATE_INVALID", "session ownership record exceeds its size limit"
            )
        os.lseek(self._fd, 0, os.SEEK_SET)
        raw = os.read(self._fd, _MAX_RECORD_BYTES + 1)
        if len(raw) != size or len(raw) > _MAX_RECORD_BYTES:
            raise LocalAccountSessionGuardError(
                "SESSION_STATE_INVALID", "session ownership record could not be read completely"
            )
        try:
            record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise LocalAccountSessionGuardError(
                "SESSION_STATE_INVALID", "session ownership record is not valid JSON"
            ) from exc
        if not _valid_record(record, self._account_digest):
            raise LocalAccountSessionGuardError(
                "SESSION_STATE_INVALID", "session ownership record has an invalid shape"
            )
        return record

    def _record(
        self,
        status: str,
        generation: Optional[str],  # noqa: UP045 -- Python 3.9 support.
    ) -> dict[str, Any]:
        assert generation is not None
        return {
            "account_digest": self._account_digest,
            "generation": generation,
            "owner_ref": self._owner_ref,
            "status": status,
            "version": 1,
        }

    def _write_record(self, record: dict[str, Any]) -> None:
        assert self._fd is not None
        payload = json.dumps(
            record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        if len(payload) > _MAX_RECORD_BYTES:
            raise LocalAccountSessionGuardError(
                "SESSION_STATE_INVALID", "session ownership record exceeds its size limit"
            )
        os.lseek(self._fd, 0, os.SEEK_SET)
        os.ftruncate(self._fd, 0)
        written = 0
        while written < len(payload):
            count = os.write(self._fd, payload[written:])
            if count <= 0:
                raise OSError("session ownership record write made no progress")
            written += count
        os.fsync(self._fd)

    def _verify_owned_record(self, active_only: bool) -> None:
        self._verify_file_identity()
        try:
            record = self._read_record()
        except LocalAccountSessionGuardError:
            raise
        except OSError as exc:
            raise LocalAccountSessionGuardError(
                "SESSION_IO_ERROR", "session ownership record cannot be read"
            ) from exc
        if record is None or not _record_matches_owner(
            record, self._account_digest, self._generation, self._owner_ref
        ):
            raise LocalAccountSessionGuardError(
                "SESSION_STATE_CHANGED", "session ownership record no longer matches this owner"
            )
        if active_only and record["status"] != "active":
            raise LocalAccountSessionGuardError(
                "SESSION_NOT_OWNED", "session ownership record is no longer active"
            )

    def _cleanup_failed_acquire(self) -> Optional[BaseException]:  # noqa: UP045 -- Python 3.9 support.
        if self._fd is None:
            self._phase = "idle"
            self._generation = None
            return None
        if self._os_locked:
            try:
                self._unlock_file()
                self._os_locked = False
            except BaseException as exc:
                self._phase = "acquire_cleanup"
                return exc
        try:
            self._close_descriptor()
        except BaseException as exc:
            return exc
        self._generation = None
        self._phase = "idle"
        return None

    def _cleanup_unpublished_or_raise(self) -> None:
        cleanup_error = self._cleanup_failed_acquire()
        if cleanup_error is not None:
            raise LocalAccountSessionGuardError(
                "SESSION_CLEANUP_REQUIRED", "acquisition cleanup still needs an owner-thread retry"
            ) from cleanup_error

    def _close_descriptor(self) -> None:
        if self._fd is None:
            self._phase = "idle"
            return
        fd = self._fd
        try:
            os.close(fd)
        except OSError as exc:
            if self._os_locked:
                self._phase = "acquire_cleanup"
            elif self._phase == "unlocked_pending_close":
                self._phase = "unlocked_pending_close"
            else:
                self._phase = "pending_close"
            raise LocalAccountSessionGuardError(
                "SESSION_CLEANUP_REQUIRED", "session lock descriptor remains open for retry"
            ) from exc
        self._fd = None
        self._file_identity = None
        self._generation = None
        self._closed_record_durable = False
        self._os_locked = False
        self._phase = "idle"


def _trusted_directory(directory: Path) -> Path:
    try:
        requested = Path(directory).absolute()
        info = requested.lstat()
        _reject_reparse_point(info, "session directory")
        if not stat.S_ISDIR(info.st_mode):
            raise LocalAccountSessionGuardError(
                "SESSION_DIRECTORY_INVALID", "session ownership directory must already exist"
            )
        resolved = requested.resolve(strict=True)
        resolved_info = resolved.lstat()
        _reject_reparse_point(resolved_info, "session directory")
        if not stat.S_ISDIR(resolved_info.st_mode):
            raise LocalAccountSessionGuardError(
                "SESSION_DIRECTORY_INVALID", "session ownership path is not a directory"
            )
        _identity(resolved_info)
        return resolved
    except LocalAccountSessionGuardError:
        raise
    except (OSError, RuntimeError) as exc:
        raise LocalAccountSessionGuardError(
            "SESSION_DIRECTORY_INVALID", "session ownership directory cannot be verified"
        ) from exc


def _bounded_text(value: str, name: str, max_bytes: int) -> bytes:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text without NUL")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8 text") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{name} exceeds its size limit")
    return encoded


def _identity(info: os.stat_result) -> tuple[int, int]:
    device, inode = int(info.st_dev), int(info.st_ino)
    if inode == 0:
        raise LocalAccountSessionGuardError(
            "SESSION_PATH_CHANGED", "filesystem does not expose a stable file identity"
        )
    return device, inode


def _reject_reparse_point(info: os.stat_result, label: str) -> None:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag:
        raise LocalAccountSessionGuardError(
            "SESSION_PATH_CHANGED", f"{label} cannot be a symbolic link or reparse point"
        )


def _is_lock_busy(exc: OSError) -> bool:
    if os.name == "nt":
        return getattr(exc, "winerror", None) == 33 or exc.errno == errno.EACCES
    busy_codes = {errno.EACCES, errno.EAGAIN}
    if hasattr(errno, "EWOULDBLOCK"):
        busy_codes.add(errno.EWOULDBLOCK)
    return exc.errno in busy_codes


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _valid_record(value: Any, account_digest: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "account_digest",
        "generation",
        "owner_ref",
        "status",
        "version",
    }:
        return False
    if (
        type(value["version"]) is not int
        or value["version"] != 1
        or type(value["account_digest"]) is not str
        or value["account_digest"] != account_digest
        or type(value["status"]) is not str
        or value["status"] not in {"active", "closed"}
        or not _is_generation(value["generation"])
    ):
        return False
    try:
        _bounded_text(value["owner_ref"], "owner_ref", 512)
    except (TypeError, ValueError):
        return False
    return True


def _is_generation(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 32
        and all(character in "0123456789abcdef" for character in value)
    )


def _record_matches_owner(
    record: dict[str, Any],
    account_digest: str,
    generation: Optional[str],  # noqa: UP045 -- Python 3.9 support.
    owner_ref: str,
) -> bool:
    return (
        record["account_digest"] == account_digest
        and record["generation"] == generation
        and record["owner_ref"] == owner_ref
    )
