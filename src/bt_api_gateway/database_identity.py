"""Fail-closed identity checks for local SQLite file paths."""

from __future__ import annotations

import os
from pathlib import Path
from threading import RLock
from typing import Optional


class GatewayDatabaseIdentityError(RuntimeError):
    """The resolved SQLite path no longer names the file opened at startup."""

    code = "WRITER_DATABASE_IDENTITY_CHANGED"


class SQLiteFileIdentity:
    """Pin a local database's resolved path and filesystem device/inode pair.

    This detects ordinary replacement of the database file or one of its path
    ancestors between connections. It is not an OS file-handle lock and does
    not fence writers that bypass this path or run on another host.
    """

    def __init__(self, path: Path) -> None:
        self._requested_path = Path(path).absolute()
        self._path = self._requested_path.resolve()
        self._identity: Optional[tuple[int, int]] = None  # noqa: UP045 -- Python 3.9 support.
        self._lock = RLock()

    @property
    def path(self) -> Path:
        return self._path

    def verify(self) -> None:
        """Capture the initial file identity or reject any later path change."""
        with self._lock:
            try:
                resolved = self._requested_path.resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                raise GatewayDatabaseIdentityError(
                    "SQLite database path cannot be resolved"
                ) from exc
            if resolved != self._path:
                raise GatewayDatabaseIdentityError(
                    "SQLite database path now resolves to a different target"
                )
            try:
                metadata = os.stat(self._path, follow_symlinks=True)
            except FileNotFoundError as exc:
                if self._identity is None:
                    # SQLite may create a new database on the first connection.
                    return
                raise GatewayDatabaseIdentityError(
                    "SQLite database file disappeared after identity was pinned"
                ) from exc
            except OSError as exc:
                raise GatewayDatabaseIdentityError(
                    "SQLite database file identity cannot be verified"
                ) from exc

            current = (int(metadata.st_dev), int(metadata.st_ino))
            if current[1] == 0:
                raise GatewayDatabaseIdentityError(
                    "filesystem does not expose a stable SQLite file identity"
                )
            if self._identity is None:
                self._identity = current
            elif current != self._identity:
                raise GatewayDatabaseIdentityError(
                    "SQLite database file identity changed after startup"
                )
