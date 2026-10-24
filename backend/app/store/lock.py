from __future__ import annotations

import fcntl
import os
import threading
from collections.abc import Callable
from pathlib import Path


class StoreLock:
    """Thread lock plus an exclusive lock file.

    The outermost acquisition reloads from disk so several processes share one
    store. Nested acquisitions on the same thread keep the in-memory copy.
    """

    def __init__(self, path: Path, reload: Callable[[], None]):
        self.path = path
        self._reload = reload
        self._thread = threading.RLock()
        self._depth = 0
        self._fd: int | None = None

    def __enter__(self) -> StoreLock:
        self._thread.acquire()
        entered = False
        try:
            if self._depth == 0:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            self._depth += 1
            entered = True
            if self._depth == 1:
                self._reload()
            return self
        except BaseException:
            if entered:
                self._depth -= 1
            if self._depth == 0 and self._fd is not None:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(self._fd)
                self._fd = None
            self._thread.release()
            raise

    def __exit__(self, *args: object) -> None:
        try:
            self._depth -= 1
            if self._depth == 0 and self._fd is not None:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(self._fd)
                self._fd = None
        finally:
            self._thread.release()
