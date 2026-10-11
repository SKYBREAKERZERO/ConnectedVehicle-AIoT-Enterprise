from __future__ import annotations

import errno
import math
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


class RuntimeAlreadyRunningError(RuntimeError):
    """The ledger already has an active runtime or maintenance owner."""


@contextmanager
def runtime_lock(database: Path, *, wait_seconds: float = 0) -> Iterator[None]:
    """Local-filesystem OS lock; process exit releases it, including abrupt crashes.

    Keep the sidecar file: unlinking it could split contenders across two inodes.
    All runtimes and replay maintenance must use this guard before opening SQLite.
    """
    if not math.isfinite(wait_seconds) or wait_seconds < 0:
        raise ValueError("invalid_ownership_wait")
    path = database.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with Path(str(path) + ".runtime.lock").open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                if sys.platform == "win32":
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeAlreadyRunningError("device_ledger_already_owned") from exc
                time.sleep(min(0.05, remaining))
        try:
            yield
        finally:
            stream.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
