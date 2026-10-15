"""Private, non-overwriting atomic publication; no interpretation of payloads."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import uuid


class SafetyError(RuntimeError):
    pass


def sha(value: str | bytes) -> str:
    return hashlib.sha256(value.encode('utf-8') if isinstance(value, str) else value).hexdigest()


def strict_json(text: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SafetyError('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def invalid_constant(_):
        raise SafetyError('NONFINITE_JSON_NUMBER')
    value = json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise SafetyError('JSON_ROOT_NOT_OBJECT')
    return value


def safe_path(root: Path, relative: str) -> Path:
    root = Path(root).absolute()
    rel = Path(relative)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise SafetyError('PATH_OUTSIDE_ROOT')
    result = root / rel
    for p in [result, *result.parents]:
        if p.is_symlink():
            raise SafetyError('SYMLINK_REJECTED')
    return result


def private_dir(root: Path, relative: str) -> Path:
    p = safe_path(root, relative)
    p.mkdir(mode=0o700, parents=True, exist_ok=False)
    return p


def atomic_create(root: Path, relative: str, value: object) -> Path:
    p = safe_path(root, relative)
    data = value if isinstance(value, bytes) else value.encode('utf-8') if isinstance(value, str) else (
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(relative).parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        temporary = '.pending-' + uuid.uuid4().hex
        output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(output, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.link(temporary, p.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.fsync(fd)
        finally:
            os.unlink(temporary, dir_fd=fd)  # Only the unique temporary file created above.
    finally:
        os.close(fd)
    return p


class ExclusiveLease:
    """No stale-lock guessing; an interrupted lease requires explicit reconciliation."""
    def __init__(self, root: Path, name: str = 'ACTIVE_RUNNER_LOCK.json') -> None:
        self.root, self.name, self.token = root, name, uuid.uuid4().hex

    def __enter__(self):
        atomic_create(self.root, self.name, {'pid': os.getpid(), 'token': self.token})
        return self

    def __exit__(self, typ, value, traceback):
        # An abnormal exit keeps the lock and prevents an automatic duplicate run.
        if typ is None:
            p = safe_path(self.root, self.name)
            if strict_json(p.read_text())['token'] != self.token:
                raise SafetyError('LEASE_OWNERSHIP_CHANGED')
            p.unlink()

