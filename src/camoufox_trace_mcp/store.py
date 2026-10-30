"""Read-only trace access beneath an explicit, trusted directory."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .reader import read_stream


class TraceStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("trace root must be a directory")
        if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("MCP file access requires POSIX directory-fd and O_NOFOLLOW support")

    def read(self, name: str, *, allow_legacy: bool = False):
        path = Path(name)
        if not name or path.is_absolute() or ".." in path.parts or path.suffix not in ('.jsonl', '.log'):
            raise ValueError("trace must be a relative .jsonl or .log path beneath the configured root")
        parts = path.parts
        descriptors = []
        try:
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(directory)
            for component in parts[:-1]:
                directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                descriptors.append(directory)
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
            descriptors.append(descriptor)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("trace must be a regular file")
            with os.fdopen(descriptor, "rb") as stream:
                descriptors.pop()
                return read_stream(stream, allow_legacy=allow_legacy, raw_name=name)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def list(self, *, offset: int = 0, limit: int = 50) -> dict:
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("offset must be nonnegative and limit must be between 1 and 1000")
        entries = []
        scanned = 0
        capped = False
        for directory, subdirectories, files in os.walk(self.root, followlinks=False):
            scanned += 1
            if scanned > 10_000:
                capped = True
                break
            subdirectories[:] = sorted(name for name in subdirectories
                                       if not (Path(directory) / name).is_symlink())
            for name in sorted(files):
                scanned += 1
                if scanned > 10_000:
                    capped = True
                    break
                path = Path(directory) / name
                if path.suffix in ('.jsonl', '.log') and not path.is_symlink() and path.is_file():
                    entries.append(path.relative_to(self.root).as_posix())
            if capped:
                break
        entries.sort()
        end = offset + limit
        return {"traces": entries[offset:end], "matched": len(entries), "offset": offset,
                "limit": limit, "next_offset": end if end < len(entries) else None,
                "listing_capped": capped}

