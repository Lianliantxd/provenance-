"""Verify the exact public allowlist using the existing Python standard library."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "PUBLIC_MANIFEST.json").read_text())
    allowed = {"PUBLIC_MANIFEST.json"}
    for entry in manifest["files"]:
        rel = PurePosixPath(entry["path"])
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError("Unsafe relative path")
        path = root / rel
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Symlink or escaped path")
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"Checksum mismatch: {rel}")
        allowed.add(str(rel))
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual != allowed:
        raise ValueError("Unexpected or missing publication files")
    print(json.dumps({"status": "PUBLIC_MANIFEST_VERIFIED", "files": len(manifest["files"])}))


if __name__ == "__main__":
    main()
