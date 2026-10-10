"""Read-only D0 inventory of the four small ATLAS archives.

No archive member is extracted or executed. Pass the official ZIP files in the
order M1 raw, M1 experiment, S1 raw, S1 experiment.
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path


LABELS = (b"0xalsaheel.com", b"192.168.223.3", b"payload.exe", b"aalsahee/index.html")


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(path):
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        return {
            "archive_sha256": sha256_file(path),
            "compressed_file_bytes": path.stat().st_size,
            "members": len(infos),
            "uncompressed_member_bytes": sum(i.file_size for i in infos),
            "security_log_members": [i.filename for i in infos if i.filename.endswith("security_events.txt")],
            "malicious_label_members": [
                {"member": i.filename, "bytes": i.file_size,
                 "sha256": hashlib.sha256(z.read(i)).hexdigest()}
                for i in infos if i.filename.endswith("/malicious_labels.txt")
                and "/testing_logs/" in i.filename
            ],
        }


def scan_m1(path):
    result = {}
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.startswith("M1/") or not name.split("/")[-1] in ("dns", "firefox.txt", "security_events.txt"):
                continue
            counts = {s.decode(): 0 for s in LABELS}
            first = {s.decode(): None for s in LABELS}
            byte_offset = 0
            line_count = 0
            with z.open(name) as member:
                for line_count, line in enumerate(member, 1):
                    lower = line.lower()
                    for label in LABELS:
                        key = label.decode()
                        if label in lower:
                            counts[key] += 1
                            if first[key] is None:
                                first[key] = {"line": line_count, "byte_offset": byte_offset,
                                              "line_sha256": hashlib.sha256(line).hexdigest()}
                    byte_offset += len(line)
            result[name] = {"physical_lines": line_count, "uncompressed_bytes": byte_offset,
                            "literal_line_match_counts": counts, "first_literal_line_ref": first}
    return result


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: audit_zip.py M1_raw.zip M1_experiment.zip S1_raw.zip S1_experiment.zip")
    keys = ("M1_raw", "M1_experiment", "S1_raw", "S1_experiment")
    paths = [Path(p) for p in sys.argv[1:]]
    output = {"note": "Literal line hits are not event IDs, process instances, attack steps, or causal edges.",
              "archives": {k: inventory(p) for k, p in zip(keys, paths)},
              "M1_raw_literal_scan": scan_m1(paths[0])}
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
