#!/usr/bin/env python3
"""Bounded-memory, read-only Avro OCF inventory for one official E5 CDM member.

Uses only the Python standard library. It inventories record kinds, host IDs and
timestamps; it does not infer attack edges or labels.
"""

import argparse
import collections
import datetime as dt
import gzip
import hashlib
import io
import json
import struct
import sys
from pathlib import Path


def read_exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise EOFError(f"wanted {n} bytes, got {len(b)}")
    return b


def long(f):
    shift = 0
    value = 0
    while True:
        byte = read_exact(f, 1)[0]
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return (value >> 1) ^ -(value & 1)
        shift += 7
        if shift > 70:
            raise ValueError("invalid Avro long")


def maybe_long(f):
    first = f.read(1)
    if not first:
        return None
    shift = 0
    value = 0
    byte = first[0]
    while True:
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return (value >> 1) ^ -(value & 1)
        shift += 7
        if shift > 70:
            raise ValueError("invalid Avro long")
        byte = read_exact(f, 1)[0]


def blob(f):
    size = long(f)
    if size < 0 or size > 128 * 1024 * 1024:
        raise ValueError(f"invalid byte length {size}")
    return read_exact(f, size)


def string(f):
    return blob(f).decode("utf-8", errors="replace")


def read_map_bytes(f):
    out = {}
    while True:
        count = long(f)
        if count == 0:
            return out
        if count < 0:
            count = -count
            long(f)
        for _ in range(count):
            key = string(f)
            out[key] = blob(f)


def collect_names(schema, names, namespace=None):
    if isinstance(schema, list):
        for item in schema:
            collect_names(item, names, namespace)
        return
    if not isinstance(schema, dict):
        return
    typ = schema.get("type")
    if typ in ("record", "enum", "fixed"):
        name = schema["name"]
        ns = schema.get("namespace", namespace)
        fullname = name if "." in name else f"{ns}.{name}" if ns else name
        names[fullname] = schema
        names.setdefault(name.split(".")[-1], schema)
        namespace = fullname.rpartition(".")[0]
    if typ == "record":
        for field in schema["fields"]:
            collect_names(field["type"], names, namespace)
    elif typ == "array":
        collect_names(schema["items"], names, namespace)
    elif typ == "map":
        collect_names(schema["values"], names, namespace)
    elif isinstance(typ, (list, dict)):
        collect_names(typ, names, namespace)


def decode(f, schema, names):
    if isinstance(schema, list):
        index = long(f)
        if not 0 <= index < len(schema):
            raise ValueError(f"invalid union index {index}")
        return decode(f, schema[index], names)
    if isinstance(schema, str):
        typ = schema
    else:
        typ = schema["type"]
    if isinstance(typ, (list, dict)):
        return decode(f, typ, names)
    if typ == "null":
        return None
    if typ == "boolean":
        return bool(read_exact(f, 1)[0])
    if typ in ("int", "long"):
        return long(f)
    if typ == "float":
        return struct.unpack("<f", read_exact(f, 4))[0]
    if typ == "double":
        return struct.unpack("<d", read_exact(f, 8))[0]
    if typ == "bytes":
        return blob(f).hex()
    if typ == "string":
        return string(f)
    if typ == "fixed":
        return read_exact(f, schema["size"]).hex()
    if typ == "enum":
        index = long(f)
        return schema["symbols"][index]
    if typ == "record":
        out = {"_record_type": schema["name"].split(".")[-1]}
        for field in schema["fields"]:
            out[field["name"]] = decode(f, field["type"], names)
        return out
    if typ in ("array", "map"):
        out = [] if typ == "array" else {}
        while True:
            count = long(f)
            if count == 0:
                return out
            if count < 0:
                count = -count
                long(f)
            if count > 10_000_000:
                raise ValueError("unreasonable array/map block")
            for _ in range(count):
                if typ == "array":
                    out.append(decode(f, schema["items"], names))
                else:
                    key = string(f)
                    out[key] = decode(f, schema["values"], names)
    if typ in names:
        return decode(f, names[typ], names)
    raise ValueError(f"unknown Avro type {typ}")


def utc_iso(ns):
    try:
        return dt.datetime.fromtimestamp(ns / 1e9, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def inventory(path, max_records, progress_every):
    stats = {
        "input": str(path), "reader": "stdlib Avro OCF streaming decoder v1",
        "record_count": 0, "block_count": 0, "record_types": collections.Counter(),
        "event_types": collections.Counter(), "host_ids": collections.Counter(),
        "cdm_versions": collections.Counter(), "timestamp_fields": {},
        "subject_types": collections.Counter(), "event_subject_ids_sample": [],
    }
    with gzip.open(path, "rb") as stream:
        if read_exact(stream, 4) != b"Obj\x01":
            raise ValueError("not an Avro OCF")
        metadata = read_map_bytes(stream)
        sync = read_exact(stream, 16)
        schema = json.loads(metadata["avro.schema"])
        codec = metadata.get("avro.codec", b"null").decode()
        if codec != "null":
            raise ValueError(f"unsupported codec {codec}")
        names = {}
        collect_names(schema, names)
        stats["ocf_codec"] = codec
        stats["embedded_schema_sha256"] = hashlib.sha256(metadata["avro.schema"]).hexdigest()
        stats["embedded_schema_name"] = schema.get("name")
        stats["embedded_schema_namespace"] = schema.get("namespace")
        while True:
            count = maybe_long(stream)
            if count is None:
                break
            size = long(stream)
            if count < 0 or size < 0 or size > 128 * 1024 * 1024:
                raise ValueError(f"invalid block count/size {count}/{size}")
            raw = read_exact(stream, size)
            block = io.BytesIO(raw)
            for _ in range(count):
                row = decode(block, schema, names)
                stats["record_count"] += 1
                kind = row.get("type") or row.get("datum", {}).get("_record_type") or "UNKNOWN"
                stats["record_types"][str(kind)] += 1
                stats["host_ids"][str(row.get("hostId"))] += 1
                stats["cdm_versions"][str(row.get("CDMVersion"))] += 1
                datum = row.get("datum") or {}
                if datum.get("_record_type") == "Event":
                    stats["event_types"][str(datum.get("type"))] += 1
                    if len(stats["event_subject_ids_sample"]) < 10:
                        stats["event_subject_ids_sample"].append(datum.get("subject"))
                elif datum.get("_record_type") == "Subject":
                    stats["subject_types"][str(datum.get("type"))] += 1
                for field in ("timestampNanos", "startTimestampNanos"):
                    value = datum.get(field)
                    if isinstance(value, int) and value > 0:
                        span = stats["timestamp_fields"].setdefault(field, {"min": value, "max": value, "count": 0})
                        span["min"] = min(span["min"], value)
                        span["max"] = max(span["max"], value)
                        span["count"] += 1
                if max_records and stats["record_count"] >= max_records:
                    break
            if block.tell() != size and not (max_records and stats["record_count"] >= max_records):
                raise ValueError(f"block trailing bytes: {size - block.tell()}")
            if read_exact(stream, 16) != sync:
                raise ValueError("OCF sync mismatch")
            stats["block_count"] += 1
            if progress_every and stats["record_count"] % progress_every < count:
                print(f"processed {stats['record_count']} records, {stats['block_count']} blocks", file=sys.stderr, flush=True)
            if max_records and stats["record_count"] >= max_records:
                stats["stopped_early"] = True
                break
    for span in stats["timestamp_fields"].values():
        span["min_utc"] = utc_iso(span["min"])
        span["max_utc"] = utc_iso(span["max"])
    for key in ("record_types", "event_types", "host_ids", "cdm_versions", "subject_types"):
        stats[key] = dict(stats[key])
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--max-records", type=int, default=0)
    ap.add_argument("--progress-every", type=int, default=100000)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    stats = inventory(args.input, args.max_records, args.progress_every)
    result = json.dumps(stats, indent=2, sort_keys=True, ensure_ascii=False)
    if args.output:
        args.output.write_text(result + "\n")
    else:
        print(result)


if __name__ == "__main__":
    main()
