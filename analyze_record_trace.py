#!/usr/bin/env python3
"""Inspect records captured after MATLAB's R2025a PVM decoder."""

from __future__ import annotations

import argparse
import collections
import dataclasses
import pathlib
import struct
import sys

MAGIC_V1 = b"PCTR0001"
MAGIC_V2 = b"PCTR0002"
MAGIC_V3 = b"PCTR0003"


@dataclasses.dataclass(frozen=True)
class Record:
    index: int
    type: int
    mask: int
    has_payload: bool
    value: int
    payload: bytes


@dataclasses.dataclass(frozen=True)
class PermutationEvent:
    record_index: int
    mode: int
    count: int
    placements: tuple[tuple[int, int], ...]


def read_trace_with_permutations(
        path: pathlib.Path) -> tuple[list[Record], dict[int, PermutationEvent]]:
    data = memoryview(path.read_bytes())
    if len(data) < 16 or data[:8] not in (MAGIC_V1, MAGIC_V2, MAGIC_V3):
        raise ValueError(f"{path}: not a supported PCTR trace")
    version = {MAGIC_V1: 1, MAGIC_V2: 2, MAGIC_V3: 3}[bytes(data[:8])]
    count = struct.unpack_from("<Q", data, 8)[0]
    offset = 16
    records: list[Record] = []
    for index in range(count):
        header_size = 8 if version == 1 else 12
        if offset + header_size > len(data):
            raise ValueError(f"{path}: truncated record header {index}")
        if version == 1:
            record_type, mask, flags, payload_length = struct.unpack_from("<BBHI", data, offset)
            value = payload_length if flags & 1 else 0
        else:
            record_type, mask, flags, value, payload_length = struct.unpack_from(
                "<BBHII", data, offset)
        offset += header_size
        if offset + payload_length > len(data):
            raise ValueError(f"{path}: truncated payload {index}")
        payload = bytes(data[offset : offset + payload_length])
        offset += payload_length
        records.append(Record(index, record_type, mask, bool(flags & 1), value, payload))
    permutations: dict[int, PermutationEvent] = {}
    if version >= 3:
        if offset + 8 > len(data):
            raise ValueError(f"{path}: missing permutation section")
        permutation_count = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
        for event_index in range(permutation_count):
            if offset + 20 > len(data):
                raise ValueError(f"{path}: truncated permutation event {event_index}")
            record_index, mode, item_count, placement_count = struct.unpack_from(
                "<QIII", data, offset)
            offset += 20
            placements: list[tuple[int, int]] = []
            for _ in range(placement_count):
                if offset + 8 > len(data):
                    raise ValueError(f"{path}: truncated permutation placement")
                placements.append(struct.unpack_from("<II", data, offset))
                offset += 8
            permutations[record_index] = PermutationEvent(
                record_index, mode, item_count, tuple(placements))
    if offset != len(data):
        raise ValueError(f"{path}: {len(data) - offset} trailing bytes")
    return records, permutations


def read_trace(path: pathlib.Path) -> list[Record]:
    return read_trace_with_permutations(path)[0]


def display_bytes(payload: bytes) -> str:
    if not payload:
        return ""
    escaped = "".join(chr(byte) if 32 <= byte < 127 and byte not in (92,) else f"\\x{byte:02x}"
                      for byte in payload)
    return escaped


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=pathlib.Path)
    parser.add_argument("--all", action="store_true", help="show records without payloads too")
    parser.add_argument("--limit", type=int, default=0, help="maximum displayed records")
    parser.add_argument("--strings-only", action="store_true",
                        help="print payload strings in stream order without statistics")
    parser.add_argument("--output", type=pathlib.Path,
                        help="write report to this UTF-8 text file")
    args = parser.parse_args()

    records = read_trace(args.trace)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        stream = args.output.open("w", encoding="utf-8", newline="\n")
    else:
        stream = sys.stdout
    try:
        if args.strings_only:
            for record in records:
                if record.has_payload:
                    print(display_bytes(record.payload), file=stream)
            return
        type_counts = collections.Counter(record.type for record in records)
        payload_counts = collections.Counter(record.type for record in records if record.has_payload)
        masks = collections.Counter(record.mask for record in records)

        print(f"records={len(records)} payload_records={sum(payload_counts.values())} "
              f"payload_bytes={sum(len(record.payload) for record in records)}", file=stream)
        print("types:", " ".join(f"{key}:{value}" for key, value in sorted(type_counts.items())),
              file=stream)
        print("payload types:",
              " ".join(f"{key}:{value}" for key, value in sorted(payload_counts.items())),
              file=stream)
        print("masks:", " ".join(f"{key:02x}:{value}" for key, value in sorted(masks.items())),
              file=stream)

        shown = 0
        for record in records:
            if not args.all and not record.has_payload:
                continue
            print(f"{record.index:6d} type={record.type:3d} mask={record.mask:02x} "
                  f"value={record.value:8d} len={len(record.payload):5d} "
                  f"payload={display_bytes(record.payload)}",
                  file=stream)
            shown += 1
            if args.limit and shown >= args.limit:
                break
    finally:
        if stream is not sys.stdout:
            stream.close()


if __name__ == "__main__":
    main()

