from __future__ import annotations

from dataclasses import dataclass
import struct

import nacl.bindings
import nacl.exceptions


class ContainerError(ValueError):
    pass


@dataclass(frozen=True)
class Footer:
    offset: int
    start: int
    size: int


@dataclass(frozen=True)
class Table:
    index: int
    offset: int
    data: bytes


@dataclass(frozen=True)
class Instruction:
    rva: int
    data: bytes


@dataclass(frozen=True)
class Transform:
    table: int
    offset: int
    kind: int
    size: int
    targets: tuple[tuple[int, int], ...]
    source: bytes | None
    checksum_valid: bool


@dataclass(frozen=True)
class Container:
    footer: Footer
    plaintext: bytes
    tables: tuple[Table, ...]

    def table(self, index: int) -> bytes:
        return next((t.data for t in self.tables if t.index == index), b"")


def find_footers(data: bytes, *, base_offset: int = 0) -> list[Footer]:

    hits = []
    mask = (1 << 64) - 1

    for offset in range(len(data) - 40, max(-1, len(data) - 40 - 8192), -1):
        check, factor, size, salt, _ = struct.unpack_from("<5Q", data, offset)
        if (((~(factor * size)) & mask) ^ salt) != check:
            continue
        absolute_offset = base_offset + offset
        if size < 89 or size > absolute_offset:
            continue
        hits.append(Footer(absolute_offset, absolute_offset - size, size))
    return hits


def parse_tables(plaintext: bytes) -> tuple[Table, ...]:

    header_size = 8 + 32 * 24
    if len(plaintext) < header_size:
        raise ContainerError("Truncated container directory")
    tables = []
    spans = []
    for index in range(32):
        offset, size, _ = struct.unpack_from("<3Q", plaintext, 8 + 24 * index)
        if not size:
            continue
        start = header_size + offset
        end = start + size
        if start < header_size or end > len(plaintext):
            raise ContainerError(f"Table {index} exceeds authenticated plaintext")
        spans.append((start, end))
        tables.append(Table(index, start, plaintext[start:end]))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ContainerError("Container tables overlap")
    if not tables:
        raise ContainerError("Empty container directory")
    return tuple(tables)


def open_container(data: bytes) -> Container:
    successes = []
    for footer in find_footers(data):
        payload = data[footer.start:footer.offset]


        try:
            shared = nacl.bindings.crypto_box_beforenm(payload[32:64], payload[:32])
            nonce = payload[-8:] + bytes(16)
            plaintext = nacl.bindings.crypto_box_open_afternm(
                payload[64:-8], nonce, shared
            )
            tables = parse_tables(plaintext)
        except (nacl.exceptions.CryptoError, ValueError):
            continue
        successes.append(Container(footer, plaintext, tables))
    if len(successes) != 1:
        raise ContainerError(
            f"Expected one authenticated container; found {len(successes)}"
        )
    return successes[0]


def instructions(container: Container) -> tuple[Instruction, ...]:
    data = container.table(0)
    result = []
    position = 0
    while position < len(data):
        if len(data) - position < 5:
            raise ContainerError("Truncated native-instruction record")
        rva, size = struct.unpack_from("<IB", data, position)
        if not 1 <= size <= 15 or position + 5 + size > len(data):
            raise ContainerError("Invalid native-instruction record length")
        result.append(Instruction(rva, bytes(v ^ 255 for v in data[position + 5:position + 5 + size])))
        position += 5 + size


    selected = {}
    for record in result:
        selected.setdefault(record.rva, record)
    return tuple(selected.values())


def transforms(container: Container, table: int) -> tuple[Transform, ...]:
    if table not in (1, 3):
        raise ContainerError("Unknown transform-table format")
    data = container.table(table)
    header = 313 if table == 1 else 49
    position = 0
    result = []
    mask = (1 << 64) - 1
    while position < len(data):
        if len(data) - position < header:
            raise ContainerError("Truncated transform header")
        record_size, size = struct.unpack_from("<2Q", data, position)
        if record_size < header or position + record_size > len(data) or size == 0:
            raise ContainerError("Invalid transform extent")
        record = data[position:position + record_size]
        kind = record[header - 1]
        checksum_offset = 288 if table == 1 else 24
        a, b = struct.unpack_from("<2Q", record, checksum_offset)
        if table == 3 or kind in (21, 22):
            targets = ((struct.unpack_from("<Q", record, 16)[0], size),)
        else:
            rvas = struct.unpack_from("<16Q", record, 16)
            lengths = struct.unpack_from("<16Q", record, 144)
            targets = tuple((rva, length) for rva, length in zip(rvas, lengths) if rva)
            if not targets or any(length == 0 for _, length in targets):
                raise ContainerError("Invalid protected-range targets")
        source = None
        if kind != 22:
            if header + size != record_size:
                raise ContainerError("Inline source length differs from record extent")
            source = record[header:]
        elif record_size != header:
            raise ContainerError("Unexpected data after in-place transform header")
        if table == 3 and kind not in (21, 22):
            raise ContainerError(f"Unknown startup transform kind: {kind}")
        result.append(Transform(table, position, kind, size, targets, source, a == (b ^ mask)))
        position += record_size
    return tuple(result)


def xor_transform(source: bytes, seed: int, multiplier: int) -> bytes:

    mask = (1 << 64) - 1
    key = multiplier * (seed ^ len(source)) & mask
    output = bytearray(source)
    complete = len(output) // 8 * 8
    for offset in range(0, complete, 8):
        value = struct.unpack_from("<Q", output, offset)[0] ^ key
        struct.pack_into("<Q", output, offset, value)
        key = key * multiplier & mask
    for offset in range(complete, len(output)):
        output[offset] ^= key & 255
        key >>= 8
    return bytes(output)
