from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import re
import struct

import capstone as cs
from capstone import x86_const as x
import nacl.bindings
import nacl.exceptions

from static_container import ContainerError
from static_image import Image, XorCodec


@dataclass(frozen=True)
class SealedString:
    call_rva: int
    decoder_rva: int
    source_rva: int
    public_key_rva: int
    plaintext: bytes


def exception_records(image: Image) -> tuple[tuple[int, int, int], ...]:
    cached = getattr(image, "_exception_records", None)
    if cached is not None:
        return cached
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    if not directory.Size or directory.Size % 12:
        raise ContainerError("Missing or malformed x64 exception directory")
    rows = tuple(sorted(set(struct.iter_unpack("<III", image.read(directory.VirtualAddress, directory.Size)))))
    if any(start >= end for start, end, _ in rows) or any(a[1] > b[0] for a, b in zip(rows, rows[1:])):
        raise ContainerError("Invalid or overlapping exception function ranges")
    image._exception_records = rows
    image._exception_starts = tuple(row[0] for row in rows)
    image._exception_record_set = frozenset(rows)
    return rows


def _exception_record_at(image: Image, rva: int) -> tuple[int, int, int]:
    rows = exception_records(image)
    index = bisect_right(image._exception_starts, rva) - 1
    if index < 0 or rva >= rows[index][1]:
        raise ContainerError("Instruction lacks a unique declared function extent")
    start, end, _ = rows[index]
    image.offset(start, end - start, executable=True)
    return rows[index]


def function_extent(image: Image, rva: int) -> tuple[int, int]:
    start, end, _ = _exception_record_at(image, rva)
    return start, end


def function_entry_rva(image: Image, rva: int) -> int:

    row = _exception_record_at(image, rva)
    entries = image._exception_record_set
    visited = set()
    while row not in visited:
        visited.add(row)
        start, end, unwind = row
        image.offset(start, end - start, executable=True)
        version_flags, _, count, _ = image.read(unwind, 4)
        version, flags = version_flags & 7, version_flags >> 3
        if version not in (1, 2) or flags & ~7:
            raise ContainerError("Unsupported x64 unwind metadata")
        if not flags & 4:
            return start
        if flags & 3:
            raise ContainerError("Chained unwind metadata also declares a handler")
        chain = unwind + 4 + ((count + 1) & ~1) * 2
        row = struct.unpack("<III", image.read(chain, 12))
        if row not in entries:
            raise ContainerError("Chained unwind parent is absent from the exception directory")
    raise ContainerError("Cyclic x64 unwind chain")


def register_family(md, reg: int) -> str:
    name = md.reg_name(reg)
    aliases = {alias: full for full, members in {
        "rax": ("eax", "ax", "al", "ah"), "rbx": ("ebx", "bx", "bl", "bh"),
        "rcx": ("ecx", "cx", "cl", "ch"), "rdx": ("edx", "dx", "dl", "dh"),
        "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
        "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl"),
    }.items() for alias in members}
    if re.fullmatch(r"r(?:[89]|1[0-5])[dbw]", name):
        return name[:-1]
    return aliases.get(name, name)


def sealed_strings(image: Image, start: int, end: int) -> tuple[SealedString, ...]:

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    decoded = list(md.disasm(image.read(start, end - start), image.base + start))
    if not decoded or decoded[-1].address + decoded[-1].size != image.base + end:
        raise ContainerError("Loader function does not decode to its declared end")
    labels = {i.operands[0].imm for i in decoded if i.group(cs.CS_GRP_JUMP)
              and i.operands and i.operands[0].type == x.X86_OP_IMM}
    state = {}
    results = []
    volatile = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
    for ins in decoded:
        if ins.address in labels:
            state.clear()
        ops = ins.operands
        if ins.group(cs.CS_GRP_CALL):
            source, size, key = (state.get(r) for r in ("rdx", "r8", "r9"))
            if (source is not None and key is not None and size is not None
                    and 49 < size <= 4096 and ops[0].type == x.X86_OP_IMM):
                try:
                    pair = image.read(key - image.base, 64)
                    public, private = pair[:32], pair[32:]
                    if nacl.bindings.crypto_scalarmult_base(private) == public:
                        blob = image.read(source - image.base, size - 1)
                        plain = nacl.bindings.crypto_box_seal_open(blob, public, private)
                        results.append(SealedString(ins.address - image.base,
                                                   ops[0].imm - image.base,
                                                   source - image.base,
                                                   key - image.base, plain))
                except (ContainerError, nacl.exceptions.CryptoError, ValueError):
                    pass
            for reg in volatile:
                state.pop(reg, None)
            continue
        assignment = None
        if len(ops) == 2 and ops[0].type == x.X86_OP_REG and ops[0].size in (4, 8):
            name = register_family(md, ops[0].reg)
            value = None
            if ins.mnemonic in ("mov", "movabs"):
                if ops[1].type == x.X86_OP_IMM:
                    value = ops[1].imm
                elif ops[1].type == x.X86_OP_REG:
                    value = state.get(register_family(md, ops[1].reg))
            elif ins.mnemonic == "lea" and ops[1].type == x.X86_OP_MEM:
                memory = ops[1].mem
                if memory.base == x.X86_REG_RIP and not memory.index:
                    value = ins.address + ins.size + memory.disp
                elif not memory.segment:
                    base = 0 if not memory.base else state.get(register_family(md, memory.base))
                    index = 0 if not memory.index else state.get(register_family(md, memory.index))
                    if base is not None and index is not None:
                        value = base + index * memory.scale + memory.disp
            elif ins.mnemonic == "xor" and ops[1].type == x.X86_OP_REG and ops[0].reg == ops[1].reg:
                value = 0
            if value is not None:
                assignment = (name, value & ((1 << (8 * ops[0].size)) - 1))
        _, writes = ins.regs_access()
        for reg in writes:
            state.pop(register_family(md, reg), None)
        if assignment:
            state[assignment[0]] = assignment[1]
        if ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_RET):
            state.clear()
    return tuple(results)


def discover_embedded_container_name(image: Image, codec: XorCodec) -> tuple[bytes, dict]:
    extents = {function_extent(image, rva) for rva in codec.evidence_rvas}
    if len(extents) != 1:
        raise ContainerError("XOR discovery does not identify one loader function")
    start, end = next(iter(extents))
    literals = sealed_strings(image, start, end)
    names = {s.plaintext.rstrip(b"\0") for s in literals
             if re.fullmatch(rb"\.[A-Za-z0-9_]{1,7}\x00", s.plaintext)}
    if len(names) != 1:
        raise ContainerError(f"Expected one authenticated loader section-name literal; found {len(names)}")
    name = next(iter(names))
    return name, {"loader_start_rva": hex(start), "loader_end_rva": hex(end),
                  "section_name": name.decode("ascii"),
                  "literal_call_rvas": [hex(s.call_rva) for s in literals if s.plaintext.rstrip(b"\0") == name]}
