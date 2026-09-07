from __future__ import annotations

from dataclasses import dataclass
import re
import struct

import capstone as cs
from capstone import x86_const as x
import pefile

from static_container import ContainerError


@dataclass(frozen=True)
class XorCodec:
    multiplier: int
    seed_rva: int
    evidence_rvas: tuple[int, ...]


class Image:
    def __init__(self, data: bytes):
        self.data = data
        try:
            self.pe = pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError as error:
            raise ContainerError(f"Invalid PE: {error}") from error
        pe = self.pe
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ContainerError("Expected an x64 PE32+ image")
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.sections = list(pe.sections)
        raw_spans = []
        virtual_spans = []
        if not self.sections or pe.OPTIONAL_HEADER.SizeOfHeaders > len(data):
            raise ContainerError("Missing sections or truncated headers")
        for section in self.sections:
            start = section.PointerToRawData
            size = section.SizeOfRawData
            if size:
                if start < pe.OPTIONAL_HEADER.SizeOfHeaders or start + size > len(data):
                    raise ContainerError("Section exceeds file or overlaps headers")
                raw_spans.append((start, start + size))
            va = section.VirtualAddress
            extent = max(section.Misc_VirtualSize, size)
            if va < pe.OPTIONAL_HEADER.SizeOfHeaders or va + extent > pe.OPTIONAL_HEADER.SizeOfImage:
                raise ContainerError("Section exceeds image or overlaps headers")
            virtual_spans.append((va, va + extent))
        for spans in (raw_spans, virtual_spans):
            spans.sort()
            if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
                raise ContainerError("Ambiguous overlapping PE sections")
        self.offset(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 1, executable=True)

    def offset(self, rva: int, size: int, *, executable: bool = False) -> int:
        if rva < 0 or size < 1:
            raise ContainerError("Invalid image extent")
        matches = []
        for section in self.sections:
            relative = rva - section.VirtualAddress
            if relative >= 0 and relative + size <= min(section.SizeOfRawData, section.Misc_VirtualSize):
                if executable and not section.Characteristics & 0x20000000:
                    raise ContainerError("Code target lies in a non-executable section")
                matches.append(section.PointerToRawData + relative)
        if len(matches) != 1:
            raise ContainerError(f"Unbacked or ambiguous image extent at RVA {rva:#x}")
        return matches[0]

    def read(self, rva: int, size: int) -> bytes:
        offset = self.offset(rva, size)
        return self.data[offset:offset + size]


def discover_xor_codec(image: Image) -> XorCodec:

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    discoveries: dict[tuple[int, int], set[int]] = {}
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        blob = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(rb"[\x48-\x4f][\xb8-\xbf].{8}", blob, re.DOTALL):
            offset = match.start()
            value = struct.unpack_from("<Q", blob, offset + 2)[0]
            if value <= 0xFFFFFFFF or not value & 1:
                continue
            window = blob[offset:offset + 1024]
            if window.count(b"\x0f\xaf") < 2:
                continue


            if not re.search(
                rb"[\x48-\x4f]\x31[\x00-\x3f].{0,12}"
                rb"[\x48-\x4f]\x83[\xc0-\xc7]\x08.{0,8}"
                rb"[\x48-\x4f]\x0f\xaf", window, re.DOTALL
            ):
                continue
            rva = section.VirtualAddress + offset
            insns = list(md.disasm(window, image.base + rva))
            if not insns or insns[0].mnemonic != "movabs":
                continue
            key_register = insns[0].operands[0].reg
            for index, instruction in enumerate(insns):
                operands = instruction.operands
                if instruction.mnemonic != "xor" or len(operands) != 2:
                    continue
                if operands[0].type != x.X86_OP_REG or operands[1].type != x.X86_OP_MEM:
                    continue
                if operands[1].mem.base != x.X86_REG_RIP or operands[1].size != 8:
                    continue
                accumulator = operands[0].reg
                following = insns[index + 1:index + 17]
                if not following:
                    continue

                def multiply(ins):
                    ops = ins.operands
                    return (ins.mnemonic == "imul" and len(ops) == 2
                            and all(o.type == x.X86_OP_REG for o in ops)
                            and ops[0].reg == accumulator and ops[1].reg == key_register)

                if not multiply(following[0]) or sum(multiply(i) for i in following) < 2:
                    continue
                writes = [i for i in following if i.mnemonic == "xor"
                          and len(i.operands) == 2
                          and i.operands[0].type == x.X86_OP_MEM
                          and i.operands[0].size == 8
                          and i.operands[1].type == x.X86_OP_REG
                          and i.operands[1].reg == accumulator]
                if len(writes) != 1:
                    continue
                write = writes[0]
                pointer = write.operands[0].mem.base
                advances = [i for i in following if i.mnemonic == "add"
                            and len(i.operands) == 2
                            and i.operands[0].type == x.X86_OP_REG
                            and i.operands[0].reg == pointer
                            and i.operands[1].type == x.X86_OP_IMM
                            and i.operands[1].imm == 8]
                back_edges = [i for i in following if i.mnemonic == "jne"
                              and i.operands[0].type == x.X86_OP_IMM
                              and i.operands[0].imm == write.address]
                if not advances or not back_edges:
                    continue
                seed_rva = instruction.address + instruction.size + operands[1].mem.disp - image.base
                if not any(s.VirtualAddress <= seed_rva
                           and seed_rva + 8 <= s.VirtualAddress + s.Misc_VirtualSize
                           and s.Characteristics & 0x80000000 for s in image.sections):
                    continue
                discoveries.setdefault((value, seed_rva), set()).add(rva)
    if len(discoveries) != 1:
        raise ContainerError(f"Expected one XOR recurrence; found {len(discoveries)}")
    (multiplier, seed_rva), evidence = next(iter(discoveries.items()))
    return XorCodec(multiplier, seed_rva, tuple(sorted(evidence)))
