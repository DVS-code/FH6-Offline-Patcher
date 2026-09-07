from __future__ import annotations

from dataclasses import dataclass
import re
import struct

import capstone as cs
from capstone import x86_const as x

from static_container import ContainerError
from static_image import Image


@dataclass(frozen=True)
class Profile:
    role: str
    signature: bytes
    mask: bytes
    action: str
    validation: dict | None = None

    @classmethod
    def from_json(cls, row):
        result = cls(row["role"], bytes.fromhex(row["signature"]), bytes.fromhex(row["mask"]), row["action"], row.get("validation"))
        if result.validation is not None and not isinstance(result.validation, dict):
            raise ContainerError("Invalid region-validation record")
        if (not result.signature or len(result.signature) != len(result.mask)
                or set(result.mask) - {0, 1} or not any(result.mask)):
            raise ContainerError("Invalid instruction recognition profile")
        if any(byte for byte, keep in zip(result.signature, result.mask) if not keep):
            raise ContainerError("Masked operands must not retain reference addresses")
        return result


def displacement_encoding(ins):

    operands = [op for op in ins.operands if op.type == x.X86_OP_MEM and op.mem.base == x.X86_REG_RIP]
    if not operands:
        return ins.disp_offset, ins.disp_size
    offset = ins.disp_offset
    if (ins.addr_size != 8 or not ins.modrm_offset or ins.modrm & 0xC7 != 5
            or offset != ins.modrm_offset + 1 or offset + 4 > ins.size
            or any(op.mem.disp != struct.unpack_from('<i', ins.bytes, offset)[0] for op in operands)):
        raise ContainerError("RIP-relative operand lacks a proved disp32 encoding")
    return offset, 4


def instruction_mask(code: bytes, va: int, image: Image) -> tuple[bytes, bytes]:
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    mask = bytearray(b"\1" * len(code))
    consumed = 0
    for ins in md.disasm(code, va):
        offset = ins.address - va
        consumed = offset + ins.size
        if any(o.type == x.X86_OP_MEM and o.mem.base == x.X86_REG_RIP for o in ins.operands):
            displacement, width = displacement_encoding(ins)
            mask[offset + displacement:offset + displacement + width] = bytes(width)
        address_immediate = any(o.type == x.X86_OP_IMM and image.base <= o.imm < image.base + image.pe.OPTIONAL_HEADER.SizeOfImage
                                for o in ins.operands)
        if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) or address_immediate:
            mask[offset + ins.imm_offset:offset + ins.imm_offset + ins.imm_size] = bytes(ins.imm_size)
    if not consumed:
        raise ContainerError("Recognition profile does not start with a native instruction")
    code, mask = code[:consumed], bytes(mask[:consumed])
    return bytes(byte if keep else 0 for byte, keep in zip(code, mask)), mask


def masked_hits(data: bytes, profile: Profile, limit: int = 2) -> list[int]:
    spans = [(m.start(), m.end()) for m in re.finditer(b"\1+", profile.mask)]
    if not spans:
        raise ContainerError("Recognition profile has no fixed instruction evidence")
    begin, end = max(spans, key=lambda span: span[1] - span[0])
    anchor = profile.signature[begin:end]
    result = []
    position = data.find(anchor)
    while position >= 0:
        start = position - begin
        if start >= 0 and start + len(profile.signature) <= len(data):
            if all(data[start + a:start + b] == profile.signature[a:b] for a, b in spans):
                result.append(start)
                if len(result) >= limit:
                    break
        position = data.find(anchor, position + 1)
    return result


def discover_profile(image: Image, profile: Profile) -> int:
    candidates = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        candidates.extend(section.VirtualAddress + offset for offset in masked_hits(data, profile))
        if len(candidates) > 1:
            break
    if len(candidates) != 1:
        raise ContainerError(f"{profile.role}: expected one instruction-profile match, found {len(candidates)}")
    return candidates[0]
