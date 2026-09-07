from __future__ import annotations

from dataclasses import dataclass
import re

import capstone as cs
from capstone import x86_const as x

from static_container import ContainerError
from static_image import Image
from static_semantics import function_extent, function_entry_rva, register_family


@dataclass(frozen=True)
class ExportHash:
    seed: int
    multiplier: int
    target: int
    multiply_rva: int
    compare_rva: int


def folded_hash(name: str, seed: int, multiplier: int) -> int:
    try:
        value = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise ContainerError("Export resolver supports ASCII names only") from error
    if not value or b"\0" in value or len(value) >= 255:
        raise ContainerError("Invalid export name")
    result = seed
    for byte in value:
        if 65 <= byte <= 90:
            byte += 32
        result = ((result ^ byte) * multiplier) & ((1 << 64) - 1)
    return result


def hash_loops(image: Image, start: int, end: int) -> tuple[ExportHash, ...]:
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(image.read(start, end - start), image.base + start))
    results = []

    def reg(op):
        return register_family(md, op.reg) if op.type == x.X86_OP_REG else None

    def rr(ins, mnemonic, destination, source):
        return (ins.mnemonic == mnemonic and len(ins.operands) == 2
                and reg(ins.operands[0]) == destination and reg(ins.operands[1]) == source)

    def ri(ins, mnemonic, destination, value):
        return (ins.mnemonic == mnemonic and len(ins.operands) == 2
                and reg(ins.operands[0]) == destination
                and ins.operands[1].type == x.X86_OP_IMM and ins.operands[1].imm == value)

    for index, multiply in enumerate(insns):
        ops = multiply.operands
        if (index < 8 or multiply.mnemonic != "imul" or len(ops) != 3
                or ops[0].type != x.X86_OP_REG or ops[0].size != 8
                or ops[1].type != x.X86_OP_REG or ops[1].size != 8
                or ops[2].type != x.X86_OP_IMM):
            continue
        accumulator, mixed = reg(ops[0]), reg(ops[1])
        body = insns[index - 8:index]
        if len(body[0].operands) != 2 or len(body[1].operands) != 2:
            continue
        original, character = reg(body[0].operands[0]), reg(body[0].operands[1])
        if None in (original, character) or len({original, character, accumulator, mixed}) != 4:
            continue
        if not (rr(body[0], "mov", original, character)
                and ri(body[1], "sub", character, ord("A"))
                and rr(body[2], "mov", mixed, original)
                and ri(body[3], "or", mixed, 0x20)
                and ri(body[4], "cmp", character, ord("Z") - ord("A"))
                and rr(body[5], "cmova", mixed, original)
                and rr(body[6], "movsxd", mixed, mixed)
                and rr(body[7], "xor", mixed, accumulator)):
            continue


        if body[1].operands[0].size != 1 or body[4].operands[0].size != 1:
            continue
        if any(body[i].operands[0].size != 4 for i in (0, 2, 3, 5)):
            continue
        if body[6].operands[0].size != 8 or body[6].operands[1].size != 4:
            continue
        initializers = [(i, ins) for i, ins in enumerate(insns[:index - 8])
                        if ins.mnemonic == "mov" and len(ins.operands) == 2
                        and reg(ins.operands[0]) == accumulator and ins.operands[0].size == 8
                        and ins.operands[1].type == x.X86_OP_REG]
        if not initializers:
            continue
        init_index, initialize = initializers[-1]
        seed_register = reg(initialize.operands[1])
        seed = None
        for ins in reversed(insns[:init_index]):
            _, writes = ins.regs_access()
            if not any(register_family(md, written) == seed_register for written in writes):
                continue
            if (ins.mnemonic in ("mov", "movabs") and len(ins.operands) == 2
                    and reg(ins.operands[0]) == seed_register and ins.operands[0].size in (4, 8)
                    and ins.operands[1].type == x.X86_OP_IMM):
                seed = ins.operands[1].imm & ((1 << (8 * ins.operands[0].size)) - 1)
            break
        if seed is None:
            continue


        loads = [ins for ins in insns[init_index + 1:index - 8]
                 if ins.mnemonic == "movsx" and len(ins.operands) == 2
                 and reg(ins.operands[0]) == character and ins.operands[0].size == 4
                 and ins.operands[1].type == x.X86_OP_MEM and ins.operands[1].size == 1]
        if len(loads) != 1:
            continue
        back_edges = [ins for ins in insns[index + 1:index + 5]
                      if ins.mnemonic in ("jne", "jnz") and ins.operands[0].type == x.X86_OP_IMM
                      and ins.operands[0].imm == loads[0].address]
        if len(back_edges) != 1:
            continue
        comparisons = [ins for ins in insns[index + 1:index + 12]
                       if ins.mnemonic == "cmp" and len(ins.operands) == 2
                       and reg(ins.operands[0]) == accumulator and ins.operands[0].size == 8
                       and ins.operands[1].type == x.X86_OP_REG]
        if len(comparisons) != 1:
            continue
        compare = comparisons[0]
        target_register = reg(compare.operands[1])
        target_value = None
        for ins in reversed([item for item in insns if item.address < compare.address]):
            _, writes = ins.regs_access()
            if not any(register_family(md, written) == target_register for written in writes):
                continue
            if (ins.mnemonic == "movabs" and len(ins.operands) == 2
                    and reg(ins.operands[0]) == target_register and ins.operands[0].size == 8
                    and ins.operands[1].type == x.X86_OP_IMM):
                target_value = ins.operands[1].imm
            break
        if target_value is not None:
            results.append(ExportHash(seed, ops[2].imm & ((1 << 64) - 1),
                                      target_value & ((1 << 64) - 1),
                                      multiply.address - image.base, compare.address - image.base))
    return tuple(results)


def discover_export_resolver(image: Image, name: str) -> tuple[int, dict]:
    ranges = set()
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]

        for match in re.finditer(rb"[\x48-\x4f]\x69[\xc0-\xff].{4}", data, re.DOTALL):
            try:
                ranges.add(function_extent(image, section.VirtualAddress + match.start()))
            except ContainerError:
                continue
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    found = []
    for start, end in sorted(ranges):


        code = image.read(start, end - start)
        if b"\x0f\xbe" not in code or b"\x0f\x47" not in code:
            continue
        candidates = [loop for loop in hash_loops(image, start, end)
                      if folded_hash(name, loop.seed, loop.multiplier) == loop.target]
        if not candidates:
            continue
        displacements = {op.mem.disp for ins in md.disasm(code, image.base + start)
                         for op in ins.operands if op.type == x.X86_OP_MEM}
        if not {0x3C, 0x88, 0x18, 0x20, 0x24, 0x1C} <= displacements:
            continue
        if len(candidates) != 1:
            raise ContainerError("Ambiguous export hash loops in one resolver")
        found.append((function_entry_rva(image, start), candidates[0]))
    if len(found) != 1:
        raise ContainerError(f"Expected one input-derived resolver for {name}; found {len(found)}")
    entry, loop = found[0]
    return entry, {"export_name": name, "seed_from_input": hex(loop.seed),
                   "multiplier_from_input": hex(loop.multiplier), "target_hash_from_input": hex(loop.target),
                   "multiply_rva": hex(loop.multiply_rva), "comparison_rva": hex(loop.compare_rva),
                   "saved_api_hash_used": False, "saved_game_address_used": False}
