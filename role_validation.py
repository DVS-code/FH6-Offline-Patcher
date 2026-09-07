import capstone as cs
from capstone import x86_const as x
import struct

from recognition import Profile, instruction_mask
from static_container import ContainerError
from static_semantics import function_extent, register_family
from tls_layout import tls_operands


def _switch_tables(image, begin, end, decoded, md):

    tables = []
    for index in range(2, len(decoded) - 3):
        compare, bounds = decoded[index - 2:index]
        base, load, add, jump = decoded[index:index + 4]
        if (base.mnemonic != "lea" or len(base.operands) != 2
                or base.operands[0].type != x.X86_OP_REG or base.operands[1].type != x.X86_OP_MEM
                or base.operands[1].mem.base != x.X86_REG_RIP
                or base.address + base.size + base.operands[1].mem.disp != image.base):
            continue
        base_reg = register_family(md, base.operands[0].reg)
        if (load.mnemonic not in ("mov", "movsxd") or len(load.operands) != 2
                or load.operands[0].type != x.X86_OP_REG or load.operands[1].type != x.X86_OP_MEM
                or load.operands[1].size != 4 or load.operands[1].mem.scale != 4
                or not load.operands[1].mem.index
                or register_family(md, load.operands[1].mem.base) != base_reg):
            continue
        destination = register_family(md, load.operands[0].reg)
        if (add.mnemonic != "add" or len(add.operands) != 2
                or any(op.type != x.X86_OP_REG for op in add.operands)
                or register_family(md, add.operands[0].reg) != destination
                or register_family(md, add.operands[1].reg) != base_reg
                or jump.mnemonic != "jmp" or len(jump.operands) != 1
                or jump.operands[0].type != x.X86_OP_REG
                or register_family(md, jump.operands[0].reg) != destination):
            continue
        if (compare.mnemonic != "cmp" or len(compare.operands) != 2
                or compare.operands[0].type != x.X86_OP_REG or compare.operands[1].type != x.X86_OP_IMM
                or register_family(md, compare.operands[0].reg) != register_family(md, load.operands[1].mem.index)
                or bounds.mnemonic != "ja" or bounds.operands[0].type != x.X86_OP_IMM
                or not image.base + begin <= bounds.operands[0].imm < image.base + end):
            raise ContainerError("Image-relative switch has no supported unsigned bound")
        count = compare.operands[1].imm + 1
        table = load.operands[1].mem.disp
        if not 1 <= count <= (end - begin) // 4 or not begin <= table < table + count * 4 <= end:
            raise ContainerError("Image-relative switch table exceeds its containing region")
        targets = struct.unpack("<" + "I" * count, image.read(table, count * 4))
        if any(not begin <= target < table for target in targets):
            raise ContainerError("Switch target is outside the code preceding its table")
        tables.append((table, targets, load.address - image.base - begin + load.disp_offset, load.disp_size))
    return tables


def region_shape(image, rva):
    begin, end = function_extent(image, rva)
    code = image.read(begin, end - begin)
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    decoded = list(md.disasm(code, image.base + begin))
    tables = _switch_tables(image, begin, end, decoded, md)
    code_end = min((table for table, _, _, _ in tables), default=end)
    native = code[:code_end - begin]
    signature, mask = instruction_mask(native, image.base + begin, image)
    if len(signature) != len(native):
        raise ContainerError(f"Containing region {begin:#x}..{end:#x} has undecoded native bytes")
    signature, mask = bytearray(signature), bytearray(mask)
    decoded = list(md.disasm(native, image.base + begin))
    tls_spans, tls_identity = tls_operands(image, decoded, md,
            tuple(image.base + target for _, targets, _, _ in tables for target in targets))
    for offset, size in tls_spans:
        signature[offset:offset + size] = bytes(size)
        mask[offset:offset + size] = bytes(size)
    boundaries = {instruction.address - image.base for instruction in decoded}
    cursor = code_end
    for table, targets, displacement, width in sorted(tables):
        if table != cursor or width != 4 or any(target not in boundaries for target in targets):
            raise ContainerError("Switch tables overlap, leave unsupported data, or target instruction operands")
        signature[displacement:displacement + width] = bytes(width)
        mask[displacement:displacement + width] = bytes(width)

        signature.extend(struct.pack("<" + "I" * len(targets), *(target - begin for target in targets)))
        mask.extend(b"\1" * (4 * len(targets)))
        cursor += 4 * len(targets)
    if cursor != end:
        raise ContainerError("Unsupported bytes after native code and switch tables")
    for instruction in decoded:
        if (instruction.group(cs.CS_GRP_JUMP) or instruction.group(cs.CS_GRP_CALL)) and instruction.operands:
            operand = instruction.operands[0]
            if operand.type == x.X86_OP_IMM and image.base + begin <= operand.imm < image.base + end:
                offset = instruction.address - image.base - begin + instruction.imm_offset
                size = instruction.imm_size
                mask[offset:offset + size] = b"\1" * size
                signature[offset:offset + size] = code[offset:offset + size]
    if tls_identity:
        signature.extend(b'TLS1' + tls_identity)
        mask.extend(b'\1' * (4 + len(tls_identity)))
    return bytes(signature), bytes(mask)


def validate_region_shape(image, profile, rva, validation):
    if validation.get("kind") == "argument_only_leaf":
        if profile.action != "return_from_thread_hide_leaf":
            raise ContainerError("Leaf identity validation assigned to an incompatible role")

        return
    if validation.get("kind") == "complete_containing_region_digest":
        from dependencies import region_digest
        if region_digest(image, rva) != validation.get("digest"):
            raise ContainerError(f"{profile.role}: complete containing region or control flow changed")
    elif validation.get("kind") == "complete_containing_region":
        expected = Profile.from_json({"role": profile.role, "action": profile.action,
                                      "signature": validation["signature"], "mask": validation["mask"]})
        actual_signature, actual_mask = region_shape(image, rva)
        if actual_mask != expected.mask or actual_signature != expected.signature:
            raise ContainerError(f"{profile.role}: complete containing region or control flow changed")
    else:
        raise ContainerError(f"Missing complete-region identity validation for {profile.role}")
    if "dependencies" in validation:
        from dependencies import dependency_shape
        if dependency_shape(image, rva) != validation["dependencies"]:
            raise ContainerError(f"{profile.role}: native, import, or data dependency changed")
