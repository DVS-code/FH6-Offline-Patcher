import capstone as cs
from capstone import x86_const as x

from control_flow import direct_callers
from patch_actions import entry_return
from recognition import Profile, masked_hits, displacement_encoding
from static_container import ContainerError
from static_semantics import function_extent, function_entry_rva, register_family


def normalized_instruction(ins, base):
    operands = []
    for op in ins.operands:
        if op.type == x.X86_OP_REG:
            value = ("reg", op.size, op.reg)
        elif op.type == x.X86_OP_IMM:
            immediate = op.imm - ins.address if ins.group(cs.CS_GRP_JUMP) else op.imm
            value = ("imm", op.size, immediate)
        elif op.type == x.X86_OP_MEM:
            memory = op.mem
            displacement = (ins.address + ins.size + memory.disp - base
                            if memory.base == x.X86_REG_RIP else memory.disp)
            value = ("mem", op.size, memory.segment, memory.base, memory.index, memory.scale, displacement)
        else:
            value = ("other", op.type)
        operands.append(value)
    return ins.mnemonic, ins.size, tuple(operands)


def discover_formatter_variant(image, prototype):
    start, end = function_extent(image, prototype)
    if start != prototype or function_entry_rva(image, start) != start:
        raise ContainerError("Formatter prototype is not a proved function entry")
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    source = image.read(start, end - start)
    original = list(md.disasm(source, image.base + start))
    if not original or original[-1].address + original[-1].size != image.base + end:
        raise ContainerError("Formatter prototype does not decode completely")
    mask = bytearray(b"\1" * len(source))
    for ins in original:
        offset = ins.address - image.base - start
        for position, size in ((ins.imm_offset, ins.imm_size), displacement_encoding(ins)):
            mask[offset + position:offset + position + size] = bytes(size)
    profile = Profile("input_formatter_shape", bytes(value if keep else 0 for value, keep in zip(source, mask)),
                      bytes(mask), "candidate_only")
    candidates = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        offsets = masked_hits(section.get_data()[:section.Misc_VirtualSize], profile, limit=1025)
        if len(offsets) > 1024:
            raise ContainerError("Formatter candidate shape is insufficiently selective")
        for offset in offsets:
            rva = section.VirtualAddress + offset
            if rva == prototype:
                continue
            if function_extent(image, rva) != (rva, rva + len(source)) or function_entry_rva(image, rva) != rva:
                continue
            code = list(md.disasm(image.read(rva, len(source)), image.base + rva))
            if len(code) != len(original):
                continue
            differences = [(a, b) for a, b in zip(original, code)
                           if normalized_instruction(a, image.base) != normalized_instruction(b, image.base)]
            if len(differences) != 1:
                continue
            a, b = differences[0]
            if (a.mnemonic != "mov" or b.mnemonic != "mov" or len(a.operands) != 2 or len(b.operands) != 2
                    or a.operands[0].type != x.X86_OP_MEM or a.operands[0].size != 4
                    or a.operands[0].mem.base not in (x.X86_REG_RBP, x.X86_REG_RSP)
                    or a.operands[0].mem.index or a.operands[0].mem.segment
                    or a.operands[1].type != x.X86_OP_IMM or b.operands[1].type != x.X86_OP_IMM
                    or normalized_instruction(a, image.base)[:2] != normalized_instruction(b, image.base)[:2]
                    or normalized_instruction(a, image.base)[2][0] != normalized_instruction(b, image.base)[2][0]):
                continue
            candidates.append((rva, a, b))
    if len(candidates) != 1:
        raise ContainerError(f"Expected one dependency-identical formatter variant; found {len(candidates)}")
    rva, original_tag, variant_tag = candidates[0]
    callers = direct_callers(image, rva)
    if not callers:
        raise ContainerError("Formatter variant has no validated callers")
    for call in callers:
        owner, owner_end = function_extent(image, call)
        code = list(md.disasm(image.read(owner, owner_end - owner), image.base + owner))
        discarded = False
        for ins in code:
            if ins.address - image.base <= call:
                continue
            if ins.group(cs.CS_GRP_CALL):
                discarded = True
                break
            if ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_RET):
                break
            reads, _ = ins.regs_access()
            if any(register_family(md, reg) in {"rax", "xmm0"} for reg in reads):
                raise ContainerError("Formatter variant return state is consumed by a caller")
        if not discarded:
            raise ContainerError("Formatter variant caller does not establish an ignored return value")
    patch = entry_return(image, "dependency_identical_formatter_variant", rva, "void")
    patch.evidence.update({"prototype_rva": hex(prototype), "resolved_dependencies_equal": True,
                           "original_tag_store_rva": hex(original_tag.address - image.base),
                           "variant_tag_store_rva": hex(variant_tag.address - image.base),
                           "original_tag_from_input": original_tag.operands[1].imm,
                           "variant_tag_from_input": variant_tag.operands[1].imm,
                           "caller_rvas": [hex(call) for call in callers], "saved_tag_used": False})
    return patch
