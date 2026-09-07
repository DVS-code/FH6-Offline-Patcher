import re
import struct

import capstone as cs
from capstone import x86_const as x

from control_flow import direct_callers
from patch_actions import suppress_call
from static_container import ContainerError
from static_semantics import function_extent, function_entry_rva, register_family


def discover_response_creators(image, terminal_response_rva):

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    workers, preparation = {}, set()
    for caller in direct_callers(image, terminal_response_rva):
        start, end = function_extent(image, caller)
        code = list(md.disasm(image.read(start, end - start), image.base + start))
        if (not code or code[-1].mnemonic != "jmp" or len(code[-1].operands) != 1
                or code[-1].operands[0].type != x.X86_OP_IMM
                or not image.base + start <= code[-1].operands[0].imm < image.base + caller
                or code[-2].address - image.base != caller
                or any(ins.group(cs.CS_GRP_RET) for ins in code)):
            continue
        if function_entry_rva(image, start) != start:
            raise ContainerError("Looping response worker is not a standalone entry")
        calls = [ins for ins in code if ins.group(cs.CS_GRP_CALL)]
        if len(calls) < 3 or any(ins.operands[0].type != x.X86_OP_IMM for ins in calls[:2]):
            raise ContainerError("Response worker lacks its native delay/preparation calls")
        preparation.add(tuple(ins.operands[0].imm - image.base for ins in calls[:2]))
        workers[start] = caller
    if not workers or len(preparation) != 1:
        raise ContainerError("A consistent set of delayed response workers was not found")
    owners = set()
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(rb"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}", data, re.DOTALL):
            offset = match.start()
            rva = section.VirtualAddress + offset
            target = rva + 7 + struct.unpack_from("<i", data, offset + 3)[0]
            if target in workers:
                owners.add(function_extent(image, rva))
    candidates = []
    for start, end in sorted(owners):
        code = list(md.disasm(image.read(start, end - start), image.base + start))
        labels = {ins.operands[0].imm for ins in code if ins.group(cs.CS_GRP_JUMP)
                  and ins.operands and ins.operands[0].type == x.X86_OP_IMM}
        aliases, pending = {}, None
        for ins in code:
            if ins.address in labels:
                aliases.clear()
                pending = None
            ops = ins.operands
            if ins.group(cs.CS_GRP_CALL):
                if pending is not None:
                    if len(ops) != 1 or ops[0].type != x.X86_OP_IMM:
                        raise ContainerError("Response callback reaches an unsupported indirect creator")
                    candidates.append((pending, ins.address - image.base, ops[0].imm - image.base, start))
                pending = None
                aliases = {reg: value for reg, value in aliases.items()
                           if reg in {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}}
                continue
            assigned = None
            if len(ops) == 2 and ops[0].type == x.X86_OP_REG and ops[0].size == 8:
                if (ins.mnemonic == "lea" and ops[1].type == x.X86_OP_MEM
                        and ops[1].mem.base == x.X86_REG_RIP and not ops[1].mem.index):
                    target = ins.address + ins.size + ops[1].mem.disp - image.base
                    if target in workers:
                        assigned = (register_family(md, ops[0].reg), target)
                elif ins.mnemonic == "mov" and ops[1].type == x.X86_OP_REG:
                    source = aliases.get(register_family(md, ops[1].reg))
                    if source is not None:
                        assigned = (register_family(md, ops[0].reg), source)
            if (ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == x.X86_OP_MEM
                    and ops[0].size == 8 and ops[0].mem.base == x.X86_REG_RSP
                    and not ops[0].mem.index and ops[0].mem.disp == 0x20):

                pending = aliases.get(register_family(md, ops[1].reg)) if ops[1].type == x.X86_OP_REG else None
            _, writes = ins.regs_access()
            for reg in writes:
                family = register_family(md, reg)
                aliases.pop(family, None)
                if family == "rsp":
                    pending = None
            if assigned:
                aliases[assigned[0]] = assigned[1]
            if ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_RET):
                aliases.clear()
                pending = None
    if (len(candidates) != len(workers) or {row[0] for row in candidates} != set(workers)
            or len({(row[2], row[3]) for row in candidates}) != 1):
        raise ContainerError("Response callbacks do not map uniquely to a shared creator and owner")
    patches = []
    for worker, call, creator, owner in sorted(candidates):
        patch = suppress_call(image, "delayed_terminal_response_creator", call, zero_result=False)
        patch.evidence.update({"worker_entry_rva": hex(worker), "terminal_response_rva": hex(terminal_response_rva),
                               "worker_terminal_call_rva": hex(workers[worker]),
                               "creator_target_rva": hex(creator), "creator_owner_rva": hex(owner),
                               "callback_argument_number": 5, "saved_event_id_used": False})
        patches.append(patch)
    return patches
