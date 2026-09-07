from collections import deque
import json
import struct

import capstone as cs
from capstone import x86_const as x

from static_container import ContainerError
from static_semantics import register_family


def tls_layout(image):
    if hasattr(image, '_static_tls_layout'):
        return image._static_tls_layout
    image._static_tls_layout = None
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
    if not directory.VirtualAddress or directory.Size < 40:
        return None
    start, end, index, _, zero_fill = struct.unpack_from('<4QI', image.read(directory.VirtualAddress, 40))
    if not 0 < end - start <= 1024 * 1024 or zero_fill > 1024 * 1024:
        return None
    try:
        template = image.read(start - image.base, end - start) + bytes(zero_fill)
    except ContainerError:
        return None

    slots = [section for section in image.sections
             if section.VirtualAddress <= index - image.base
             and index - image.base + 4 <= section.VirtualAddress + section.Misc_VirtualSize
             and section.Characteristics & 0x80000000]
    if len(slots) == 1:
        image._static_tls_layout = (index, template)
    return image._static_tls_layout


def tls_operands(image, decoded, md, switch_targets=()):

    layout = tls_layout(image)
    if not layout or not decoded:
        return [], b''
    tls_index, template = layout
    if not any(op.type == x.X86_OP_MEM and op.mem.base == x.X86_REG_RIP
               and ins.address + ins.size + op.mem.disp == tls_index
               for ins in decoded for op in ins.operands):
        return [], b''
    candidates = {ins.address: ins.operands[1].imm for ins in decoded if ins.mnemonic == 'mov'
                  and len(ins.operands) == 2 and ins.operands[0].type == x.X86_OP_REG
                  and ins.operands[0].size >= 4 and ins.operands[1].type == x.X86_OP_IMM
                  and 0 <= ins.operands[1].imm < len(template) and ins.imm_size == 4}
    if not candidates:
        return [], b''
    instructions = {ins.address: ins for ins in decoded}
    begin = decoded[0].address
    successors = {}
    for ins in decoded:
        following = ins.address + ins.size
        edges = []
        if ins.group(cs.CS_GRP_JUMP):
            if ins.operands and ins.operands[0].type == x.X86_OP_IMM:
                edges.append(ins.operands[0].imm)
            elif switch_targets:
                edges.extend(switch_targets)
            if ins.mnemonic != 'jmp':
                edges.append(following)
        elif ins.mnemonic not in ('ret', 'int3', 'ud2'):
            edges.append(following)
        successors[ins.address] = [a for a in edges if a in instructions]

    families = {}
    def family(reg):
        if reg not in families:
            families[reg] = register_family(md, reg) if reg else None
        return families[reg]

    writes = {ins.address: [family(reg) for reg in ins.regs_access()[1]] for ins in decoded}

    def transfer(ins, incoming):
        result = dict(incoming)
        for reg in writes[ins.address]:
            result.pop(reg, None)
        if ins.group(cs.CS_GRP_CALL):
            for reg in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                result.pop(reg, None)
        ops = ins.operands
        if ins.mnemonic != 'mov' or len(ops) != 2 or ops[0].type != x.X86_OP_REG:
            return result
        destination, source = ops
        tag = None
        if ins.address in candidates:
            tag = ('offset', ins.address)
        elif source.type == x.X86_OP_REG and destination.size == source.size and source.size >= 4:
            tag = incoming.get(family(source.reg))
            if tag and tag[0] in ('array', 'block') and source.size != 8:
                tag = None
        elif source.type == x.X86_OP_MEM and ins.addr_size == 8:
            mem = source.mem
            base, index = incoming.get(family(mem.base)), incoming.get(family(mem.index))
            if (source.size == 4 and mem.base == x.X86_REG_RIP and not mem.index
                    and not mem.segment and ins.address + ins.size + mem.disp == tls_index):
                tag = ('index',)
            elif (source.size == 8 and mem.segment == x.X86_REG_GS and not mem.base
                    and not mem.index and mem.disp == 0x58):
                tag = ('array',)
            elif (source.size == 8 and not mem.segment and mem.disp == 0 and mem.index
                  and base == ('array',) and index == ('index',) and mem.scale == 8):
                tag = ('block',)
        if tag is not None and destination.size >= 4:
            result[family(destination.reg)] = tag
        return result

    def accesses(ins, state):
        result = []

        if ins.mnemonic == 'lea':
            return result
        for index, operand in enumerate(ins.operands):
            if operand.type != x.X86_OP_MEM:
                continue
            mem = operand.mem
            if mem.segment or mem.disp or not mem.index or mem.scale != 1 or ins.addr_size != 8:
                continue
            base, subscript = state.get(family(mem.base)), state.get(family(mem.index))
            offset = subscript if base == ('block',) else base if subscript == ('block',) else None
            if not offset or offset[0] != 'offset':
                continue
            origin = offset[1]
            field = candidates[origin]
            if operand.size and field + operand.size <= len(template):
                result.append((origin, ins.address - begin, index, operand.size))
        return result

    def propagate(entry, initial, *, bounded=False):
        states, pending = {entry: initial}, deque([entry])
        while pending:
            address = pending.popleft()
            ins = instructions[address]
            if bounded and accesses(ins, states[address]):
                continue
            outgoing = transfer(ins, states[address])
            for target in successors[address]:
                if bounded and not entry <= target < entry + 512:
                    continue
                prior = states.get(target)
                merged = outgoing if prior is None else {reg: tag for reg, tag in prior.items()
                                                        if outgoing.get(reg) == tag}
                if prior is None or merged != prior:
                    states[target] = dict(merged)
                    pending.append(target)
        return states

    states = propagate(begin, {})
    proofs = set()
    for origin in candidates.keys() & states.keys():
        local = propagate(origin, states[origin], bounded=True)
        for address, state in local.items():
            proofs.update(row for row in accesses(instructions[address], state) if row[0] == origin)
    origins = sorted({row[0] for row in proofs})
    aliases, descriptors = {}, []
    for origin, instruction, operand, width in sorted(proofs):
        field = candidates[origin]
        alias = aliases.setdefault(field, len(aliases))
        descriptors.append([origin - begin, instruction, operand, width, alias,
                            template[field:field + width].hex()])
    spans = [(address - begin + instructions[address].imm_offset, instructions[address].imm_size)
             for address in origins]
    return spans, json.dumps(descriptors, separators=(',', ':')).encode() if spans else b''
