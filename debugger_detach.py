import struct

import capstone as cs
from capstone import x86_const as x

from control_flow import direct_callers
from patch_actions import Patch
from static_container import ContainerError
from static_semantics import function_extent, function_entry_rva, register_family

MASK64 = (1 << 64) - 1


def decoded_function(image, rva):
    begin, end = function_extent(image, rva)
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    code = list(md.disasm(image.read(begin, end - begin), image.base + begin))
    if not code or code[-1].address + code[-1].size != image.base + end:
        raise ContainerError("Detach transaction does not decode completely")
    return md, code


def call_states(image, md, code, query_target):

    registers, memory, calls = {"rsp": ("stack", 0)}, {}, {}

    def family(op):
        return register_family(md, op.reg)

    def add(value, displacement, width=8):
        if isinstance(value, int):
            return (value + displacement) & ((1 << (width * 8)) - 1)
        if isinstance(value, tuple) and value[0] == "stack" and width == 8:
            return ("stack", value[1] + displacement)
        return None

    def address(op):
        if op.mem.index or op.mem.segment:
            return None
        return add(registers.get(register_family(md, op.mem.base)), op.mem.disp)

    def value(op):
        if op.type == x.X86_OP_REG:
            return registers.get(family(op))
        if op.type == x.X86_OP_IMM:
            return op.imm & ((1 << (op.size * 8)) - 1)
        if op.type == x.X86_OP_MEM:
            return memory.get((address(op), op.size))
        return None

    def store(address, width, result):

        if not isinstance(address, tuple) or address[0] != "stack":
            memory.clear()
            return
        for key in list(memory):
            previous, size = key
            if previous[1] < address[1] + width and address[1] < previous[1] + size:
                del memory[key]
        if result is not None:
            memory[address, width] = result

    for ins in code:
        ops = ins.operands
        if ins.group(cs.CS_GRP_CALL):
            if len(ops) != 1 or ops[0].type != x.X86_OP_IMM:
                raise ContainerError("Detach transaction contains an unresolved call")
            target = ops[0].imm - image.base
            calls[ins.address - image.base] = (target, registers.copy(), memory.copy())
            if target == query_target:
                output = registers.get("r8")
                if isinstance(output, tuple) and output[0] == "stack":
                    store(output, 8, ("debug_handle", output))
            for name in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                registers.pop(name, None)
            continue
        if ins.mnemonic == "push":
            pushed = value(ops[0])
            registers["rsp"] = add(registers.get("rsp"), -8)
            store(registers.get("rsp"), 8, pushed)
            continue
        if ins.mnemonic == "pop":
            if ops and ops[0].type == x.X86_OP_REG:
                registers.pop(family(ops[0]), None)
            registers["rsp"] = add(registers.get("rsp"), 8)
            continue
        result = None
        if len(ops) == 2:
            if ins.mnemonic == "mov":
                result = value(ops[1])
            elif ins.mnemonic == "lea" and ops[1].type == x.X86_OP_MEM:
                result = add(registers.get(register_family(md, ops[1].mem.base)), ops[1].mem.disp, ops[0].size) if not ops[1].mem.index else None
            elif ins.mnemonic == "xor" and ops[0].type == ops[1].type == x.X86_OP_REG and ops[0].reg == ops[1].reg:
                result = 0
            elif ins.mnemonic == "or" and ops[1].type == x.X86_OP_IMM and ops[1].imm == -1:
                result = (1 << (ops[0].size * 8)) - 1
            elif ins.mnemonic in ("add", "sub") and ops[1].type == x.X86_OP_IMM:
                result = add(value(ops[0]), ops[1].imm * (-1 if ins.mnemonic == "sub" else 1), ops[0].size)
        _, written = ins.regs_access()
        for register in written:
            registers.pop(register_family(md, register), None)
        if len(ops) == 2 and ins.mnemonic in ("mov", "lea", "xor", "or", "add", "sub"):
            if ops[0].type == x.X86_OP_REG:
                if ops[0].size >= 4 and result is not None:
                    registers[family(ops[0])] = result
        for op in ops:
            if op.type == x.X86_OP_MEM and op.access & cs.CS_AC_WRITE:
                store(address(op), op.size, result if op is ops[0] else None)
    return calls


def prove_arguments(image, md, code, targets, sites):
    states = call_states(image, md, code, targets[0])
    query, setting, removal, closing = [states[site] for site in sites]
    if [item[0] for item in (query, setting, removal, closing)] != list(targets):
        raise ContainerError("Detach transaction calls differ from the validated native operations")
    q = query[1]
    output = q.get("r8")
    if (q.get("rcx") != MASK64 or q.get("rdx") != 30 or q.get("r9") != 8
            or not isinstance(output, tuple) or output[0] != "stack"
            or query[2].get((output, 8)) != MASK64):
        raise ContainerError("ProcessDebugObjectHandle query arguments or initial output are unproved")
    handle = ("debug_handle", output)
    s = setting[1]
    if (s.get("rcx") != handle or s.get("rdx") != 1 or s.get("r9") != 4
            or setting[2].get((s.get("r8"), 4)) != 0):
        raise ContainerError("Debug-object flag arguments do not follow the queried handle")
    if removal[1].get("rcx") != MASK64 or removal[1].get("rdx") != handle or closing[1].get("rcx") != handle:
        raise ContainerError("Detach/close arguments do not follow the queried process and handle")


def discover_additional_detach_queries(image, known_patch):

    wait = int(known_patch.evidence["branch_target_rva"], 16)
    md, known_code = decoded_function(image, known_patch.rva)
    operations = [ins for ins in known_code if known_patch.rva <= ins.address - image.base < wait
                  and ins.group(cs.CS_GRP_CALL)]
    if len(operations) != 4 or any(ins.operands[0].type != x.X86_OP_IMM for ins in operations):
        raise ContainerError("Known detach transaction lacks four resolved native operations")
    targets = tuple(ins.operands[0].imm - image.base for ins in operations)
    if len(set(targets)) != 4:
        raise ContainerError("Known detach operations alias unexpectedly")
    prove_arguments(image, md, known_code, targets, [ins.address - image.base for ins in operations])
    known_begin = function_extent(image, known_patch.rva)[0]
    callers = direct_callers(image, targets[2])
    owners = sorted({function_extent(image, call)[0] for call in callers} - {known_begin})
    patches = []
    for begin in owners:
        md, code = decoded_function(image, begin)
        selected = [ins for ins in code if ins.group(cs.CS_GRP_CALL) and ins.operands[0].type == x.X86_OP_IMM
                    and ins.operands[0].imm - image.base in targets]
        if len(selected) != 4:
            raise ContainerError("Additional detach caller has an unsupported operation sequence")
        sites = [ins.address - image.base for ins in selected]
        prove_arguments(image, md, code, targets, sites)
        query = selected[0]
        index = code.index(query)
        if any(ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) for ins in code[:index]):
            raise ContainerError("Additional debug query has conditional or call-dependent initialization")
        failure_targets = []
        status_branches = []
        for operation in selected:
            following = code[code.index(operation) + 1:code.index(operation) + 3]
            if len(following) != 2:
                raise ContainerError("Detach operation lacks a native error continuation")
            test, branch = following
            if (test.mnemonic != "test" or len(test.operands) != 2
                    or any(op.type != x.X86_OP_REG or op.reg != x.X86_REG_EAX for op in test.operands)
                    or branch.mnemonic != "js" or branch.operands[0].type != x.X86_OP_IMM):
                raise ContainerError("Detach operation does not use a signed status failure edge")
            failure_targets.append(branch.operands[0].imm - image.base)
            status_branches.append(branch.address)
        transaction = code[index:code.index(selected[-1]) + 3]
        if any((ins.group(cs.CS_GRP_CALL) and ins not in selected)
               or (ins.group(cs.CS_GRP_JUMP) and ins.address not in status_branches)
               for ins in transaction):
            raise ContainerError("Detach transaction has an unproved call or control-flow edge")
        if len(set(failure_targets)) != 1:
            raise ContainerError("Detach failures do not share one native cleanup path")
        failure = failure_targets[0]
        instruction = next((ins for ins in code if ins.address - image.base == failure), None)
        if (instruction is None or instruction.mnemonic != "xor" or len(instruction.operands) != 2
                or any(op.type != x.X86_OP_REG or op.reg != x.X86_REG_AL for op in instruction.operands)
                or function_entry_rva(image, failure) != function_entry_rva(image, begin)):
            raise ContainerError("Detach failure does not enter the native false-result cleanup")
        if query.size != 5:
            raise ContainerError("Unsupported direct query-call encoding")
        patches.append(Patch("cancel_additional_debugger_detach_query", sites[0], bytes(query.bytes),
                             b"\xb8" + struct.pack("<I", 0xC0000022),
                             {"action": "return_ntstatus_failure_from_call", "ntstatus": "0xc0000022",
                              "native_failure_rva": hex(failure), "function_rva": hex(begin),
                              "native_operation_targets_from_input": [hex(target) for target in targets],
                              "query_output_initialized": True, "native_frame_and_cleanup_preserved": True,
                              "saved_game_address_used": False}))
    return patches
