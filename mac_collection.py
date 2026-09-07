import capstone as cs
from capstone import x86_const as x

from control_flow import direct_callers
from hashed_exports import discover_export_resolver
from patch_actions import entry_return
from static_container import ContainerError
from static_semantics import function_extent, function_entry_rva, register_family


def discover_mac_collector(image):
    resolver, evidence = discover_export_resolver(image, "SendARP")
    callers = direct_callers(image, resolver)
    if len(callers) != 1:
        raise ContainerError("MAC collection lacks a unique direct SendARP caller")
    call = callers[0]
    start, end = function_extent(image, call)
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(image.read(start, end - start), image.base + start))
    by_rva = {ins.address - image.base: ins for ins in instructions}
    test = by_rva.get(call + 5)
    if (test is None or test.mnemonic != "test" or len(test.operands) != 2
            or any(op.type != x.X86_OP_REG or op.reg != x.X86_REG_EAX for op in test.operands)):
        raise ContainerError("SendARP result is not checked as a native status code")
    branch = by_rva.get(call + 5 + test.size)
    if (branch is None or branch.mnemonic not in ("jne", "jnz")
            or branch.operands[0].type != x.X86_OP_IMM):
        raise ContainerError("SendARP failure has no supported direct continuation")
    target = branch.operands[0].imm - image.base
    failure = by_rva.get(target)
    if (target <= call or failure is None or failure.mnemonic != "mov" or len(failure.operands) != 2
            or failure.operands[0].type != x.X86_OP_REG or failure.operands[0].reg != x.X86_REG_EAX
            or failure.operands[1].type != x.X86_OP_REG or failure.operands[1].size != 4):
        raise ContainerError("SendARP failure does not return the initialized boolean")
    source = register_family(md, failure.operands[1].reg)
    if source not in {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}:
        raise ContainerError("Failure value is not kept in a nonvolatile register")
    last_writer = None
    for ins in instructions:
        if ins.address - image.base >= call:
            break
        _, writes = ins.regs_access()
        if any(register_family(md, reg) == source for reg in writes):
            last_writer = ins
    if (last_writer is None or last_writer.mnemonic != "xor" or len(last_writer.operands) != 2
            or any(op.type != x.X86_OP_REG or register_family(md, op.reg) != source
                   for op in last_writer.operands) or last_writer.operands[0].size < 4):
        raise ContainerError("MAC-collection failure result is not independently initialized to false")
    entry = function_entry_rva(image, call)
    patch = entry_return(image, "mac_collection_returns_native_failure", entry, "zero")
    patch.evidence.update(evidence)
    patch.evidence.update({"resolver_rva": hex(resolver), "resolver_call_rva": hex(call),
                           "native_failure_rva": hex(target),
                           "failure_value_initializer_rva": hex(last_writer.address - image.base)})
    return patch
