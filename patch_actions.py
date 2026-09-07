from __future__ import annotations

from dataclasses import dataclass
import struct
import re

import capstone as cs
from capstone import x86_const as x

from static_container import ContainerError
from static_image import Image
from static_semantics import function_extent, function_entry_rva, register_family


@dataclass(frozen=True)
class Patch:
    role: str
    rva: int
    before: bytes
    after: bytes
    evidence: dict


def decode_at(image: Image, rva: int):
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    for size in range(15, 0, -1):
        try:
            data = image.read(rva, size)
        except ContainerError:
            continue
        instruction = next(md.disasm(data, image.base + rva, count=1), None)
        if instruction is not None:
            return instruction
    raise ContainerError("Patch target does not decode")


def force_branch(image: Image, role: str, rva: int) -> Patch:
    ins = decode_at(image, rva)
    if (not ins.group(cs.CS_GRP_JUMP) or ins.mnemonic == "jmp"
            or len(ins.operands) != 1 or ins.operands[0].type != x.X86_OP_IMM):
        raise ContainerError("Expected a direct conditional branch")
    target = ins.operands[0].imm - image.base
    image.offset(target, 1, executable=True)
    if ins.size == 2 and 0x70 <= ins.bytes[0] <= 0x7F:
        replacement = b"\xeb" + struct.pack("b", target - (rva + 2))
    elif ins.size == 6 and ins.bytes[0] == 0x0F and 0x80 <= ins.bytes[1] <= 0x8F:
        displacement = target - (rva + 5)
        if not -(1 << 31) <= displacement < 1 << 31:
            raise ContainerError("Unconditional branch destination is out of range")
        replacement = b"\xe9" + struct.pack("<i", displacement) + b"\x90"
    else:
        raise ContainerError("Unsupported conditional-branch encoding")
    return Patch(role, rva, bytes(ins.bytes), replacement,
                 {"action": "force_branch", "original_mnemonic": ins.mnemonic,
                  "branch_target_rva": hex(target), "destination_preserved": True})


def suppress_call(image: Image, role: str, rva: int, *, zero_result: bool) -> Patch:
    ins = decode_at(image, rva)
    if not ins.group(cs.CS_GRP_CALL) or ins.size not in (5, 6):
        raise ContainerError("Expected a complete five/six-byte call instruction")
    replacement = b"\x31\xc0" if zero_result else b""
    replacement += b"\x90" * (ins.size - len(replacement))
    return Patch(role, rva, bytes(ins.bytes), replacement,
                 {"action": "suppress_call", "zero_result": zero_result,
                  "instruction_size": ins.size})


def fail_hresult_call(image: Image, role: str, rva: int, error: int = 0x80004004) -> Patch:

    instruction = decode_at(image, rva)
    if not instruction.group(cs.CS_GRP_CALL) or instruction.size not in (5, 6):
        raise ContainerError("HRESULT substitution requires a complete five/six-byte call")
    if not 0x80000000 <= error <= 0xFFFFFFFF:
        raise ContainerError("HRESULT error substitution requires a failure value")
    code = b"\xb8" + struct.pack("<I", error) + b"\x90" * (instruction.size - 5)
    return Patch(role, rva, bytes(instruction.bytes), code,
                 {"action": "return_hresult_failure_from_call", "hresult": hex(error),
                  "native_stack_and_cleanup_preserved": True})


def stall_entry(image: Image, role: str, rva: int) -> Patch:

    start, end = function_extent(image, rva)
    if start != rva or function_entry_rva(image, rva) != rva or end - start < 2:
        raise ContainerError("Nonreturning action requires a declared function entry")
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    for ins in md.disasm(image.read(start, end - start), image.base + start):
        if (ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)) and ins.operands:
            if ins.operands[0].type == x.X86_OP_IMM and ins.operands[0].imm == image.base + rva + 1:
                raise ContainerError("A control-flow edge enters the overwritten entry")
    return Patch(role, rva, image.read(rva, 2), b"\xeb\xfe", {
        "action": "nonreturning_entry_loop", "loop_target_rva": hex(rva),
        "stack_frame_entered": False, "role_authorization_required": True,
    })


def thread_hide_leaf_return(image: Image, role: str, rva: int) -> Patch:

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    constants = {}
    cursor, target = rva, None
    volatile_arguments = {"rcx", "rdx", "r8", "r9"}
    for _ in range(16):
        ins = decode_at(image, cursor)
        ops = ins.operands
        if ins.mnemonic == "jmp" and len(ops) == 1 and ops[0].type == x.X86_OP_IMM:
            target = ops[0].imm - image.base
            image.offset(target, 1, executable=True)
            break
        if not ops or ops[0].type != x.X86_OP_REG or ops[0].size not in (4, 8):
            raise ContainerError("Thread-hide leaf has side effects or unsupported argument setup")
        destination = register_family(md, ops[0].reg)
        if destination not in volatile_arguments:
            raise ContainerError("Thread-hide leaf modifies state beyond volatile arguments")
        value = None
        if (ins.mnemonic == "xor" and len(ops) == 2 and ops[1].type == x.X86_OP_REG
                and ops[0].reg == ops[1].reg):
            value = 0
        elif ins.mnemonic == "mov" and len(ops) == 2:
            if ops[1].type == x.X86_OP_IMM:
                value = ops[1].imm
            elif ops[1].type == x.X86_OP_REG:
                value = constants.get(register_family(md, ops[1].reg))
        elif ins.mnemonic == "lea" and len(ops) == 2 and ops[1].type == x.X86_OP_MEM:
            memory = ops[1].mem
            base = constants.get(register_family(md, memory.base))
            if base is not None and not memory.index and not memory.segment:
                value = base + memory.disp
        if value is None:
            raise ContainerError("Thread-hide leaf argument is not statically determined")
        constants[destination] = value & ((1 << (ops[0].size * 8)) - 1)
        cursor += ins.size
    expected = {"rcx": (1 << 64) - 2, "rdx": 17, "r8": 0, "r9": 0}
    if target is None or constants != expected:
        raise ContainerError("Leaf does not prepare the reviewed ThreadHideFromDebugger argument contract")
    callers = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(b"[\xe8\xe9]", data):
            offset = match.start()
            if offset + 5 > len(data):
                continue
            site = section.VirtualAddress + offset
            if site + 5 + struct.unpack_from("<i", data, offset + 1)[0] != rva:
                continue
            try:
                start, end = function_extent(image, site)
            except ContainerError:
                raise ContainerError("Unclassified direct reference to the thread-hide leaf")
            decoded = list(md.disasm(image.read(start, end - start), image.base + start))
            by_rva = {ins.address - image.base: ins for ins in decoded}
            if site not in by_rva:
                continue
            call, following = by_rva[site], by_rva.get(site + 5)
            if call.mnemonic != "call" or following is None or following.mnemonic != "rdtsc":
                raise ContainerError("Thread-hide leaf return value is not proved discarded by its caller")
            callers.append(site)
    if not callers:
        raise ContainerError("No validated direct caller proves the leaf entry/return contract")
    return Patch(role, rva, image.read(rva, 1), b"\xc3", {
        "action": "return_from_argument_only_leaf", "tail_target_rva": hex(target),
        "argument_values": {key: hex(value) for key, value in constants.items()},
        "direct_caller_rvas": [hex(site) for site in callers],
        "return_value_overwritten_by_rdtsc": True, "role_authorization_required": True,
    })


def jump_to_existing_branch_destination(image: Image, role: str, rva: int,
                                        selected_branch_rva: int) -> Patch:

    extent = function_extent(image, rva)
    if function_extent(image, selected_branch_rva) != extent:
        raise ContainerError("Selected continuation belongs to a different function")
    branch = decode_at(image, selected_branch_rva)
    if (not branch.group(cs.CS_GRP_JUMP) or len(branch.operands) != 1
            or branch.operands[0].type != x.X86_OP_IMM):
        raise ContainerError("Continuation evidence must be a direct input branch")
    target = branch.operands[0].imm - image.base
    if not (rva < target < extent[1]):
        raise ContainerError("Skip must reach a later instruction in the same function")
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    decoded = list(md.disasm(image.read(extent[0], extent[1] - extent[0]), image.base + extent[0]))
    by_rva = {ins.address - image.base: ins for ins in decoded}
    if any(address not in by_rva for address in (rva, target, selected_branch_rva)):
        raise ContainerError("Skip evidence is not on decoded instruction boundaries")
    displacement = target - (rva + 2)
    if -128 <= displacement <= 127:
        replacement = b"\xeb" + struct.pack("b", displacement)
    else:
        displacement = target - (rva + 5)
        if not -(1 << 31) <= displacement < 1 << 31:
            raise ContainerError("Skip target is outside relative-branch reach")
        replacement = b"\xe9" + struct.pack("<i", displacement)


    finish = rva + len(replacement)
    for ins in decoded:
        if (ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)) and ins.operands:
            operand = ins.operands[0]
            if operand.type == x.X86_OP_IMM and rva < operand.imm - image.base < finish:
                raise ContainerError("Another control-flow edge enters the overwritten bytes")
    return Patch(role, rva, image.read(rva, len(replacement)), replacement,
                 {"action": "skip_to_existing_edge", "branch_evidence_rva": hex(selected_branch_rva),
                  "branch_target_rva": hex(target)})


def entry_return(image: Image, role: str, rva: int, value: str) -> Patch:
    start, _ = function_extent(image, rva)
    if start != rva or function_entry_rva(image, rva) != rva:
        raise ContainerError("Returning before a native epilogue requires a proved entry point")
    encodings = {"void": b"\xc3", "zero": b"\x31\xc0\xc3",
                 "true_bool": b"\xb0\x01\xc3", "first_argument": b"\x48\x8b\xc1\xc3"}
    if value not in encodings:
        raise ContainerError("Unknown return semantics")
    code = encodings[value]
    return Patch(role, rva, image.read(rva, len(code)), code,
                  {"action": "entry_return", "value": value, "declared_function_entry": True})


def initialized_object_return(image: Image, role: str, rva: int) -> Patch:

    start, end = function_extent(image, rva)
    if start != rva or function_entry_rva(image, rva) != rva:
        raise ContainerError("Object-return action requires a function entry")
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    aliases, values, initialized = {"rcx"}, {}, {}
    first_transfer = None
    evidence_stores = []
    for ins in md.disasm(image.read(start, end - start), image.base + start):
        if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_RET):
            first_transfer = ins.address - image.base
            break
        ops = ins.operands
        copy, known = None, None
        if (len(ops) == 2 and ops[0].type == x.X86_OP_REG
                and ins.mnemonic in ("xor", "xorps", "xorpd", "pxor")
                and ops[1].type == x.X86_OP_REG and ops[0].reg == ops[1].reg):
            if ops[0].size >= 4:
                known = (register_family(md, ops[0].reg), 0)
        if ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == x.X86_OP_REG:
            dst = register_family(md, ops[0].reg)
            if ops[1].type == x.X86_OP_REG:
                src = register_family(md, ops[1].reg)
                if ops[0].size == 8 and src in aliases:
                    copy = dst
                if ops[0].size >= 4 and src in values:
                    known = (dst, values[src] & ((1 << (ops[0].size * 8)) - 1))
            elif ops[1].type == x.X86_OP_IMM and ops[0].size >= 4:
                known = (dst, ops[1].imm & ((1 << (ops[0].size * 8)) - 1))
        store_mnemonics = ("mov", "movups", "movaps", "movdqu", "movdqa")


        if (len(ops) == 2 and ops[0].type == x.X86_OP_MEM
                and (ops[0].access & cs.CS_AC_WRITE or ins.mnemonic in store_mnemonics)):
            memory = ops[0].mem
            if register_family(md, memory.base) in aliases:
                if (ins.mnemonic not in store_mnemonics
                        or memory.index or memory.segment or memory.disp < 0
                        or memory.disp + ops[0].size > 256):
                    raise ContainerError("Unsupported return-object initialization store")
                value = ops[1].imm if ops[1].type == x.X86_OP_IMM else (
                    values.get(register_family(md, ops[1].reg)) if ops[1].type == x.X86_OP_REG else None)
                if value is None:
                    raise ContainerError("Return-object initialization depends on an unknown value")
                data = (value & ((1 << (ops[0].size * 8)) - 1)).to_bytes(ops[0].size, "little")
                initialized.update((memory.disp + index, byte) for index, byte in enumerate(data))
                evidence_stores.append(ins.address - image.base)
        _, writes = ins.regs_access()
        for reg in writes:
            name = register_family(md, reg)
            aliases.discard(name)
            values.pop(name, None)
        if copy:
            aliases.add(copy)
        if known:
            values[known[0]] = known[1]
    if first_transfer is None or not initialized or not evidence_stores:
        raise ContainerError("No bounded unconditional return-object initialization")
    replacement = bytearray()
    pending = dict(initialized)
    while pending:
        offset = min(pending)
        chosen = None
        for width, prefix in ((8, b"\x48\xc7\x81"), (4, b"\xc7\x81"),
                              (2, b"\x66\xc7\x81"), (1, b"\xc6\x81")):
            if not all(offset + i in pending for i in range(width)):
                continue
            data = bytes(pending[offset + i] for i in range(width))
            if width == 8 and int.from_bytes(data, "little", signed=True) != int.from_bytes(data[:4], "little", signed=True):
                continue
            chosen = (width, prefix, data[:4] if width == 8 else data)
            break
        width, prefix, immediate = chosen
        replacement += prefix + struct.pack("<i", offset) + immediate
        for index in range(width):
            del pending[offset + index]
    replacement += b"\x48\x8b\xc1\xc3"
    if rva + len(replacement) > first_transfer:
        raise ContainerError("Initialization stub would exceed the original unconditional prefix")

    for ins in md.disasm(image.read(start, end - start), image.base + start):
        if (ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_CALL)) and ins.operands:
            op = ins.operands[0]
            if op.type == x.X86_OP_IMM and rva < op.imm - image.base < rva + len(replacement):
                raise ContainerError("A control-flow edge enters the object-initialization replacement")
    return Patch(role, rva, image.read(rva, len(replacement)), bytes(replacement), {
        "action": "initialize_and_return_incoming_object",
        "initialization_store_rvas": [hex(address) for address in evidence_stores],
        "initialized_bytes_from_input": {hex(offset): value for offset, value in sorted(initialized.items())},
        "fixed_object_layout_used": False,
    })


def skip_reserved_identity_strike(image: Image, role: str, rva: int) -> Patch:
    first = decode_at(image, rva)
    compare_rva = rva + first.size
    compare = decode_at(image, compare_rva)
    second_rva = compare_rva + compare.size
    second = decode_at(image, second_rva)
    if (first.mnemonic not in ("je", "jz") or first.operands[0].type != x.X86_OP_IMM
            or first.operands[0].imm - image.base >= rva
            or compare.mnemonic != "cmp" or len(compare.operands) != 2
            or compare.operands[0].type != x.X86_OP_REG
            or compare.operands[0].reg != x.X86_REG_EAX
            or compare.operands[1].type != x.X86_OP_IMM
            or second.mnemonic not in ("jne", "jnz")):
        raise ContainerError("Reserved-identity decision does not have the reviewed control-flow shape")
    patch = jump_to_existing_branch_destination(image, role, rva, second_rva)
    patch.evidence["decision"] = "advance_using_the_existing_no_strike_edge"
    return patch


def skip_debugger_detach_transaction(image: Image, role: str, rva: int) -> Patch:
    start, end = function_extent(image, rva)
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(image.read(start, end - start), image.base + start))
    wait_entries = []
    for index in range(len(insns) - 3):
        load, zero, call, compare = insns[index:index + 4]
        if load.address - image.base <= rva:
            continue
        if (load.mnemonic != "mov" or len(load.operands) != 2
                or load.operands[0].type != x.X86_OP_REG or load.operands[0].reg != x.X86_REG_RCX
                or load.operands[1].type != x.X86_OP_MEM or load.operands[1].mem.base != x.X86_REG_RIP):
            continue
        if (zero.mnemonic != "xor" or len(zero.operands) != 2
                or any(o.type != x.X86_OP_REG or o.reg != x.X86_REG_EDX for o in zero.operands)
                or not call.group(cs.CS_GRP_CALL)):
            continue
        if (compare.mnemonic == "cmp" and len(compare.operands) == 2
                and compare.operands[0].type == x.X86_OP_REG and compare.operands[0].reg == x.X86_REG_EAX
                and compare.operands[1].type == x.X86_OP_IMM and compare.operands[1].imm == 0x102):
            wait_entries.append(load.address)
    if len(wait_entries) != 1:
        raise ContainerError("A unique native WAIT_TIMEOUT continuation was not found")
    target = wait_entries[0]
    branches = [i for i in insns if rva < i.address - image.base < target - image.base
                and i.group(cs.CS_GRP_JUMP) and i.operands[0].type == x.X86_OP_IMM
                and i.operands[0].imm == target]
    if len(branches) != 1:
        raise ContainerError("The native wait lacks a unique transaction-exit edge")
    patch = jump_to_existing_branch_destination(image, role, rva, branches[0].address - image.base)
    patch.evidence["decision"] = "preserve_the_native_wait_and_its_boolean_result"
    return patch


def clear_mutex_result_slots(image: Image, role: str, rva: int) -> Patch:

    start, end = function_extent(image, rva)
    if start != rva or function_entry_rva(image, rva) != rva:
        raise ContainerError("Expected the initializer's function entry")
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    code = list(md.disasm(image.read(start, end - start), image.base + start))
    aliases = {"rcx"}
    nonvolatile = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
    result_callee = None
    stores = []
    for ins in code:
        if ins.group(cs.CS_GRP_JUMP):
            break
        ops = ins.operands
        if ins.group(cs.CS_GRP_CALL):
            result_callee = ops[0].imm if ops[0].type == x.X86_OP_IMM else None
            aliases.intersection_update(nonvolatile)
            continue
        if (ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == x.X86_OP_MEM
                and ops[0].size == 8 and ops[1].type == x.X86_OP_REG
                and ops[1].reg == x.X86_REG_RAX and result_callee is not None):
            memory = ops[0].mem
            if register_family(md, memory.base) in aliases and not memory.index:
                stores.append((memory.disp, result_callee, ins.address - image.base))
                result_callee = None
        copy = None
        if (ins.mnemonic == "mov" and len(ops) == 2
                and ops[0].type == ops[1].type == x.X86_OP_REG and ops[0].size == 8):
            if register_family(md, ops[1].reg) in aliases:
                copy = register_family(md, ops[0].reg)
        _, writes = ins.regs_access()
        for reg in writes:
            name = register_family(md, reg)
            aliases.discard(name)
            if name == "rax":
                result_callee = None
        if copy:
            aliases.add(copy)
    offsets = [offset for offset, _, _ in stores]
    if len(stores) != 2 or len(set(offsets)) != 2 or len({callee for _, callee, _ in stores}) != 1:
        raise ContainerError("Mutex output slots could not be determined uniquely")
    if any(offset < 0 or offset > 0x7FFFFFFF or offset % 8 for offset in offsets):
        raise ContainerError("Unsupported mutex object-slot displacement")
    replacement = b"".join(b"\x48\xc7\x81" + struct.pack("<iI", offset, 0) for offset in offsets) + b"\xc3"
    return Patch(role, rva, image.read(rva, len(replacement)), replacement,
                 {"action": "clear_mutex_result_slots", "object_offsets_from_input": offsets,
                  "store_rvas": [hex(store) for _, _, store in stores]})


def apply_plan(image: Image, patches: list[Patch]) -> bytes:
    if not patches:
        raise ContainerError("An empty patch plan is not a patched game")
    result = bytearray(image.data)
    end = -1
    for patch in sorted(patches, key=lambda p: p.rva):
        if not patch.before or len(patch.before) != len(patch.after):
            raise ContainerError("Patch extents must be nonempty and equal")
        if patch.rva < end:
            raise ContainerError("Patch plan contains overlapping writes")
        end = patch.rva + len(patch.before)
        offset = image.offset(patch.rva, len(patch.before), executable=True)
        if image.data[offset:offset + len(patch.before)] != patch.before:
            raise ContainerError("A planned preimage changed")
        result[offset:offset + len(patch.after)] = patch.after
    return bytes(result)
