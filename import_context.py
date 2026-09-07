from __future__ import annotations

from dataclasses import dataclass
import re
import struct

import capstone as cs
from capstone import x86_const as x

from patch_actions import initialized_object_return, suppress_call, fail_hresult_call
from static_container import ContainerError
from static_image import Image
from static_semantics import function_extent, function_entry_rva, register_family


@dataclass(frozen=True)
class ImportedCall:
    rva: int
    iat_rva: int
    library: str
    name: str
    thunk_rva: int | None = None


def import_slots(image: Image) -> dict[int, tuple[str, str]]:
    cached = getattr(image, "_import_slots", None)
    if cached is not None:
        return cached.copy()


    if not hasattr(image.pe, "DIRECTORY_ENTRY_IMPORT"):
        image.pe.parse_data_directories(directories=[1])
    slots = {}
    for descriptor in getattr(image.pe, "DIRECTORY_ENTRY_IMPORT", ()):
        try:
            library = descriptor.dll.decode("ascii")
            for symbol in descriptor.imports:
                if symbol.name is None:
                    continue
                rva = symbol.address - image.base
                image.offset(rva, 8)
                identity = (library, symbol.name.decode("ascii"))
                if rva in slots and slots[rva] != identity:
                    raise ContainerError("Conflicting import identities for one IAT slot")
                slots[rva] = identity
        except UnicodeDecodeError as error:
            raise ContainerError("Malformed import name") from error
    if not slots:
        raise ContainerError("No named imports available for semantic discovery")
    image._import_slots = slots
    return slots.copy()


def import_thunks(image, slots):

    thunks = {}
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(b"\xff\x25", data):
            offset = match.start()
            if offset + 6 > len(data):
                continue
            rva = section.VirtualAddress + offset
            slot = rva + 6 + struct.unpack_from("<i", data, offset + 2)[0]
            if slot in slots:
                image.offset(rva, 6, executable=True)
                thunks[rva] = slot
    return thunks


def decoded_import_call(image, ins, slots, thunks=None):
    if ins.mnemonic != "call" or len(ins.operands) != 1:
        return None
    operand = ins.operands[0]
    if operand.type == x.X86_OP_IMM and thunks is not None:
        thunk = operand.imm - image.base
        if thunk in thunks:
            slot = thunks[thunk]
            library, name = slots[slot]
            return ImportedCall(ins.address - image.base, slot, library, name, thunk)
        return None
    if (operand.type != x.X86_OP_MEM or operand.mem.base != x.X86_REG_RIP
            or operand.mem.index or operand.mem.segment):
        return None
    rva = ins.address - image.base
    slot = rva + ins.size + operand.mem.disp
    if slot not in slots:
        return None
    library, name = slots[slot]
    return ImportedCall(rva, slot, library, name)


def discover_context_call(image: Image, api: str, required_context: set[str]) -> tuple[ImportedCall, dict]:

    slots = import_slots(image)
    thunks = import_thunks(image, slots)
    wanted = {slot for slot, (_, name) in slots.items() if name == api}
    wanted_thunks = {thunk for thunk, slot in thunks.items() if slot in wanted}
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    functions = set()
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(b"\xff\x15", data):
            offset = match.start()
            if offset + 6 > len(data):
                continue
            rva = section.VirtualAddress + offset
            slot = rva + 6 + struct.unpack_from("<i", data, offset + 2)[0]
            if slot not in wanted:
                continue
            try:
                functions.add(function_extent(image, rva))
            except ContainerError:
                continue
        if wanted_thunks:
            for match in re.finditer(b"\xe8", data):
                offset = match.start()
                if offset + 5 > len(data):
                    continue
                rva = section.VirtualAddress + offset
                target = rva + 5 + struct.unpack_from("<i", data, offset + 1)[0]
                if target not in wanted_thunks:
                    continue
                try:
                    functions.add(function_extent(image, rva))
                except ContainerError:
                    continue
    candidates = []
    for start, end in sorted(functions):
        decoded = list(md.disasm(image.read(start, end - start), image.base + start))
        if not decoded or decoded[-1].address + decoded[-1].size != image.base + end:
            continue
        calls = [call for ins in decoded if (call := decoded_import_call(image, ins, slots, thunks))]
        names = {call.name for call in calls}
        if required_context <= names:
            for call in calls:
                if call.name == api:
                    candidates.append((call, {
                        "function_start_rva": hex(start), "function_end_rva": hex(end),
                        "imported_api": api, "import_library": call.library,
                        "import_slot_rva": hex(call.iat_rva),
                        "import_thunk_rva": hex(call.thunk_rva) if call.thunk_rva is not None else None,
                        "required_context_calls": sorted(required_context),
                        "observed_context_calls": sorted(names),
                        "saved_instruction_profile_used": False,
                    }))
    if len(candidates) != 1:
        raise ContainerError(f"Expected one {api} call in the required API context; found {len(candidates)}")
    return candidates[0]


def discover_fatal_handler_debugger_call(image: Image):
    call, evidence = discover_context_call(image, "IsDebuggerPresent", {
        "IsProcessorFeaturePresent", "RtlCaptureContext", "RtlLookupFunctionEntry",
        "RtlVirtualUnwind", "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
    })
    patch = suppress_call(image, "fatal_handler_debugger_check", call.rva, zero_result=True)
    patch.evidence.update(evidence)
    return patch


def discover_computer_name_result(image: Image):
    call, evidence = discover_context_call(image, "GetComputerNameA", set())
    start, _ = function_extent(image, call.rva)
    patch = initialized_object_return(image, "empty_computer_name_result", start)
    patch.evidence.update(evidence)
    return patch


def discover_webcall_cancellation(image: Image):
    call, evidence = discover_context_call(image, "HCHttpCallCreate", {
        "HCHttpCallRequestGetUrl", "HCHttpCallRequestSetUrl", "HCHttpCallDuplicateHandle",
        "HCHttpCallRequestGetRequestBodyBytes", "HCHttpCallRequestSetRequestBodyBytes",
    })
    start, end = function_extent(image, call.rva)
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    code = list(md.disasm(image.read(start, end - start), image.base + start))
    index = next(i for i, ins in enumerate(code) if ins.address - image.base == call.rva)
    zero, stores, argument = set(), {}, None

    def local(memory):
        if memory.base not in (x.X86_REG_RSP, x.X86_REG_RBP) or memory.index or memory.segment:
            return None
        return memory.base, memory.disp

    for ins in code[:index]:
        if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) or ins.group(cs.CS_GRP_RET):
            raise ContainerError("HTTP handle initialization is not an unconditional local prefix")
        ops = ins.operands
        next_zero, next_argument = None, None
        if (ins.mnemonic == "xor" and len(ops) == 2 and ops[0].type == ops[1].type == x.X86_OP_REG
                and ops[0].reg == ops[1].reg and ops[0].size >= 4):
            next_zero = register_family(md, ops[0].reg)
        if ins.mnemonic == "lea" and len(ops) == 2 and ops[0].type == x.X86_OP_REG and ops[0].reg == x.X86_REG_RCX:
            if ops[1].type == x.X86_OP_MEM:
                next_argument = local(ops[1].mem)
        if (len(ops) == 2 and ops[0].type == x.X86_OP_MEM
                and (ops[0].access & cs.CS_AC_WRITE or ins.mnemonic in ("mov", "movups", "movaps", "movdqu", "movdqa"))):
            slot = local(ops[0].mem)
            if slot is not None:
                is_zero = (ins.mnemonic == "mov" and (
                    (ops[1].type == x.X86_OP_REG and register_family(md, ops[1].reg) in zero)
                    or (ops[1].type == x.X86_OP_IMM and ops[1].imm == 0)))
                for byte in range(ops[0].size):
                    stores[slot[0], slot[1] + byte] = is_zero
        _, writes = ins.regs_access()
        for written in writes:
            family = register_family(md, written)
            zero.discard(family)
            if family == "rcx":
                argument = None
        if next_zero:
            zero.add(next_zero)
        if next_argument:
            argument = next_argument
    if argument is None or not all(stores.get((argument[0], argument[1] + byte)) for byte in range(8)):
        raise ContainerError("HTTP creation's output handle is not proved initialized to null")
    after = [ins for ins in code[index + 1:] if ins.mnemonic != "nop"]
    if len(after) < 3:
        raise ContainerError("HTTP creation lacks a native error continuation")
    save, test, branch = after[:3]
    if (save.mnemonic != "mov" or len(save.operands) != 2
            or save.operands[1].type != x.X86_OP_REG or save.operands[1].reg != x.X86_REG_EAX
            or test.mnemonic != "test" or len(test.operands) != 2
            or any(op.type != x.X86_OP_REG or op.reg != x.X86_REG_EAX for op in test.operands)
            or branch.mnemonic != "js" or branch.operands[0].type != x.X86_OP_IMM):
        raise ContainerError("HTTP creation does not select a native HRESULT-failure path")
    target = branch.operands[0].imm - image.base
    entry = function_entry_rva(image, call.rva)
    if target <= call.rva or function_entry_rva(image, target) != entry:
        raise ContainerError("HTTP error continuation leaves the native function")
    target_start, target_end = function_extent(image, target)
    boundaries = {address - image.base for address, _, _, _
                  in md.disasm_lite(image.read(target_start, target_end - target_start), image.base + target_start)}
    if target not in boundaries:
        raise ContainerError("HTTP failure continuation is not on an instruction boundary")
    patch = fail_hresult_call(image, "cancel_telemetry_webcall_creation", call.rva)
    patch.evidence.update(evidence)
    patch.evidence.update({"actual_function_entry_rva": hex(entry), "native_failure_rva": hex(target),
                           "null_handle_base_register": md.reg_name(argument[0]),
                           "null_handle_displacement_from_input": argument[1],
                           "chained_region_ret_avoided": True})
    return patch
