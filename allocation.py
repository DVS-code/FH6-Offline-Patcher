from dataclasses import dataclass, asdict
import re

import capstone as cs
from capstone import x86_const as x

from import_context import import_slots, decoded_import_call
from static_container import ContainerError
from static_semantics import function_extent, function_entry_rva, register_family, exception_records


@dataclass(frozen=True)
class AllocationSite:
    function_start: int
    function_end: int
    parent_unwind: int
    call_rva: int
    old_allocator: int
    allocation_size: int
    allocation_flags: int
    protection_flags: int
    result_global: int
    failure_rva: int
    failure_size: int
    stores_rva: int
    stores_size: int
    lock_rva: int
    lock_acquire_rva: int
    release_iat: int
    virtualalloc_iat: int
    epilogue_rva: int
    cookie_check: int

    def evidence(self):
        return {key: hex(value) if key not in ("allocation_size", "failure_size", "stores_size") else value
                for key, value in asdict(self).items()}


def _dominates(code, blocked, target):

    by_address = {ins.address: ins for ins in code}
    pending, visited = [code[0].address], set()
    while pending:
        address = pending.pop()
        if address == target:
            return False
        if address in visited or address == blocked or address not in by_address:
            continue
        visited.add(address)
        ins = by_address[address]
        if ins.group(cs.CS_GRP_RET):
            continue
        if ins.group(cs.CS_GRP_JUMP):
            if not ins.operands or ins.operands[0].type != x.X86_OP_IMM:
                raise ContainerError("Indirect control flow prevents allocation lock proof")
            pending.append(ins.operands[0].imm)
            if ins.mnemonic != "jmp":
                pending.append(address + ins.size)
        else:
            pending.append(address + ins.size)
    return True


def _writable(image, rva, size=8):
    if not any(section.Characteristics & 0x80000000 and section.VirtualAddress <= rva
               and rva + size <= section.VirtualAddress + section.Misc_VirtualSize for section in image.sections):
        raise ContainerError("Allocation state does not refer to writable image storage")


def _analyze(image, rva, slots):
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    start, end = function_extent(image, rva)
    if function_entry_rva(image, start) != start:
        raise ContainerError("Allocation owner is a chained fragment")
    code = list(md.disasm(image.read(start, end - start), image.base + start))
    by_rva = {ins.address - image.base: index for index, ins in enumerate(code)}
    if rva not in by_rva:
        raise ContainerError("Allocation candidate is not on an instruction boundary")
    index = by_rva[rva]
    setup = code[index:index + 6]
    if len(setup) != 6:
        raise ContainerError("Incomplete allocation argument sequence")
    protection, flags, size_move, zero, call, store = setup

    def reg(op, name):
        return op.type == x.X86_OP_REG and register_family(md, op.reg) == name

    def immediate(ins, name):
        if (ins.mnemonic == "mov" and len(ins.operands) == 2 and reg(ins.operands[0], name)
                and ins.operands[0].size == 4 and ins.operands[1].type == x.X86_OP_IMM):
            return ins.operands[1].imm
        raise ContainerError("Allocation flag argument is not a direct input constant")

    protection_value, flags_value = immediate(protection, "r9"), immediate(flags, "r8")
    if protection_value != 4 or flags_value & 0x3000 != 0x3000:
        raise ContainerError("Allocation does not request read/write reserved and committed pages")
    if (size_move.mnemonic != "mov" or len(size_move.operands) != 2 or not reg(size_move.operands[0], "rdx")
            or size_move.operands[1].type != x.X86_OP_REG or size_move.operands[1].size != 8):
        raise ContainerError("Allocation size is not held in a supported register")
    size_register = register_family(md, size_move.operands[1].reg)
    if size_register not in {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}:
        raise ContainerError("Allocation size is not in a nonvolatile register")
    if (zero.mnemonic != "xor" or len(zero.operands) != 2
            or any(not reg(op, "rcx") or op.size != 4 for op in zero.operands)
            or call.mnemonic != "call" or call.size != 5 or call.operands[0].type != x.X86_OP_IMM):
        raise ContainerError("Allocation call does not have the expected null-address argument")
    allocation_size = None
    for ins in reversed(code[:index]):
        _, writes = ins.regs_access()
        if any(register_family(md, written) == size_register for written in writes):
            if (ins.mnemonic in ("mov", "movabs") and len(ins.operands) == 2
                    and reg(ins.operands[0], size_register) and ins.operands[0].size in (4, 8)
                    and ins.operands[1].type == x.X86_OP_IMM):
                allocation_size = ins.operands[1].imm
            break
    if allocation_size is None or allocation_size <= 0:
        raise ContainerError("Allocation size cannot be derived from its reaching definition")
    if (store.mnemonic != "mov" or len(store.operands) != 2 or store.operands[0].type != x.X86_OP_MEM
            or store.operands[0].size != 8 or store.operands[0].mem.base != x.X86_REG_RIP
            or store.operands[0].mem.index or not reg(store.operands[1], "rax")):
        raise ContainerError("Allocation result is not published to a direct image global")
    global_rva = store.address + store.size + store.operands[0].mem.disp - image.base
    _writable(image, global_rva)
    test_index = None
    for position in range(index + 6, min(index + 12, len(code))):
        ins = code[position]
        if ins.mnemonic == "test" and len(ins.operands) == 2 and all(reg(op, "rax") and op.size == 8 for op in ins.operands):
            test_index = position
            break
        _, writes = ins.regs_access()
        if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) or any(register_family(md, reg_id) == "rax" for reg_id in writes):
            break
    if test_index is None or test_index + 1 >= len(code):
        raise ContainerError("Allocation result is not checked before further calls")
    branch = code[test_index + 1]
    if branch.mnemonic not in ("jne", "jnz") or branch.operands[0].type != x.X86_OP_IMM:
        raise ContainerError("Allocation lacks its native nonnull success branch")
    success = branch.operands[0].imm - image.base
    if success not in by_rva:
        raise ContainerError("Allocation success is not an instruction in its owner")
    position = by_rva[success]
    while position < len(code) and code[position].mnemonic == "lea" and not reg(code[position].operands[0], "rax"):
        position += 1
    if position >= len(code):
        raise ContainerError("Allocation success lacks initialization stores")
    stores_rva, total = code[position].address - image.base, 0
    while position < len(code):
        ins = code[position]
        ops = ins.operands
        if (ins.mnemonic not in ("movups", "movaps", "movdqu", "movdqa") or len(ops) != 2
                or ops[0].type != x.X86_OP_MEM or ops[0].size != 16
                or ops[0].mem.base != x.X86_REG_RAX or ops[0].mem.index
                or ops[0].mem.disp != total or ops[1].type != x.X86_OP_REG or ops[1].size != 16):
            break
        total += 16
        position += 1
    if total != allocation_size:
        raise ContainerError("Native initialization stores do not match the discovered allocation size")
    failures = []
    for position, jump in enumerate(code):
        if (jump.mnemonic != "jmp" or not jump.operands or jump.operands[0].type != x.X86_OP_IMM
                or jump.operands[0].imm - image.base != stores_rva or position == 0):
            continue
        load = code[position - 1]
        if not branch.address < load.address < image.base + success:
            continue
        if (load.mnemonic == "mov" and len(load.operands) == 2 and reg(load.operands[0], "rax")
                and load.operands[1].type == x.X86_OP_MEM and load.operands[1].mem.base == x.X86_REG_RIP
                and load.address + load.size + load.operands[1].mem.disp - image.base == global_rva):
            failures.append((load.address - image.base, load.size + jump.size))
    if len(failures) != 1 or failures[0][1] < 5:
        raise ContainerError("Allocation failure does not have a unique reload-and-store edge")
    acquires = []
    for position, ins in enumerate(code[:index]):
        imported = decoded_import_call(image, ins, slots)
        if imported and imported.name == "AcquireSRWLockExclusive" and position:
            argument = code[position - 1]
            if (argument.mnemonic == "lea" and len(argument.operands) == 2 and reg(argument.operands[0], "rcx")
                    and argument.operands[1].type == x.X86_OP_MEM and argument.operands[1].mem.base == x.X86_REG_RIP):
                lock = argument.address + argument.size + argument.operands[1].mem.disp - image.base
                acquires.append((position, lock))
    if not acquires:
        raise ContainerError("Allocation has no identified exclusive lock acquisition")
    acquire_index, lock = acquires[-1]
    _writable(image, lock)
    if not _dominates(code, code[acquire_index].address, call.address):
        raise ContainerError("The discovered lock acquisition does not dominate allocation")
    if any((imported := decoded_import_call(image, ins, slots)) and imported.name == "ReleaseSRWLockExclusive"
           for ins in code[acquire_index + 1:index]):
        raise ContainerError("Lock ownership is ambiguous before allocation")
    epilogues = []
    for position in range(len(code) - 3):
        load, xor, check = code[position:position + 3]
        if (load.mnemonic != "mov" or len(load.operands) != 2 or not reg(load.operands[0], "rcx")
                or load.operands[1].type != x.X86_OP_MEM or load.operands[1].mem.base not in (x.X86_REG_RSP, x.X86_REG_RBP)
                or xor.mnemonic != "xor" or len(xor.operands) != 2 or not reg(xor.operands[0], "rcx")
                or not reg(xor.operands[1], "rsp") or check.mnemonic != "call"
                or check.operands[0].type != x.X86_OP_IMM):
            continue
        tail = code[position + 3:]
        if tail and tail[-1].mnemonic == "ret" and all(ins.mnemonic in {
                "lea", "mov", "movaps", "movups", "movdqu", "movdqa", "pop", "add", "ret", "nop"} for ins in tail):
            epilogues.append((load.address - image.base, check.operands[0].imm - image.base))
    if len(epilogues) != 1:
        raise ContainerError("A unique native cookie/register restoration epilogue was not found")

    def iat(name):
        values = [address for address, (_, imported_name) in slots.items() if imported_name == name]
        if len(values) != 1:
            raise ContainerError(f"Required {name} import is missing or ambiguous")
        return values[0]

    parent = next(row for row in exception_records(image) if row[0] == start and row[1] == end)
    return AllocationSite(start, end, parent[2], call.address - image.base, call.operands[0].imm - image.base,
                          allocation_size, flags_value, protection_value, global_rva, *failures[0], stores_rva, total,
                          lock, code[acquire_index].address - image.base, iat("ReleaseSRWLockExclusive"),
                          iat("VirtualAlloc"), *epilogues[0])


def discover_allocation_site(image):
    slots = import_slots(image)
    candidates = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(rb"\x41\xb9.{4}\x41\xb8.{4}", data, re.DOTALL):
            offset = match.start()
            if (int.from_bytes(data[offset + 2:offset + 6], "little") != 4
                    or int.from_bytes(data[offset + 8:offset + 12], "little") & 0x3000 != 0x3000):
                continue
            try:
                candidates.append(_analyze(image, section.VirtualAddress + match.start(), slots))
            except ContainerError:
                continue
    if len(candidates) != 1:
        raise ContainerError(f"Expected one guarded global allocation with the reviewed data flow; found {len(candidates)}")
    return candidates[0]
