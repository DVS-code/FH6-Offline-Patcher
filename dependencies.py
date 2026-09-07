import hashlib
import json
import struct

import capstone as cs
from capstone import x86_const as x

from import_context import import_slots
from role_validation import region_shape, _switch_tables
from recognition import instruction_mask
from static_container import ContainerError
from static_semantics import function_extent, register_family
from tls_layout import tls_operands


def region_digest(image, rva):
    signature, mask = region_shape(image, rva)
    return hashlib.sha256(struct.pack("<I", len(signature)) + signature + mask).hexdigest()


def storage_identity(image, address, width):
    sections = [s for s in image.sections if s.VirtualAddress <= address
                < s.VirtualAddress + s.Misc_VirtualSize]
    if len(sections) != 1:
        raise ContainerError("Role data dependency is outside a unique section")
    section = sections[0]
    return {"kind": "storage", "width": width,
            "permissions": section.Characteristics & 0xE0000000}


def null_transfer(image, rva):

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    known, rows, address, visited = {}, [], rva, set()
    for _ in range(20):
        if address in visited:
            return None
        visited.add(address)
        ins = next(md.disasm(image.read(address, 15), image.base + address), None)
        if ins is None:
            return None
        ops = ins.operands
        signature, mask = instruction_mask(ins.bytes, ins.address, image)
        rows.append([address - rva, signature.hex(), mask.hex()])
        if (ins.mnemonic == "xor" and len(ops) == 2 and ops[0].type == ops[1].type == x.X86_OP_REG
                and ops[0].reg == ops[1].reg and ops[0].size >= 4):
            known[register_family(md, ops[0].reg)] = 0
        elif (ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == ops[1].type == x.X86_OP_REG
              and register_family(md, ops[1].reg) in known and ops[0].size >= 4):
            known[register_family(md, ops[0].reg)] = known[register_family(md, ops[1].reg)]
        elif ins.mnemonic == "jmp" and len(ops) == 1:
            if ops[0].type == x.X86_OP_IMM:
                address = ops[0].imm - image.base
                if not rva <= address < rva + 128:
                    return None
                continue
            if ops[0].type == x.X86_OP_REG and known.get(register_family(md, ops[0].reg)) == 0:
                return {"kind": "proved_null_transfer", "noreturn": True,
                        "digest": hashlib.sha256(json.dumps(rows).encode()).hexdigest()}
            return None
        else:
            return None
        address += ins.size
    return None


def leaf_digest(image, rva, slots, depth):

    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    pending, rows, occupied, decoded = [rva], {}, set(), {}
    while pending:
        address = pending.pop()
        if address in rows:
            continue
        if not rva <= address < rva + 4096 or len(rows) >= 2048:
            raise ContainerError("Native leaf dependency exceeds its CFG bound")
        ins = next(md.disasm(image.read(address, 15), image.base + address), None)
        if ins is None or ins.mnemonic in ("int3", "ud2"):
            raise ContainerError("Unsupported native leaf dependency")
        span = set(range(address, address + ins.size))
        if span & occupied:
            raise ContainerError("Overlapping native leaf instructions")
        occupied.update(span)
        decoded[ins.address] = ins
        signature, mask = instruction_mask(ins.bytes, ins.address, image)
        row = {"offset": address - rva, "signature": signature.hex(), "mask": mask.hex()}
        no_return = False
        control = ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP)
        for operand in ins.operands:
            if control and operand.type == x.X86_OP_IMM:
                target = operand.imm - image.base
                if rva <= target < rva + 4096 and not ins.group(cs.CS_GRP_CALL):
                    row["edge"] = target - rva
                    pending.append(target)
                else:
                    row["edge"] = native_identity(image, target, slots, depth + 1)
                    no_return = bool(row["edge"].get("noreturn"))
            elif operand.type == x.X86_OP_MEM and operand.mem.base == x.X86_REG_RIP:
                target = address + ins.size + operand.mem.disp
                if target in slots:
                    row["import"] = list(slots[target])
                else:
                    row["data"] = storage_identity(image, target, operand.size)
        rows[address] = row
        if ins.mnemonic not in ("ret", "jmp") and not no_return:
            pending.append(address + ins.size)
    spans, identity = tls_operands(image, [decoded[a] for a in sorted(decoded)], md)
    for offset, width in spans:
        owner = next(ins for ins in decoded.values()
                     if ins.address - image.base - rva + ins.imm_offset == offset)
        row = rows[owner.address - image.base]
        signature, mask = bytearray.fromhex(row['signature']), bytearray.fromhex(row['mask'])
        signature[owner.imm_offset:owner.imm_offset + width] = bytes(width)
        mask[owner.imm_offset:owner.imm_offset + width] = bytes(width)
        row.update(signature=signature.hex(), mask=mask.hex())
    payload = json.dumps([rows[a] for a in sorted(rows)], sort_keys=True).encode()
    return hashlib.sha256(payload + (b'TLS1' + identity if identity else b'')).hexdigest()


def native_identity(image, address, slots, depth=0):
    if depth > 12:
        raise ContainerError("Native dependency tail chain is cyclic or too deep")
    cache = getattr(image, "_native_identities", {})
    image._native_identities = cache
    if address in cache:
        return cache[address]
    image.offset(address, 1, executable=True)
    try:
        start, _ = function_extent(image, address)
    except ContainerError:
        item = null_transfer(image, address)
        if item is None:
            item = {"kind": "native_leaf", "digest": leaf_digest(image, address, slots, depth)}
    else:
        item = {"kind": "native_region", "entry_offset": address - start,
                "digest": region_digest(image, address)}
    cache[address] = item
    return item


def dependency_shape(image, rva):

    begin, end = function_extent(image, rva)
    slots = getattr(image, "_dependency_imports", None)
    if slots is None:
        slots = import_slots(image)
        image._dependency_imports = slots
    cache = getattr(image, "_dependency_targets", {})
    image._dependency_targets = cache
    aliases = {}
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True

    def describe(target, code):
        if image.base + begin <= target < image.base + end:
            return {"kind": "internal", "offset": target - image.base - begin}
        if target == image.base:
            return {"kind": "image_base"}
        address = target - image.base
        key = (address, code)
        if key not in cache:
            if address in slots:
                library, name = slots[address]
                item = {"kind": "import", "library": library.lower(), "name": name}
            else:
                sections = [s for s in image.sections if s.VirtualAddress <= address
                            < s.VirtualAddress + s.Misc_VirtualSize]
                if len(sections) != 1:
                    raise ContainerError("Role dependency is outside a unique image section")
                section = sections[0]
                if code:
                    image.offset(address, 1, executable=True)

                    head = image.read(address, 6)
                    slot = address + 6 + struct.unpack_from("<i", head, 2)[0]
                    if head[:2] == b"\xff\x25" and slot in slots:
                        library, name = slots[slot]
                        item = {"kind": "import_thunk", "library": library.lower(), "name": name}
                    else:
                        item = native_identity(image, address, slots)
                else:
                    item = {"kind": "storage", "permissions": section.Characteristics & 0xE0000000}
                cache[key] = item
            cache[key] = item
        alias = aliases.setdefault(address, len(aliases))
        return {**cache[key], "alias": alias}

    references = []
    decoded = list(md.disasm(image.read(begin, end - begin), image.base + begin))
    tables = _switch_tables(image, begin, end, decoded, md)
    code_end = min((table for table, _, _, _ in tables), default=end)
    for instruction in decoded:
        if instruction.address >= image.base + code_end:
            break
        control = instruction.group(cs.CS_GRP_CALL) or instruction.group(cs.CS_GRP_JUMP)
        for index, operand in enumerate(instruction.operands):
            target, code = None, False
            if operand.type == x.X86_OP_MEM and operand.mem.base == x.X86_REG_RIP:
                target = instruction.address + instruction.size + operand.mem.disp
            elif operand.type == x.X86_OP_IMM and (control or image.base <= operand.imm < image.base + image.pe.OPTIONAL_HEADER.SizeOfImage):
                target, code = operand.imm, bool(control)
            if target is not None:
                references.append({"instruction": instruction.address - image.base - begin,
                                   "operand": index, "width": operand.size,
                                   "target": describe(target, code)})
    return references
