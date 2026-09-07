from __future__ import annotations

from dataclasses import dataclass
import struct

from static_container import ContainerError
from static_image import Image


@dataclass(frozen=True)
class CallableTable:
    type_name: str
    type_rva: int
    locator_rva: int
    vtable_rva: int
    targets: tuple[int, ...]


def find_callable_tables(image: Image, type_fragment: str) -> tuple[CallableTable, ...]:
    fragment = type_fragment.encode("ascii")
    if not fragment or b"\0" in fragment:
        raise ContainerError("An RTTI query must be a nonempty name fragment")
    data_sections = [s for s in image.sections if s.Characteristics & 0x40000000
                     and not s.Characteristics & 0x20000000]
    types = {}
    for section in data_sections:
        data = section.get_data()[:section.Misc_VirtualSize]
        position = data.find(fragment)
        while position >= 0:
            start = data.rfind(b"\0", max(0, position - 4096), position) + 1
            end = data.find(b"\0", position)
            if end >= 0 and end - start <= 4096:
                name = data[start:end]



                if name.startswith((b".?AV", b".?AU")) and start >= 16:
                    type_rva = section.VirtualAddress + start - 16
                    if type_rva % 8 == 0:
                        try:
                            types[type_rva] = name.decode("ascii", errors="strict")
                        except UnicodeDecodeError as error:
                            raise ContainerError("Malformed decorated RTTI name") from error
            position = data.find(fragment, position + 1)
    results = []
    for type_rva, name in types.items():
        needle = struct.pack("<I", type_rva)
        locators = set()
        for section in data_sections:
            data = section.get_data()[:section.Misc_VirtualSize]
            position = data.find(needle)
            while position >= 0:
                start = position - 12
                if start >= 0 and start + 24 <= len(data):
                    signature, offset, constructor, descriptor, hierarchy, self_rva = struct.unpack_from("<6I", data, start)
                    locator = section.VirtualAddress + start
                    if signature == 1 and offset == 0 and constructor == 0 and self_rva == locator:
                        try:
                            image.offset(hierarchy, 16)
                        except ContainerError:
                            pass
                        else:
                            locators.add(locator)
                position = data.find(needle, position + 1)
        for locator in locators:
            pointer = struct.pack("<Q", image.base + locator)
            for section in data_sections:
                data = section.get_data()[:section.Misc_VirtualSize]
                position = data.find(pointer)
                while position >= 0:
                    vtable = section.VirtualAddress + position + 8
                    if vtable % 8 == 0:
                        targets = []
                        cursor = position + 8
                        while cursor + 8 <= len(data):
                            target = struct.unpack_from("<Q", data, cursor)[0] - image.base
                            try:
                                image.offset(target, 1, executable=True)
                            except ContainerError:
                                break
                            targets.append(target)
                            cursor += 8
                            if len(targets) > 256:
                                raise ContainerError("Unbounded RTTI vtable candidate")
                        if targets:
                            results.append(CallableTable(name, type_rva, locator, vtable, tuple(targets)))
                    position = data.find(pointer, position + 1)
    return tuple(sorted(set(results), key=lambda result: (result.type_name, result.vtable_rva)))


def discover_fatal_license_thunk(image: Image):

    from capstone import x86_const as x
    from patch_actions import Patch, decode_at

    tables = find_callable_tables(image, "PerformLicenseCheck_Fatal@Security")
    candidates = {}
    for table in tables:
        for rva in table.targets:
            ins = decode_at(image, rva)
            if (ins.mnemonic != "jmp" or ins.size != 5 or len(ins.operands) != 1
                    or ins.operands[0].type != x.X86_OP_IMM):
                continue
            target = ins.operands[0].imm - image.base
            image.offset(target, 1, executable=True)
            candidates.setdefault(rva, []).append(table)
    if len(candidates) != 1:
        raise ContainerError(f"Expected one named fatal callable tail thunk; found {len(candidates)}")
    rva, evidence = next(iter(candidates.items()))
    return Patch("fatal_license_inner_callable", rva, image.read(rva, 5), b"\x31\xc0\xc3\x90\x90",
                 {"action": "return_zero_from_named_tail_thunk",
                  "rtti_types": sorted({table.type_name for table in evidence}),
                  "vtables": [hex(table.vtable_rva) for table in evidence],
                  "fixed_vtable_slot_used": False})
