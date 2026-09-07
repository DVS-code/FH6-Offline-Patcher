from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
import struct

import capstone

from static_container import ContainerError, Instruction, Transform
from static_image import Image


def validate_restored_boundaries(image: Image, native: list[Instruction],
                                dynamic: list[Transform]) -> dict:
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    if not directory.Size or directory.Size % 12:
        raise ContainerError("Missing or malformed independent exception metadata")
    extents = sorted({(start, end) for start, end, _ in struct.iter_unpack(
        "<III", image.read(directory.VirtualAddress, directory.Size))})
    if any(start >= end for start, end in extents):
        raise ContainerError("Invalid exception function extent")
    if any(a[1] > b[0] for a, b in zip(extents, extents[1:])):
        raise ContainerError("Overlapping exception function extents")
    starts = [start for start, _ in extents]
    groups = defaultdict(list)
    outside = []
    for record in native:
        index = bisect_right(starts, record.rva) - 1
        if index < 0 or record.rva >= extents[index][1]:
            outside.append(record.rva)
            continue
        if record.rva + len(record.data) > extents[index][1]:
            raise ContainerError("Native record crosses an independent function boundary")
        groups[extents[index]].append(record)
    if not groups:
        raise ContainerError("No native records are supported by independent function metadata")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    matched = 0
    for (start, end), records in groups.items():
        image.offset(start, end - start, executable=True)
        boundaries = {address - image.base: size for address, size, _, _
                      in md.disasm_lite(image.read(start, end - start), image.base + start)}
        for record in records:
            if boundaries.get(record.rva) != len(record.data):
                raise ContainerError(
                    f"Input files disagree at native instruction RVA {record.rva:#x}: "
                    "not an instruction boundary in the EXE's function metadata")
            matched += 1
    for record in dynamic:
        start, prefix = record.targets[0]
        size = prefix + record.size
        image.offset(start, size, executable=True)
        decoded = list(md.disasm_lite(image.read(start, size), image.base + start))
        if (not decoded or decoded[0][1] != prefix
                or decoded[-1][0] + decoded[-1][1] != image.base + start + size):
            raise ContainerError(f"Restored protected body at RVA {start:#x} does not decode completely")
    return {
        "metadata_functions_checked": len(groups),
        "native_records_on_metadata_instruction_boundaries": matched,
        "native_records_without_exception_metadata": len(outside),
        "native_rvas_without_exception_metadata": [hex(rva) for rva in outside],
        "protected_bodies_decoded_completely": len(dynamic),
        "cryptographic_exe_container_binding": False,
    }
