import re
import struct

import capstone as cs

from static_container import ContainerError
from static_semantics import function_extent


def direct_callers(image, target):
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    found, decoded_ranges = [], {}
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        data = section.get_data()[:section.Misc_VirtualSize]
        for match in re.finditer(b"[\xe8\xe9]", data):
            offset = match.start()
            if offset + 5 > len(data):
                continue
            rva = section.VirtualAddress + offset
            if rva + 5 + struct.unpack_from("<i", data, offset + 1)[0] != target:
                continue
            start, end = function_extent(image, rva)
            if (start, end) not in decoded_ranges:
                decoded_ranges[start, end] = {address - image.base: (size, mnemonic)
                    for address, size, mnemonic, _ in md.disasm_lite(image.read(start, end - start), image.base + start)}
            instruction = decoded_ranges[start, end].get(rva)
            if instruction is None:
                continue
            if instruction != (5, "call"):
                raise ContainerError("Unexpected non-call direct reference to the selected function")
            found.append(rva)
    return tuple(sorted(found))
