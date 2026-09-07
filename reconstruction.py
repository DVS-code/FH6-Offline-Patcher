from __future__ import annotations

from collections import Counter
import hashlib
import struct

import capstone

from static_container import Container, ContainerError, instructions, transforms, xor_transform
from static_image import Image, XorCodec
from input_consistency import validate_restored_boundaries


def reconstruct(image: Image, container: Container, codec: XorCodec) -> tuple[bytes, dict]:
    seed_data = container.table(2)
    if len(seed_data) != 8:
        raise ContainerError("Missing or unsupported XOR seed record")
    seed = struct.unpack("<Q", seed_data)[0]
    startup = transforms(container, 3)
    dynamic = transforms(container, 1)
    native = sorted(instructions(container), key=lambda row: row.rva)
    if not startup or not dynamic or not native:
        raise ContainerError("Incomplete protection tables")
    output = bytearray(image.data)
    for record in startup:
        if not record.checksum_valid:
            raise ContainerError("Startup transform selects nondeterministic corruption")
        rva, size = record.targets[0]
        offset = image.offset(rva, size, executable=True)
        source = record.source
        if source is None:
            source = bytes(output[offset:offset + size])
        output[offset:offset + size] = xor_transform(source, seed, codec.multiplier)
    startup_image = bytes(output)
    dynamic_spans = []
    dynamic_hashes = []
    for record in dynamic:
        if record.kind not in (0, 6, 7) or record.source is None:
            raise ContainerError(f"Unsupported dynamic record kind: {record.kind}")
        start, prefix = record.targets[0]
        end = start + prefix + record.size
        image.offset(start, prefix + record.size, executable=True)
        if any(not (start <= rva < end and rva + size <= end) for rva, size in record.targets):
            raise ContainerError("Dynamic target lies outside its source body")
        offset = image.offset(start + prefix, record.size, executable=True)
        plaintext = xor_transform(record.source, seed, codec.multiplier)
        output[offset:offset + record.size] = plaintext
        dynamic_spans.append((start, end))
        dynamic_hashes.append({"body_rva": start + prefix, "size": record.size,
                               "sha256": hashlib.sha256(plaintext).hexdigest()})
    dynamic_spans.sort()
    if any(a[1] > b[0] for a, b in zip(dynamic_spans, dynamic_spans[1:])):
        raise ContainerError("Overlapping dynamic source bodies need lifecycle resolution")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    previous_end = -1
    for record in native:
        if record.rva < previous_end:
            raise ContainerError("Overlapping native-instruction records")
        previous_end = record.rva + len(record.data)
        decoded = list(md.disasm(record.data, image.base + record.rva))
        if len(decoded) != 1 or decoded[0].size != len(record.data):
            raise ContainerError("Native record is not exactly one x64 instruction")
        offset = image.offset(record.rva, len(record.data), executable=True)
        output[offset:offset + len(record.data)] = record.data
    consistency = validate_restored_boundaries(Image(bytes(output)), native, dynamic)
    report = {
        "analysis_only": True,
        "bootable_patched_game": False,
        "game_sha256": hashlib.sha256(image.data).hexdigest(),
        "container_plaintext_sha256": hashlib.sha256(container.plaintext).hexdigest(),
        "xor_multiplier_from_input": hex(codec.multiplier),
        "xor_seed_from_container": hex(seed),
        "codec_evidence_rvas": [hex(rva) for rva in codec.evidence_rvas],
        "startup_records": len(startup),
        "startup_kinds": dict(Counter(record.kind for record in startup)),
        "startup_declared_bytes": sum(record.size for record in startup),
        "startup_image_sha256": hashlib.sha256(startup_image).hexdigest(),
        "dynamic_records": len(dynamic),
        "dynamic_kinds": dict(Counter(record.kind for record in dynamic)),
        "dynamic_source_bytes": sum(record.size for record in dynamic),
        "dynamic_bodies": dynamic_hashes,
        "native_instruction_records": len(native),
        "input_consistency": consistency,
        "analysis_image_sha256": hashlib.sha256(output).hexdigest(),
        "validation_limits": [
            "Observed container format only; alternate formats are not implemented.",
            "Input association needs stronger build-matching evidence before patch publication.",
            "Reconstructed code has not been certified as a complete plaintext image.",
            "No patch plan, startup lifecycle rewrite, or game acceptance is implied.",
        ],
    }
    return bytes(output), report
