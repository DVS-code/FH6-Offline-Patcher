from __future__ import annotations

import os
import struct
import sys

import nacl.bindings
import pefile

from static_container import ContainerError, open_container, parse_tables
from static_image import Image


def seal_container(plaintext: bytes, source: bytes, *, nonce_prefix: bytes | None = None) -> bytes:
    original = open_container(source)
    parse_tables(plaintext)
    header = source[original.footer.start:original.footer.start + 64]
    private, public = header[:32], header[32:]
    shared = nacl.bindings.crypto_box_beforenm(public, private)
    prefix = os.urandom(8) if nonce_prefix is None else nonce_prefix
    if len(prefix) != 8:
        raise ContainerError("Container nonce prefix must have eight bytes")
    sealed = nacl.bindings.crypto_box_afternm(plaintext, prefix + bytes(16), shared)
    payload = header + sealed + prefix
    _, factor, _, salt, _ = struct.unpack_from("<5Q", source, original.footer.offset)
    check = ((~(factor * len(payload))) & ((1 << 64) - 1)) ^ salt
    result = payload + struct.pack("<5Q", check, factor, len(payload), salt, len(payload) + 40)
    verified = open_container(result)
    if verified.plaintext != plaintext or verified.footer.start != 0:
        raise ContainerError("Re-encoded container did not round-trip")
    return result


def without_code_transforms(source: bytes) -> bytes:
    original = open_container(source)
    if not original.table(0) or not original.table(1) or not original.table(3):
        raise ContainerError("Expected the original nonempty protection tables")
    plaintext = bytearray(original.plaintext)


    for index in (1, 3):
        struct.pack_into("<Q", plaintext, 8 + index * 24 + 8, 0)
    return seal_container(bytes(plaintext), source)


def align(value: int, alignment: int) -> int:
    if alignment < 1 or alignment & (alignment - 1):
        raise ContainerError("PE alignment is not a power of two")
    return (value + alignment - 1) & -alignment


def add_readonly_section(image_data: bytes, name: bytes, payload: bytes) -> tuple[bytes, dict]:

    return _add_section(image_data, name, payload, 0x40000040)


def add_code_section(image_data: bytes, name: bytes, payload: bytes) -> tuple[bytes, dict]:

    return _add_section(image_data, name, payload, 0x60000020)


def next_section_rva(image: Image) -> int:
    return align(max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
                     for s in image.sections), image.pe.OPTIONAL_HEADER.SectionAlignment)


def calculate_checksum(data: bytes, checksum_offset: int) -> int:

    if checksum_offset < 0 or checksum_offset + 4 > len(data):
        raise ContainerError("PE checksum field lies outside the input")
    even = len(data) & ~1
    view = memoryview(data)
    value = (sum(view[:even].cast("H")) if sys.byteorder == "little"
             else sum(word[0] for word in struct.iter_unpack("<H", view[:even])))
    if len(data) & 1:
        value += data[-1]
    for offset in range(checksum_offset, checksum_offset + 4):
        value -= data[offset] << (8 if offset & 1 else 0)
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return value + len(data)


def checksum_valid(image: Image) -> bool:
    offset = image.pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    return image.pe.OPTIONAL_HEADER.CheckSum == calculate_checksum(image.data, offset)


def refresh_checksum(data: bytes) -> bytes:
    parsed = pefile.PE(data=data, fast_load=True)
    offset = parsed.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    result = bytearray(data)
    struct.pack_into("<I", result, offset, calculate_checksum(data, offset))
    return bytes(result)


def _add_section(image_data: bytes, name: bytes, payload: bytes, characteristics: int) -> tuple[bytes, dict]:
    image = Image(image_data)
    pe = image.pe
    optional = pe.OPTIONAL_HEADER
    if not payload or not 1 <= len(name) <= 8 or b"\0" in name or not name.isascii():
        raise ContainerError("Invalid new section name or empty payload")
    if any(s.Name.rstrip(b"\0") == name for s in image.sections):
        raise ContainerError("The input already contains the selected section")
    if pe.FILE_HEADER.NumberOfSections != len(image.sections) or len(image.sections) >= 96:
        raise ContainerError("Unsupported section count")
    file_alignment, section_alignment = optional.FileAlignment, optional.SectionAlignment
    if file_alignment < 0x200 or file_alignment > 0x10000 or section_alignment < file_alignment:
        raise ContainerError("Unsupported PE alignment")
    raw_offset = align(len(image_data), file_alignment)
    raw_size = align(len(payload), file_alignment)
    virtual_address = align(max(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
                                for s in image.sections), section_alignment)
    image_size = align(virtual_address + len(payload), section_alignment)
    if any(value > 0xFFFFFFFF for value in (raw_offset, raw_size, virtual_address, image_size)):
        raise ContainerError("New section exceeds PE field width")
    header_offset = image.sections[-1].get_file_offset() + 40
    first_raw = min(s.PointerToRawData for s in image.sections if s.SizeOfRawData)
    if header_offset + 40 > min(optional.SizeOfHeaders, first_raw):
        raise ContainerError("No space for another section header")
    if any(image_data[header_offset:header_offset + 40]):
        raise ContainerError("New section header would overwrite existing header data")
    size_field = "SizeOfCode" if characteristics & 0x20 else "SizeOfInitializedData"
    previous_size = getattr(optional, size_field)
    if previous_size + raw_size > 0xFFFFFFFF:
        raise ContainerError("Section aggregate size overflows the PE header")
    output = bytearray(image_data)
    output.extend(bytes(raw_offset - len(output)))
    output.extend(payload)
    output.extend(bytes(raw_size - len(payload)))
    header = struct.pack("<8sIIIIIIHHI", name, len(payload), virtual_address,
                         raw_size, raw_offset, 0, 0, 0, 0, characteristics)
    output[header_offset:header_offset + 40] = header
    struct.pack_into("<H", output, pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"), len(image.sections) + 1)
    struct.pack_into("<I", output, optional.get_field_absolute_offset("SizeOfImage"), image_size)
    struct.pack_into("<I", output, optional.get_field_absolute_offset(size_field), previous_size + raw_size)


    security = optional.DATA_DIRECTORY[4]
    struct.pack_into("<II", output, security.get_file_offset(), 0, 0)
    checksum_offset = optional.get_field_absolute_offset("CheckSum")
    struct.pack_into("<I", output, checksum_offset, 0)
    struct.pack_into("<I", output, checksum_offset, calculate_checksum(output, checksum_offset))
    final = Image(bytes(output))
    if final.read(virtual_address, len(payload)) != payload:
        raise ContainerError("Embedded payload failed PE read-back")
    if not checksum_valid(final):
        raise ContainerError("Constructed PE checksum is invalid")
    return bytes(output), {"name": name.decode("ascii"), "rva": hex(virtual_address),
                           "raw_offset": raw_offset, "virtual_size": len(payload),
                           "raw_size": raw_size, "characteristics": hex(characteristics),
                           "new_executable_code_bytes": len(payload) if characteristics & 0x20000000 else 0}
