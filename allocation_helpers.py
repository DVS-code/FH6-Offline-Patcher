import struct

from allocation import AllocationSite
from embedded_container import add_code_section, add_readonly_section, align, next_section_rva, refresh_checksum, checksum_valid
from patch_actions import Patch
from static_container import ContainerError
from static_image import Image
from static_semantics import function_entry_rva


def relative32(next_rva, target):
    displacement = target - next_rva
    if not -(1 << 31) <= displacement < 1 << 31:
        raise ContainerError("Generated allocation helper exceeds relative addressing range")
    return struct.pack("<i", displacement)


def emit_allocation_helpers(image: Image, site: AllocationSite):

    code_rva = next_section_rva(image)
    thunk = b"\xff\x25" + relative32(code_rva + 6, site.virtualalloc_iat)
    guard_offset = align(len(thunk), 16)
    guard_rva = code_rva + guard_offset
    guard = b"\x48\x8d\x0d" + relative32(guard_rva + 7, site.lock_rva)
    guard += b"\xff\x15" + relative32(guard_rva + len(guard) + 6, site.release_iat)
    guard += b"\x31\xc0"




    guard += b"\x0f\x84" + relative32(guard_rva + len(guard) + 6, site.epilogue_rva)
    guard += b"\x0f\x0b"
    code = thunk + b"\xcc" * (guard_offset - len(thunk)) + guard
    with_code, code_record = add_code_section(image.data, b".fh6fix", code)
    if int(code_record["rva"], 16) != code_rva:
        raise ContainerError("Generated helper section moved unexpectedly")
    code_image = Image(with_code)
    metadata_rva = next_section_rva(code_image)
    directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    original_table = image.read(directory.VirtualAddress, directory.Size)
    if directory.Size % 12:
        raise ContainerError("Cannot extend malformed exception metadata")
    rows = list(struct.iter_unpack("<III", original_table))
    parent = (site.function_start, site.function_end, site.parent_unwind)
    if parent not in rows or any(start >= guard_rva for start, _, _ in rows):
        raise ContainerError("Helper unwind metadata cannot extend the supplied ordered table")
    unwind_rva = metadata_rva + len(original_table) + 12
    parent_header = image.read(site.parent_unwind, 4)
    if parent_header[0] & 7 != 1 or parent_header[0] >> 3 & 4:
        raise ContainerError("Allocation helper requires a primary version-one unwind record")


    unwind = bytes((0x21, 0, 0, parent_header[3])) + struct.pack("<III", *parent)
    new_table = original_table + struct.pack("<III", guard_rva, guard_rva + len(guard), unwind_rva)
    with_metadata, metadata_record = add_readonly_section(with_code, b".fh6meta", new_table + unwind)
    if int(metadata_record["rva"], 16) != metadata_rva:
        raise ContainerError("Generated exception metadata moved unexpectedly")
    output = bytearray(with_metadata)
    struct.pack_into("<II", output, directory.get_file_offset(), metadata_rva, len(new_table))
    output = refresh_checksum(bytes(output))
    final = Image(output)
    if (function_entry_rva(final, guard_rva) != site.function_start
            or final.read(metadata_rva, len(original_table)) != original_table
            or not checksum_valid(final)):
        raise ContainerError("Generated helper/unwind metadata did not validate")
    call_before = image.read(site.call_rva, 5)
    if call_before[:1] != b"\xe8":
        raise ContainerError("Allocation call preimage no longer has its validated encoding")
    call_after = b"\xe8" + relative32(site.call_rva + 5, code_rva)
    failure_after = b"\xe9" + relative32(site.failure_rva + 5, guard_rva)
    failure_after += b"\x90" * (site.failure_size - len(failure_after))
    actions = [
        Patch("guarded_global_allocation_via_virtualalloc", site.call_rva, call_before, call_after,
              {"action": "redirect_to_input_import_tail_thunk", "thunk_rva": hex(code_rva),
               "allocation_size_from_input": site.allocation_size, "native_arguments_preserved": True}),
        Patch("allocation_failure_releases_lock_and_returns_false", site.failure_rva,
              image.read(site.failure_rva, site.failure_size), failure_after,
              {"action": "jump_to_native_frame_cleanup_helper", "helper_rva": hex(guard_rva),
               "native_epilogue_rva": hex(site.epilogue_rva), "chained_unwind_rva": hex(unwind_rva)}),
    ]
    return output, actions, {"code_section": code_record, "metadata_section": metadata_record,
                             "guard_rva": hex(guard_rva), "guard_size": len(guard),
                             "guard_hex": guard.hex(), "thunk_hex": thunk.hex(),
                             "unwind_rva": hex(unwind_rva), "unwind_hex": unwind.hex(),
                             "exception_directory_rva": hex(metadata_rva),
                             "exception_directory_size": len(new_table),
                             "original_exception_records_preserved": True,
                             "native_windows_unwind_tested": False, "game_tested": False}
