from __future__ import annotations

import struct
import sys
import unittest
import random
from pathlib import Path

import nacl.bindings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from static_container import (
    Container, ContainerError, Footer, Table, Instruction, find_footers, instructions,
    open_container, parse_tables, transforms, xor_transform,
)
from static_image import Image, discover_xor_codec
from embedded_container import add_readonly_section, seal_container, calculate_checksum, add_code_section
from static_semantics import sealed_strings, function_entry_rva
from rtti import discover_fatal_license_thunk
from input_consistency import validate_restored_boundaries
from recognition import Profile, instruction_mask, discover_profile
from import_context import discover_context_call
from hashed_exports import folded_hash, hash_loops
from response_creators import discover_response_creators
from formatter_variant import discover_formatter_variant
from allocation import discover_allocation_site
from role_validation import region_shape, validate_region_shape
from patch_actions import (force_branch, suppress_call, clear_mutex_result_slots, apply_plan,
                           skip_reserved_identity_strike, skip_debugger_detach_transaction,
                           initialized_object_return, thread_hide_leaf_return, stall_entry, entry_return,
                           fail_hresult_call)


def sample_container():
    plain = bytearray(8 + 32 * 24)
    struct.pack_into("<3Q", plain, 8 + 2 * 24, 0, 8, 0)
    plain += struct.pack("<Q", 12345)
    public, private = nacl.bindings.crypto_box_seed_keypair(bytes(range(32)))
    nonce = bytes(range(8)) + bytes(16)
    shared = nacl.bindings.crypto_box_beforenm(public, private)
    body = private + public + nacl.bindings.crypto_box_afternm(bytes(plain), nonce, shared) + nonce[:8]
    factor, salt = 123, 98765
    check = (~(factor * len(body)) & ((1 << 64) - 1)) ^ salt
    footer = struct.pack("<5Q", check, factor, len(body), salt, len(body) + 40)
    return body + footer, bytes(plain)


def sample_pe(text: bytes, *, text_rva=0x1000, image_base=0x180000000, data_rva=0x4000):
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, text_rva)
    struct.pack_into("<Q", data, optional + 24, image_base)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, max(text_rva, data_rva) + 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    for index, (name, rva, raw, flags) in enumerate([
        (b"code", text_rva, 0x200, 0x60000020),
        (b"state", data_rva, 0x400, 0xC0000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", data, optional + 240 + index * 40,
                         name, 0x200, rva, 0x200, raw, 0, 0, 0, 0, flags)
    data[0x200:0x200 + len(text)] = text
    return bytes(data)


def loop(text_rva, seed_rva, multiplier):
    code = bytearray(b"\x48\xbb" + struct.pack("<Q", multiplier))

    code += b"\x48\x33\x05" + struct.pack("<i", seed_rva - (text_rva + len(code) + 7))
    code += b"\x48\x0f\xaf\xc3\x48\xc1\xe9\x03"

    code += b"\x48\x31\x07\x48\x83\xc7\x08\x48\x0f\xaf\xc3\x48\xff\xc9\x75\xf0\xc3"
    return bytes(code)


def sample_function(code):
    raw = bytearray(sample_pe(code))
    struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, 0x4000, 12)
    struct.pack_into("<III", raw, 0x400, 0x1000, 0x1000 + len(code), 0x4050)
    raw[0x450] = 1
    return Image(bytes(raw))


def sample_import_functions(text_rva=0x1000, data_rva=0x4000, base=0x180000000,
                            duplicate=False, fake_instruction=False):
    code = bytearray(b"\x90" * 0x80)
    extents = []
    for index, displacement in enumerate((0, 0x40)):
        start = text_rva + displacement
        body = bytearray()
        if fake_instruction:

            body += b"\x48\xb8\xff\x15" + struct.pack("<i", data_rva + 0x60 - (start + 8)) + b"\0\0"
        else:
            body += b"\xff\x15" + struct.pack("<i", data_rva + 0x60 - (start + 6))
        if index == 0 or duplicate:
            body += b"\xff\x15" + struct.pack("<i", data_rva + 0x68 - (start + len(body) + 6))
        body += b"\xc3"
        code[displacement:displacement + len(body)] = body
        extents.append((start, start + len(body), data_rva + 0x180))
    raw = bytearray(sample_pe(bytes(code), text_rva=text_rva, data_rva=data_rva, image_base=base))
    struct.pack_into("<II", raw, 0x98 + 112 + 8, data_rva, 40)
    struct.pack_into("<5I", raw, 0x400, data_rva + 0x40, 0, 0, data_rva + 0xC0, data_rva + 0x60)
    for offset in (0x440, 0x460):
        struct.pack_into("<3Q", raw, offset, data_rva + 0x80, data_rva + 0xA0, 0)
    for offset, name in ((0x480, b"IsDebuggerPresent"), (0x4A0, b"RtlCaptureContext")):
        raw[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    raw[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, data_rva + 0x100, 24)
    for index, extent in enumerate(extents):
        struct.pack_into("<III", raw, 0x500 + 12 * index, *extent)
    return Image(bytes(raw))


def sample_allocation(size, *, text_rva=0x1000, data_rva=0x4000, bypass_lock=False, wrong_size=False):
    code = bytearray(b"\x90" * 5 + b"\x48\x83\xec\x28")
    lock, result = data_rva + 0x188, data_rva + 0x180

    def rip(opcode, target):
        code.extend(opcode + struct.pack("<i", target - (text_rva + len(code) + len(opcode) + 4)))

    rip(b"\x48\x8d\x0d", lock)
    rip(b"\xff\x15", data_rva + 0x80)
    code += b"\xbb" + struct.pack("<I", size + (16 if wrong_size else 0))
    allocation_start = len(code)
    code += b"\x41\xb9\x04\0\0\0\x41\xb8\0\x30\0\0\x48\x8b\xd3\x33\xc9"
    rip(b"\xe8", text_rva + 0x1E0)
    rip(b"\x48\x89\x05", result)
    code += b"\x48\x85\xc0"
    success_branch = len(code)
    code += b"\x0f\x85\0\0\0\0"
    rip(b"\x48\x8b\x05", result)
    failure_jump = len(code)
    code += b"\xe9\0\0\0\0"
    success = len(code)
    rip(b"\x48\x8d\x3d", data_rva + 0x1C0)
    stores = len(code)
    for offset in range(0, size, 16):
        code += b"\x0f\x11\x30" if offset == 0 else b"\x0f\x11\x70" + bytes([offset])
    rip(b"\x48\x8d\x0d", lock)
    rip(b"\xff\x15", data_rva + 0x88)
    code += b"\x31\xc0\x48\x8b\x4c\x24\x20\x48\x33\xcc"
    rip(b"\xe8", text_rva + 0x1F0)
    code += b"\x48\x83\xc4\x28\xc3"
    struct.pack_into("<i", code, success_branch + 2, success - success_branch - 6)
    struct.pack_into("<i", code, failure_jump + 1, stores - failure_jump - 5)
    if bypass_lock:
        code[:5] = b"\xe9" + struct.pack("<i", allocation_start - 5)
    raw = bytearray(sample_pe(bytes(code), text_rva=text_rva, data_rva=data_rva))
    struct.pack_into("<II", raw, 0x98 + 112 + 8, data_rva, 40)
    struct.pack_into("<5I", raw, 0x400, data_rva + 0x40, 0, 0, data_rva + 0x120, data_rva + 0x80)
    for offset in (0x440, 0x480):
        struct.pack_into("<4Q", raw, offset, data_rva + 0xB0, data_rva + 0xD0, data_rva + 0xF0, 0)
    for offset, name in ((0x4B0, b"AcquireSRWLockExclusive"), (0x4D0, b"ReleaseSRWLockExclusive"), (0x4F0, b"VirtualAlloc")):
        raw[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    raw[0x520:0x52D] = b"KERNEL32.dll\0"
    struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, data_rva + 0x100, 12)
    struct.pack_into("<III", raw, 0x500, text_rva, text_rva + len(code), data_rva + 0x150)
    raw[0x550] = 1
    return Image(bytes(raw))


class ContainerTests(unittest.TestCase):
    def test_complete_region_validation_rejects_changed_control_flow_after_same_anchor(self):
        original = sample_function(b"\x31\xc0\x75\x03\x90\x90\xc3\xc3")
        changed = sample_function(b"\x31\xc0\x75\x02\x90\x90\xc3\xc3")
        profile = Profile("reviewed", b"\x31\xc0", b"\1\1", "return_zero")
        signature, mask = region_shape(original, 0x1000)
        validation = {"kind": "complete_containing_region", "signature": signature.hex(), "mask": mask.hex()}
        self.assertEqual(discover_profile(changed, profile), 0x1000)
        validate_region_shape(original, profile, 0x1000, validation)
        with self.assertRaisesRegex(ContainerError, "control flow changed"):
            validate_region_shape(changed, profile, 0x1000, validation)

    def test_switch_identity_normalizes_moved_rvas_but_retains_case_destinations(self):
        def fixture(text_rva, data_rva, base, changed_target=False):
            code = bytearray(b"\x83\xf9\x01\x77\0")
            code += b"\x48\x8d\x15" + struct.pack("<i", -(text_rva + len(code) + 7))
            table_load = len(code)
            code += b"\x8b\x84\x8a\0\0\0\0\x48\x03\xc2\xff\xe0"
            first = len(code)
            code += b"\x31\xc0\xc3"
            second = len(code)
            code += b"\xb8\x01\0\0\0\xc3"
            default = len(code)
            code += b"\x31\xc0\xc3"
            code[4] = default - 5
            struct.pack_into("<I", code, table_load + 3, text_rva + len(code))
            code += struct.pack("<II", text_rva + first, text_rva + (first if changed_target else second))
            raw = bytearray(sample_pe(bytes(code), text_rva=text_rva, data_rva=data_rva, image_base=base))
            struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, data_rva, 12)
            struct.pack_into("<III", raw, 0x400, text_rva, text_rva + len(code), data_rva + 0x80)
            raw[0x480] = 1
            return Image(bytes(raw))
        first = fixture(0x1000, 0x4000, 0x180000000)
        moved = fixture(0x2000, 0x5000, 0x1A0000000)
        altered = fixture(0x2000, 0x5000, 0x1A0000000, True)
        self.assertEqual(region_shape(first, 0x1000), region_shape(moved, 0x2000))
        self.assertNotEqual(region_shape(first, 0x1000), region_shape(altered, 0x2000))

    def test_changed_plaintext_is_reencoded_and_authenticated(self):
        source, plain = sample_container()
        changed = bytearray(plain)
        struct.pack_into("<Q", changed, len(changed) - 8, 6789)
        result = seal_container(bytes(changed), source, nonce_prefix=b"newnonce")
        self.assertEqual(open_container(result).table(2), struct.pack("<Q", 6789))
        self.assertNotEqual(source, result)
        self.assertEqual(open_container(source).plaintext, plain)

    def test_authenticated_round_trip_and_seed_from_payload(self):
        data, plain = sample_container()
        container = open_container(data)
        self.assertEqual(container.plaintext, plain)
        self.assertEqual(container.table(2), struct.pack("<Q", 12345))

    def test_authentication_rejects_changed_ciphertext(self):
        data, _ = sample_container()
        altered = bytearray(data)
        altered[100] ^= 1
        with self.assertRaises(ContainerError):
            open_container(bytes(altered))

    def test_footer_tail_probe_uses_absolute_file_positions(self):
        data, _ = sample_container()
        expected = find_footers(data)
        self.assertEqual(find_footers(data[-40:], base_offset=len(data) - 40), expected)

    def test_truncations_are_refused(self):
        data, _ = sample_container()
        for length in (0, 1, 39, 40, 64, 88, len(data) - 1):
            with self.subTest(length=length), self.assertRaises(ContainerError):
                open_container(data[:length])

    def test_overlapping_or_out_of_bounds_tables_are_refused(self):
        data, plain = sample_container()
        overlap = bytearray(plain)
        struct.pack_into("<3Q", overlap, 8, 0, 8, 0)
        with self.assertRaises(ContainerError):
            parse_tables(bytes(overlap))
        struct.pack_into("<3Q", overlap, 8, len(plain), 8, 0)
        with self.assertRaises(ContainerError):
            parse_tables(bytes(overlap))

    def test_native_records_complement_bytes_and_keep_first_insertion(self):
        data = struct.pack("<IB", 0x1000, 1) + b"\x3c"
        data += struct.pack("<IB", 0x1000, 1) + b"\x6f"
        container = Container(Footer(0, 0, 0), b"", (Table(0, 0, data),))
        rows = instructions(container)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].data, b"\xc3")

    def test_unknown_startup_kind_and_truncated_source_are_refused(self):
        record = bytearray(49)
        struct.pack_into("<3Q", record, 0, 49, 8, 0x1000)
        record[48] = 99
        with self.assertRaises(ContainerError):
            transforms(Container(Footer(0, 0, 0), b"", (Table(3, 0, bytes(record)),)), 3)
        record[48] = 21
        with self.assertRaises(ContainerError):
            transforms(Container(Footer(0, 0, 0), b"", (Table(3, 0, bytes(record)),)), 3)

    def test_xor_recurrence_round_trip_including_tail(self):
        for size in range(34):
            data = bytes(range(size))
            encoded = xor_transform(data, 913, 0x123456789ABCD)
            self.assertEqual(xor_transform(encoded, 913, 0x123456789ABCD), data)


class ImageTests(unittest.TestCase):
    def test_fast_checksum_agrees_with_independent_pefile_calculation(self):
        generator = random.Random(197)
        for size in (0, 1, 2, 3, 511, 512, 100003):
            data = bytearray(sample_pe(b"\xc3") + generator.randbytes(size))
            image = Image(bytes(data))
            offset = image.pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
            struct.pack_into("<I", data, offset, 0xDEADBEEF)
            image = Image(bytes(data))
            self.assertEqual(calculate_checksum(image.data, offset), image.pe.generate_checksum())

    def test_code_section_updates_code_size_and_uses_executable_readonly_flags(self):
        source = Image(sample_pe(b"\xc3"))
        data, evidence = add_code_section(source.data, b".helper", b"\x31\xc0\xc3")
        image = Image(data)
        self.assertEqual(image.pe.OPTIONAL_HEADER.SizeOfCode, source.pe.OPTIONAL_HEADER.SizeOfCode + 0x200)
        self.assertEqual(image.sections[-1].Characteristics, 0x60000020)
        self.assertEqual(evidence["new_executable_code_bytes"], 3)
        self.assertTrue(image.pe.verify_checksum())

    def test_sealed_literal_uses_input_key_pair_and_rip_references(self):
        public, private = nacl.bindings.crypto_box_seed_keypair(bytes(reversed(range(32))))
        ciphertext = nacl.bindings.crypto_box_seal(b".other\0", public)
        for clobber in (False, True):
            code = bytearray()
            for opcode, target in ((b"\x4c\x8d\x0d", 0x4000),
                                   (b"\x48\x8d\x15", 0x4080)):
                code += opcode + struct.pack("<i", target - (0x1000 + len(code) + 7))
            code += b"\x41\xb8" + struct.pack("<I", len(ciphertext) + 1)
            if clobber:
                code += b"\x41\xb1\x00"
            code += b"\xe8" + struct.pack("<i", 0x1100 - (0x1000 + len(code) + 5)) + b"\xc3"
            raw = bytearray(sample_pe(bytes(code)))
            raw[0x400:0x440] = public + private
            raw[0x480:0x480 + len(ciphertext)] = ciphertext
            results = sealed_strings(Image(bytes(raw)), 0x1000, 0x1000 + len(code))
            if clobber:
                self.assertEqual(results, ())
            else:
                self.assertEqual([r.plaintext for r in results], [b".other\0"])

    def test_append_section_preserves_code_and_validates_checksum(self):
        source = sample_pe(b"\xc3")
        result, record = add_readonly_section(source, b".sample", b"example payload")
        parsed = Image(result)
        self.assertEqual(parsed.pe.FILE_HEADER.NumberOfSections, 3)
        self.assertEqual(parsed.read(0x1000, 0x200), Image(source).read(0x1000, 0x200))
        self.assertEqual(parsed.read(int(record["rva"], 16), 15), b"example payload")
        self.assertEqual(record["new_executable_code_bytes"], 0)
        self.assertTrue(parsed.pe.verify_checksum())
        with self.assertRaises(ContainerError):
            add_readonly_section(result, b".sample", b"another payload")

    def test_nonzero_header_padding_is_not_overwritten(self):
        source = bytearray(sample_pe(b"\xc3"))
        image = Image(bytes(source))
        source[image.sections[-1].get_file_offset() + 40] = 1
        with self.assertRaises(ContainerError):
            add_readonly_section(bytes(source), b".sample", b"example payload")

    def test_codec_discovery_survives_rva_imagebase_and_key_changes(self):
        for rva, base, multiplier in [(0x1000, 0x180000000, 0x123456789ABCD),
                                      (0x9000, 0x250000000, 0x87654321FEDCB)]:
            seed = rva + 0x1000
            image = Image(sample_pe(loop(rva, seed, multiplier), text_rva=rva,
                                    image_base=base, data_rva=seed))
            result = discover_xor_codec(image)
            self.assertEqual(result.multiplier, multiplier)
            self.assertEqual(result.seed_rva, seed)
            self.assertEqual(result.evidence_rvas, (rva,))

    def test_missing_or_ambiguous_codec_is_refused(self):
        with self.assertRaises(ContainerError):
            discover_xor_codec(Image(sample_pe(b"\xc3")))
        first = loop(0x1000, 0x4000, 0x123456789ABCD)
        second = loop(0x1000 + len(first), 0x4008, 0xABCDEF1234567)
        with self.assertRaises(ContainerError):
            discover_xor_codec(Image(sample_pe(first + second)))

    def test_truncated_and_overlapping_sections_are_refused(self):
        data = sample_pe(b"\xc3")
        with self.assertRaises(ContainerError):
            Image(data[:-1])
        with self.assertRaises(ContainerError):
            Image(sample_pe(b"\xc3", data_rva=0x1000))

    def test_file_mapping_checks_whole_extent(self):
        image = Image(sample_pe(b"\xc3"))
        with self.assertRaises(ContainerError):
            image.offset(0x11FF, 2)
        with self.assertRaises(ContainerError):
            image.offset(0x4000, 1, executable=True)


class PatchActionTests(unittest.TestCase):
    def test_allocation_discovery_derives_size_layout_and_failure_dependencies(self):
        for size, text, data in ((32, 0x1000, 0x4000), (48, 0x9000, 0xA000)):
            site = discover_allocation_site(sample_allocation(size, text_rva=text, data_rva=data))
            self.assertEqual(site.allocation_size, size)
            self.assertEqual(site.stores_size, size)
            self.assertEqual(site.lock_rva, data + 0x188)
            self.assertEqual(site.result_global, data + 0x180)
            self.assertEqual(site.virtualalloc_iat, data + 0x90)

    def test_allocation_discovery_refuses_size_mismatch_and_bypassed_lock(self):
        for options in ({"wrong_size": True}, {"bypass_lock": True}):
            with self.subTest(options=options), self.assertRaises(ContainerError):
                discover_allocation_site(sample_allocation(32, **options))

    def test_hresult_cancellation_replaces_only_the_complete_call(self):
        for code in (b"\xe8\0\0\0\0", b"\xff\x15\0\0\0\0"):
            image = Image(sample_pe(code))
            patch = fail_hresult_call(image, "test", 0x1000)
            self.assertEqual(patch.after, b"\xb8\x04\x40\0\x80" + b"\x90" * (len(code) - 5))
            with self.assertRaises(ContainerError):
                fail_hresult_call(image, "test", 0x1000, 0)

    def test_formatter_variant_requires_equal_resolved_dependencies(self):
        for different_dependency in (False, True):
            code = bytearray(b"\xcc" * 0x200)
            extents = []
            for offset, tag in ((0x40, 123), (0x80, 456)):
                body = bytearray(b"\xc7\x44\x24\x20" + struct.pack("<I", tag))
                target = 0x41C0 + (8 if different_dependency and offset == 0x80 else 0)
                body += b"\x48\x8d\x05" + struct.pack("<i", target - (0x1000 + offset + len(body) + 7))
                body += b"\xe8" + struct.pack("<i", 0x1180 - (0x1000 + offset + len(body) + 5)) + b"\xc3"
                code[offset:offset + len(body)] = body
                extents.append((0x1000 + offset, 0x1000 + offset + len(body), 0x4050))
            caller = b"\xe8" + struct.pack("<i", 0x1080 - 0x10C5) + b"\x48\x8d\x4c\x24\x30"
            caller += b"\xe8" + struct.pack("<i", 0x1190 - (0x10C0 + len(caller) + 5)) + b"\xc3"
            code[0xC0:0xC0 + len(caller)] = caller
            extents.append((0x10C0, 0x10C0 + len(caller), 0x4050))
            raw = bytearray(sample_pe(bytes(code)))
            struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, 0x4000, 36)
            for index, row in enumerate(extents):
                struct.pack_into("<III", raw, 0x400 + 12 * index, *row)
            raw[0x450] = 1
            if different_dependency:
                with self.assertRaises(ContainerError):
                    discover_formatter_variant(Image(bytes(raw)), 0x1040)
            else:
                patch = discover_formatter_variant(Image(bytes(raw)), 0x1040)
                self.assertEqual(patch.rva, 0x1080)
                self.assertEqual(patch.evidence["variant_tag_from_input"], 456)

    def test_api_context_follows_an_input_iat_tail_thunk(self):
        source = sample_import_functions()
        raw = bytearray(source.data)
        raw[0x200:0x206] = b"\xe8" + struct.pack("<i", 0x11A0 - 0x1005) + b"\x90"
        raw[0x3A0:0x3A6] = b"\xff\x25" + struct.pack("<i", 0x4060 - 0x11A6)
        call, _ = discover_context_call(Image(bytes(raw)), "IsDebuggerPresent", {"RtlCaptureContext"})
        self.assertEqual(call.rva, 0x1000)
        self.assertEqual(call.thunk_rva, 0x11A0)
        self.assertEqual(call.iat_rva, 0x4060)

    def test_response_creators_follow_moved_workers_and_changed_event_values(self):
        for positions, event in (((0x80, 0xC0), 12345), ((0x90, 0xD0), 987654)):
            code = bytearray(b"\xcc" * 0x200)
            owner = bytearray()
            extents = []
            for worker in positions:
                owner += b"\x48\x8d\x05" + struct.pack("<i", worker - (len(owner) + 7))
                owner += b"\x48\x89\x44\x24\x20"
                owner += b"\xe8" + struct.pack("<i", 0x190 - (len(owner) + 5))
                body = bytearray(b"\xb9\x7b\0\0\0")
                for target in (0x170, 0x180):
                    body += b"\xe8" + struct.pack("<i", target - (worker + len(body) + 5))
                loop_start = len(body)
                body += b"\x48\xb9" + struct.pack("<Q", event)
                body += b"\xe8" + struct.pack("<i", 0x160 - (worker + len(body) + 5))
                body += b"\xeb" + struct.pack("b", loop_start - (len(body) + 2))
                code[worker:worker + len(body)] = body
                extents.append((0x1000 + worker, 0x1000 + worker + len(body), 0x4050))
            owner += b"\xc3"
            code[:len(owner)] = owner
            extents.insert(0, (0x1000, 0x1000 + len(owner), 0x4050))
            raw = bytearray(sample_pe(bytes(code)))
            struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, 0x4000, 36)
            for index, row in enumerate(extents):
                struct.pack_into("<III", raw, 0x400 + 12 * index, *row)
            raw[0x450] = 1
            patches = discover_response_creators(Image(bytes(raw)), 0x1160)
            self.assertEqual([p.rva for p in patches], [0x100C, 0x101D])
            self.assertTrue(all(p.after == b"\x90" * 5 for p in patches))

            raw[0x203] ^= 1
            with self.assertRaises(ContainerError):
                discover_response_creators(Image(bytes(raw)), 0x1160)

    def test_export_hash_parameters_come_from_input_instructions(self):
        for seed, multiplier in ((0x811C9DC5, 0x1000193), (13579, 0x100019B)):
            target = folded_hash("SendARP", seed, multiplier)
            code = bytearray(b"\x49\xbe" + struct.pack("<Q", target)
                             + b"\xba" + struct.pack("<I", seed) + b"\x48\x8b\xf2\xbd\xff\0\0\0")
            loop_start = len(code)
            code += bytes.fromhex("410fbe3b48ffcd49ffc3")
            code += bytes.fromhex("8bd74080ef418bca83c9204080ff190f47ca4863c94833ce4869f1")
            code += struct.pack("<I", multiplier) + b"\x48\x85\xed\x75"
            code += struct.pack("b", loop_start - (len(code) + 1))
            code += b"\x49\x3b\xf6\xc3"
            rows = hash_loops(sample_function(bytes(code)), 0x1000, 0x1000 + len(code))
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0].seed, rows[0].multiplier, rows[0].target), (seed, multiplier, target))
            changed = bytes(code).replace(b"\x83\xc9\x20", b"\x83\xc9\x21")
            self.assertEqual(hash_loops(sample_function(changed), 0x1000, 0x1000 + len(changed)), ())
            changed = bytes(code).replace(b"\x49\x3b\xf6", b"\x41\xbe\x01\0\0\0\x49\x3b\xf6")
            self.assertEqual(hash_loops(sample_function(changed), 0x1000, 0x1000 + len(changed)), ())

    def test_chained_unwind_region_is_not_a_callable_entry(self):
        raw = bytearray(sample_pe(b"\x53\x48\x83\xec\x20" + b"\x90" * 11))
        struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, 0x4000, 24)
        root = (0x1000, 0x1005, 0x4050)
        struct.pack_into("<III", raw, 0x400, *root)
        struct.pack_into("<III", raw, 0x40C, 0x1005, 0x1010, 0x4060)
        raw[0x450:0x458] = bytes.fromhex("0105020005320130")
        raw[0x460:0x464] = bytes.fromhex("21000000")
        struct.pack_into("<III", raw, 0x464, *root)
        image = Image(bytes(raw))
        self.assertEqual(function_entry_rva(image, 0x1008), 0x1000)
        self.assertEqual(entry_return(image, "test", 0x1000, "zero").after, b"\x31\xc0\xc3")
        for encoder in (lambda: entry_return(image, "test", 0x1005, "void"),
                        lambda: stall_entry(image, "test", 0x1005)):
            with self.assertRaises(ContainerError):
                encoder()
        struct.pack_into("<III", raw, 0x464, 0x1005, 0x1010, 0x4060)
        with self.assertRaises(ContainerError):
            function_entry_rva(Image(bytes(raw)), 0x1008)

    def test_leaf_return_validates_arguments_and_discarded_status(self):
        for helper_offset in (0x40, 0x80):
            for consume_status in (False, True):
                code = bytearray(b"\x90" * 0x100)
                caller = b"\xe8" + struct.pack("<i", helper_offset - 5)
                caller += b"\x85\xc0" if consume_status else b"\x0f\x31"
                caller += b"\xc3"
                code[:len(caller)] = caller

                leaf = b"\x45\x33\xc0\x45\x33\xc9\xba\x11\0\0\0\x49\x8d\x49\xfe"
                leaf += b"\xe9" + struct.pack("<i", 0xF0 - (helper_offset + len(leaf) + 5))
                code[helper_offset:helper_offset + len(leaf)] = leaf
                raw = bytearray(sample_pe(bytes(code)))
                struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, 0x4000, 12)
                struct.pack_into("<III", raw, 0x400, 0x1000, 0x1000 + len(caller), 0x4050)
                image = Image(bytes(raw))
                if consume_status:
                    with self.assertRaises(ContainerError):
                        thread_hide_leaf_return(image, "test", 0x1000 + helper_offset)
                else:
                    patch = thread_hide_leaf_return(image, "test", 0x1000 + helper_offset)
                    self.assertEqual(patch.after, b"\xc3")
                    self.assertTrue(patch.evidence["return_value_overwritten_by_rdtsc"])

    def test_entry_stall_refuses_mid_function(self):
        image = sample_function(b"\x53\x48\x83\xec\x20\x90\xc3")
        self.assertEqual(stall_entry(image, "test", 0x1000).after, b"\xeb\xfe")
        with self.assertRaises(ContainerError):
            stall_entry(image, "test", 0x1001)

    def test_object_return_retains_input_initialization_and_changed_capacity_field(self):
        for capacity_offset, capacity in ((0x18, 15), (0x28, 31)):
            code = (b"\x45\x33\xff\x0f\x57\xc0\x0f\x11\x01"
                    + b"\x4c\x89\x79\x10\x48\xc7\x41" + bytes([capacity_offset])
                    + struct.pack("<I", capacity) + b"\x90" * 64 + b"\xe8\0\0\0\0\xc3")
            patch = initialized_object_return(sample_function(code), "test", 0x1000)
            initialized = patch.evidence["initialized_bytes_from_input"]
            self.assertEqual([initialized[hex(i)] for i in range(24)], [0] * 24)
            self.assertEqual(initialized[hex(capacity_offset)], capacity)
            self.assertEqual(patch.after[-4:], b"\x48\x8b\xc1\xc3")
            if capacity_offset == 0x28:
                self.assertNotIn("0x18", initialized)

    def test_object_return_refuses_unknown_values_and_insufficient_prefix_space(self):
        for code in (b"\x48\x89\x11" + b"\x90" * 64 + b"\xc3",
                     b"\x31\xc0\x48\x89\x01\xc3"):
            with self.assertRaises(ContainerError):
                initialized_object_return(sample_function(code), "test", 0x1000)

    def test_api_context_selects_call_across_changed_import_and_code_layouts(self):
        for text, data, base in ((0x1000, 0x4000, 0x180000000), (0x9000, 0xA000, 0x250000000)):
            call, evidence = discover_context_call(sample_import_functions(text, data, base),
                                                   "IsDebuggerPresent", {"RtlCaptureContext"})
            self.assertEqual(call.rva, text)
            self.assertEqual(call.iat_rva, data + 0x60)
            self.assertFalse(evidence["saved_instruction_profile_used"])

    def test_api_context_refuses_duplicate_roles_and_embedded_operand_bytes(self):
        for options in ({"duplicate": True}, {"fake_instruction": True}):
            with self.subTest(options=options), self.assertRaises(ContainerError):
                discover_context_call(sample_import_functions(**options), "IsDebuggerPresent", {"RtlCaptureContext"})

    def test_records_must_align_with_independent_function_metadata(self):
        image = sample_function(b"\x48\x8b\xc1\xc3")
        report = validate_restored_boundaries(image, [Instruction(0x1000, b"\x48\x8b\xc1")], [])
        self.assertEqual(report["native_records_on_metadata_instruction_boundaries"], 1)

        with self.assertRaises(ContainerError):
            validate_restored_boundaries(image, [Instruction(0x1001, b"\x8b\xc1")], [])

    def test_profiles_mask_addresses_and_follow_moved_instructions(self):
        source = Image(sample_pe(b"\xe8" + struct.pack("<i", 0x30) + b"\x48\x8b\x05" + struct.pack("<i", 0x3000)))
        signature, mask = instruction_mask(source.read(0x1000, 12), source.base + 0x1000, source)
        self.assertEqual(signature[1:5], bytes(4))
        self.assertEqual(signature[8:12], bytes(4))
        profile = Profile.from_json({"role": "example", "action": "review_only",
                                     "signature": signature.hex(), "mask": mask.hex()})
        moved = Image(sample_pe(b"\x90" * 9 + b"\xe8" + struct.pack("<i", 0x50)
                                + b"\x48\x8b\x05" + struct.pack("<i", -0x200),
                                text_rva=0x9000, data_rva=0xA000, image_base=0x250000000))
        self.assertEqual(discover_profile(moved, profile), 0x9009)
        with self.assertRaises(ContainerError):
            discover_profile(Image(sample_pe(source.read(0x1000, 12) * 2)), profile)

    def test_profiles_reject_saved_masked_operands(self):
        with self.assertRaises(ContainerError):
            Profile.from_json({"role": "example", "action": "review_only",
                               "signature": "e8abcdef12", "mask": "0100000000"})

    def test_named_callable_discovery_survives_layout_base_and_slot_changes(self):
        for text_rva, data_rva, base, slot in [(0x1000, 0x4000, 0x180000000, 0),
                                               (0x9000, 0xA000, 0x250000000, 2)]:
            code = bytearray(b"\xc3" * 0x100)
            code[0x60:0x65] = b"\xe9" + struct.pack("<i", 0xA0 - 0x65)
            raw = bytearray(sample_pe(bytes(code), text_rva=text_rva, data_rva=data_rva, image_base=base))
            name = b".?AVtest_PerformLicenseCheck_Fatal@Security@@\0"
            raw[0x410:0x410 + len(name)] = name
            struct.pack_into("<6I", raw, 0x500, 1, 0, 0, data_rva, data_rva + 0x180, data_rva + 0x100)
            struct.pack_into("<Q", raw, 0x540, base + data_rva + 0x100)
            targets = [text_rva, text_rva + 0x10, text_rva + 0x20]
            targets[slot] = text_rva + 0x60
            for index, target in enumerate(targets):
                struct.pack_into("<Q", raw, 0x548 + 8 * index, base + target)
            patch = discover_fatal_license_thunk(Image(bytes(raw)))
            self.assertEqual(patch.rva, text_rva + 0x60)
            self.assertFalse(patch.evidence["fixed_vtable_slot_used"])

    def test_reserved_identity_uses_the_no_strike_edge_not_the_original_edge(self):
        for target in (0x1020, 0x1030):
            code = bytearray(b"\x90" * 64)
            code[5:12] = b"\x74\xf9\x83\xf8\x0a\x75" + bytes([target - 0x100C])
            patch = skip_reserved_identity_strike(sample_function(bytes(code)), "test", 0x1005)
            self.assertEqual(patch.after, b"\xeb" + bytes([target - 0x1007]))

    def test_debugger_skip_follows_the_discovered_wait_continuation(self):
        for target in (0x1020, 0x1030):
            code = bytearray(b"\x41\xb9\x08\0\0\0\x77" + bytes([target - 0x1008]))
            code += b"\x90" * (target - (0x1000 + len(code)))
            code += b"\x48\x8b\x0d" + struct.pack("<i", 0x4000 - (target + 7))
            code += b"\x33\xd2\xe8\0\0\0\0\x3d\x02\x01\0\0\xc3"
            patch = skip_debugger_detach_transaction(sample_function(bytes(code)), "test", 0x1000)
            self.assertEqual(patch.after, b"\xeb" + bytes([target - 0x1002]))

    def test_short_branch_keeps_each_inputs_destination(self):
        for displacement in (0x20, 0x61):
            image = Image(sample_pe(bytes((0x75, displacement))))
            patch = force_branch(image, "test", 0x1000)
            self.assertEqual(patch.after, bytes((0xEB, displacement)))
            self.assertEqual(patch.evidence["branch_target_rva"], hex(0x1002 + displacement))

    def test_near_branch_accounts_for_shorter_unconditional_encoding(self):
        image = Image(sample_pe(b"\x0f\x85" + struct.pack("<i", 0x100)))
        patch = force_branch(image, "test", 0x1000)
        self.assertEqual(patch.after, b"\xe9" + struct.pack("<i", 0x101) + b"\x90")

    def test_call_suppression_uses_instruction_width(self):
        for code in (b"\xe8\0\0\0\0", b"\xff\x15\0\0\0\0"):
            image = Image(sample_pe(code))
            patch = suppress_call(image, "test", 0x1000, zero_result=True)
            self.assertEqual(patch.after, b"\x31\xc0" + b"\x90" * (len(code) - 2))
            self.assertEqual(Image(apply_plan(image, [patch])).read(0x1000, len(code)), patch.after)
            with self.assertRaises(ContainerError):
                apply_plan(image, [patch, patch])

    def test_mutex_slots_follow_changed_input_fields(self):
        for slots in ((0x80, 0x88), (0xB0, 0xC8)):
            code = bytearray(b"\x4c\x8b\xe9")
            for offset in slots:
                code += b"\xe8" + struct.pack("<i", 0x1100 - (0x1000 + len(code) + 5))
                code += b"\x49\x89\x85" + struct.pack("<i", offset)
            code += b"\xc3"
            raw = bytearray(sample_pe(bytes(code)))
            struct.pack_into("<II", raw, 0x98 + 112 + 3 * 8, 0x4000, 12)
            struct.pack_into("<III", raw, 0x400, 0x1000, 0x1000 + len(code), 0x4050)
            raw[0x450] = 1
            patch = clear_mutex_result_slots(Image(bytes(raw)), "test", 0x1000)
            self.assertEqual(patch.evidence["object_offsets_from_input"], list(slots))
            self.assertEqual(struct.unpack_from("<i", patch.after, 3)[0], slots[0])
            self.assertEqual(struct.unpack_from("<i", patch.after, 14)[0], slots[1])


if __name__ == "__main__":
    unittest.main()
