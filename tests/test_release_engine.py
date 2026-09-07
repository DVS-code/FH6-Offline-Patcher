import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dependencies import dependency_shape, native_identity, null_transfer
from engine import locked_original, publish_directory
from role_validation import region_shape, validate_region_shape
from recognition import Profile
from static_container import ContainerError
from static_image import Image
from test_static_inputs import sample_import_functions, sample_pe
from import_context import import_slots


class DependencyTests(unittest.TestCase):
    def test_repeated_import_queries_do_not_reparse_or_lose_symbols(self):
        image = sample_import_functions()
        with patch.object(image.pe, "parse_data_directories", wraps=image.pe.parse_data_directories) as parse:
            expected = import_slots(image)
            for _ in range(20):
                found = import_slots(image)
                self.assertEqual(found, expected)
                found.clear()
            self.assertEqual(parse.call_count, 1)

    def test_import_dependency_survives_layout_changes_but_rejects_redirected_api(self):
        source = sample_import_functions()
        dependencies = dependency_shape(source, 0x1000)
        moved = sample_import_functions(0x9000, 0xA000, 0x250000000)
        self.assertEqual(dependencies, dependency_shape(moved, 0x9000))
        raw = bytearray(source.data)

        struct.pack_into("<i", raw, source.offset(0x1002, 4), 0x4068 - 0x1006)
        changed = Image(bytes(raw))
        self.assertEqual(region_shape(source, 0x1000), region_shape(changed, 0x1000))
        signature, mask = region_shape(source, 0x1000)
        profile = Profile("test", b"\xff\x15", b"\1\1", "return_zero")
        validation = {"kind": "complete_containing_region", "signature": signature.hex(),
                      "mask": mask.hex(), "dependencies": dependencies}
        with self.assertRaisesRegex(ContainerError, "dependency changed"):
            validate_region_shape(changed, profile, 0x1000, validation)

    def test_multiple_return_leaf_follows_all_edges(self):

        code = b"\x85\xc9\x74\x06\xb8\x01\0\0\0\xc3\x31\xc0\xc3"
        first = native_identity(Image(sample_pe(code)), 0x1000, {})
        moved = native_identity(Image(sample_pe(code, text_rva=0x9000, data_rva=0xA000)), 0x9000, {})
        self.assertEqual(first, moved)
        changed = code[:-3] + b"\x31\xd2\xc3"
        self.assertNotEqual(first, native_identity(Image(sample_pe(changed)), 0x1000, {}))

    def test_null_transfer_requires_proved_register_value(self):
        good = Image(sample_pe(b"\x48\x31\xc0\x48\x89\xc4\xff\xe0"))
        self.assertTrue(null_transfer(good, 0x1000)["noreturn"])
        unknown = Image(sample_pe(b"\x48\x31\xc9\x48\x89\xc4\xff\xe0"))
        self.assertIsNone(null_transfer(unknown, 0x1000))


class PublicationTests(unittest.TestCase):
    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as parent:
            out = Path(parent) / "existing"
            out.mkdir()
            marker = out / "keep.txt"
            marker.write_text("unchanged")
            with self.assertRaises(ContainerError):
                publish_directory(out, {"forzahorizon6.exe": b"new"})
            self.assertEqual(marker.read_text(), "unchanged")
            self.assertEqual(list(Path(parent).iterdir()), [out])

    def test_failed_disk_sync_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as parent:
            out = Path(parent) / "new"
            with patch("engine.os.fsync", side_effect=OSError("disk fault")):
                with self.assertRaisesRegex(OSError, "disk fault"):
                    publish_directory(out, {"forzahorizon6.exe": b"candidate", "report.json": b"{}"})
            self.assertFalse(out.exists())
            self.assertEqual(list(Path(parent).iterdir()), [])

    def test_all_files_publish_together(self):
        with tempfile.TemporaryDirectory() as parent:
            out = Path(parent) / "new"
            files = {"forzahorizon6.exe": b"candidate", "report.json": b"{}"}
            publish_directory(out, files)
            self.assertEqual({p.name: p.read_bytes() for p in out.iterdir()}, files)

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics")
    def test_original_lock_prevents_changes_until_finished(self):
        with tempfile.TemporaryDirectory() as parent:
            original = Path(parent) / "original.bin"
            original.write_bytes(b"original")
            with locked_original(original) as data:
                self.assertEqual(data, b"original")
                with self.assertRaises(OSError):
                    original.write_bytes(b"modified")
                with self.assertRaises(OSError):
                    original.unlink()
            self.assertEqual(original.read_bytes(), b"original")
            original.write_bytes(b"now editable")


if __name__ == "__main__":
    unittest.main()
