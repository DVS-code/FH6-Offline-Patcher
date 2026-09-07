import struct
import unittest

from test_static_inputs import sample_function
from role_validation import region_shape
from static_image import Image
from tls_layout import tls_operands
import capstone as cs


def epoch_function(field=16, *, wrong_index=False, ambiguous=False, middle=b'', scalar=73,
                   initializer=True, guard_branch=b'\x7e\x00', constant=None):
    code = bytearray(b'\x8b\x0d' + struct.pack('<i', (0x40d4 if wrong_index else 0x40d0) - 0x1006))
    code += bytes.fromhex('65488b042558000000')
    code += b'\xba' + struct.pack('<I', field if constant is None else constant)
    code += middle
    code += bytes.fromhex('488b04c8 8b0402')
    code += b'\x39\x05' + struct.pack('<i', 0x40e0 - (0x1000 + len(code) + 6))
    code += guard_branch
    code += b'\x41\xb8' + struct.pack('<I', scalar) + b'\xc3'
    raw = bytearray(sample_function(bytes(code)).data)
    struct.pack_into('<II', raw, 0x98 + 112 + 9 * 8, 0x4080, 40)
    struct.pack_into('<3Q', raw, 0x480, 0x180004100, 0x180004180, 0x1800040d0)
    if initializer:
        struct.pack_into('<I', raw, 0x500 + field, 0x80000000)
    if ambiguous:
        struct.pack_into('<I', raw, 0x500 + 64, 0x80000000)
    return Image(bytes(raw))


class TlsLayoutTests(unittest.TestCase):
    def shape(self, **kwargs):
        return region_shape(epoch_function(**kwargs), 0x1000)

    def test_moved_field_is_derived_from_each_template(self):
        self.assertEqual(self.shape(field=16), self.shape(field=32))
        self.assertEqual(self.shape(field=16)[1][16:20], bytes(4))

    def test_unrelated_scalar_and_unproved_field_changes_remain_visible(self):
        self.assertNotEqual(self.shape(scalar=16), self.shape(field=32, scalar=32))
        self.assertNotEqual(self.shape(), self.shape(constant=32))

    def test_wrong_module_index_does_not_normalize(self):
        self.assertEqual(self.shape(wrong_index=True)[1][16:20], b'\1' * 4)

    def test_field_initial_value_is_preserved_in_identity(self):
        self.assertNotEqual(self.shape(), self.shape(initializer=False))

    def test_clobbered_register_does_not_normalize_and_branch_kind_is_preserved(self):
        for middle in (bytes.fromhex('31d2'), bytes.fromhex('e800010000')):
            self.assertEqual(self.shape(middle=middle)[1][16:20], b'\1' * 4)
        self.assertNotEqual(self.shape(), self.shape(guard_branch=b'\x76\x00'))

    def test_branch_join_requires_agreement(self):

        conflict = bytes.fromhex('4585c0 7402 31d2')
        self.assertEqual(self.shape(middle=conflict)[1][16:20], b'\1' * 4)
        preserved = bytes.fromhex('4585c0 7402 6690')
        self.assertEqual(self.shape(middle=preserved), self.shape(field=32, middle=preserved))
        self.assertEqual(self.shape(middle=preserved)[1][16:20], bytes(4))

    def test_partial_write_invalidates_offset(self):
        self.assertEqual(self.shape(middle=bytes.fromhex('b200'))[1][16:20], b'\1' * 4)

    def test_truncated_tls_array_pointer_does_not_prove_an_address(self):
        self.assertEqual(self.shape(middle=bytes.fromhex('89c0'))[1][16:20], b'\1' * 4)

    def test_out_of_bounds_field_is_not_normalized(self):
        self.assertEqual(self.shape(constant=127)[1][16:20], b'\1' * 4)

    def test_aliases_and_initial_contents_remain_part_of_field_identity(self):
        def identity(first, second):
            image = epoch_function(initializer=False)
            code = bytearray.fromhex('8b0dca300000 65488b042558000000 488b04c8')
            code += b'\xba' + struct.pack('<I', first) + bytes.fromhex('8b1c02')
            code += b'\xba' + struct.pack('<I', second) + bytes.fromhex('8b1c02 c3')
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
            md.detail = True
            spans, descriptor = tls_operands(image, list(md.disasm(code, image.base + 0x1000)), md)
            self.assertEqual(len(spans), 2)
            return descriptor
        self.assertEqual(identity(16, 24), identity(32, 40))
        self.assertNotEqual(identity(16, 24), identity(32, 32))

    def test_tls_store_uses_the_same_address_proof(self):
        image = epoch_function()
        code = bytearray(image.read(0x1000, 27))
        code[-3:] = bytes.fromhex('890c02')
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True
        spans, descriptor = tls_operands(image, list(md.disasm(code, image.base + 0x1000)), md)
        self.assertEqual(spans, [(16, 4)])
        self.assertIn(b'00000080', descriptor)


if __name__ == '__main__':
    unittest.main()
