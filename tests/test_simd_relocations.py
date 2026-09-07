import struct
import unittest
from types import SimpleNamespace

import capstone as cs
from capstone import x86_const as x

from test_static_inputs import sample_pe
from recognition import instruction_mask, displacement_encoding
from static_container import ContainerError
from static_image import Image


class SimdRelocationTests(unittest.TestCase):
    def test_full_rip_displacement_is_removed_for_prefixed_simd_load_and_store(self):
        for opcode in ('660f6f05', '660f7f0d', '660fd405', '660f7005'):
            suffix = b'\x87' if opcode == '660f7005' else b''
            signatures = []
            for displacement in (0x05833EEA, 0x058503FA, -0x123456):
                code = bytes.fromhex(opcode) + struct.pack('<i', displacement) + suffix
                signature, mask = instruction_mask(code, 0x180001000, Image(sample_pe(code)))
                self.assertEqual(mask[4:8], bytes(4))
                self.assertEqual(signature[:4], code[:4])
                self.assertEqual(signature[8:], suffix)
                signatures.append((signature, mask))
            self.assertEqual(signatures[0], signatures[1])
            self.assertEqual(signatures[1], signatures[2])

    def test_register_identity_and_shuffle_control_are_preserved(self):
        def shape(code):
            return instruction_mask(bytes.fromhex(code), 0x180001000, Image(sample_pe(bytes.fromhex(code))))
        original = shape('660f70050000120587')
        self.assertNotEqual(original, shape('660f700d0000120587'))
        self.assertNotEqual(original, shape('660f70050000120586'))

    def test_inconsistent_decoder_displacement_is_refused(self):
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        md.detail = True
        ins = next(md.disasm(bytes.fromhex('660f6f05ea3e8305'), 0x180001000))
        operand = SimpleNamespace(type=x.X86_OP_MEM, mem=SimpleNamespace(base=x.X86_REG_RIP, disp=0))
        fake = SimpleNamespace(operands=[operand], addr_size=8, modrm_offset=ins.modrm_offset,
                               modrm=ins.modrm, disp_offset=ins.disp_offset, size=ins.size, bytes=ins.bytes)
        with self.assertRaisesRegex(ContainerError, 'proved disp32'):
            displacement_encoding(fake)


if __name__ == '__main__':
    unittest.main()
