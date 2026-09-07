import struct
import unittest

from test_static_inputs import sample_pe
from debugger_detach import discover_additional_detach_queries
from patch_actions import Patch
from static_container import ContainerError
from static_image import Image


def fixture(text=0x1000, data=0x4000, base=0x180000000, change=None):
    targets = [text + 0x1E0 + n * 4 for n in range(4)]
    payload = bytearray(b'\xcc' * 0x200)
    extents, query_sites, status_sites = [], [], []
    for owner in (0, 0x100):
        start = text + owner
        code = bytearray(bytes.fromhex('4883ec5848c7442430ffffffffc744244000000000'))
        if owner and change == 'partial_output':
            code += bytes.fromhex('c644243700')
        branches = []
        arguments = [
            '4883c9ffba1e0000004c8d44243041b908000000',
            '488b4c2430ba010000004c8d44244041b904000000',
            '4883c9ff488b542430',
            '488b4c2430',
        ]
        for index, setup in enumerate(arguments):
            if owner and change == 'wrong_class' and index == 0:
                setup = setup.replace('ba1e000000', 'ba1f000000')
            code += bytes.fromhex(setup)
            if index == 0:
                query_sites.append(start + len(code))
            code += b'\xe8' + struct.pack('<i', targets[index] - (start + len(code) + 5))
            code += b'\x85\xc0\x0f\x88\0\0\0\0'
            branches.append(len(code) - 4)
            if owner and change == 'extra_branch' and index == 1:
                code += b'\xeb\x00'
        code += b'\xb0\x01\xeb\x02'
        failure = len(code)
        code += b'\x32\xc0\x48\x83\xc4\x58\xc3'
        for offset in branches:
            struct.pack_into('<i', code, offset, failure - offset - 4)
        if owner and change == 'wrong_failure':
            code[branches[0] - 1] = 0x89
        if owner and change == 'different_failure':
            struct.pack_into('<i', code, branches[1], failure + 2 - branches[1] - 4)
        payload[owner:owner + len(code)] = code
        extents.append((start, start + len(code), data + 0x100))
        status_sites.append(start + failure)
    for target in targets:
        payload[target - text] = 0xC3
    raw = bytearray(sample_pe(bytes(payload), text_rva=text, data_rva=data, image_base=base))
    struct.pack_into('<II', raw, 0x98 + 112 + 3 * 8, data, 24)
    for i, extent in enumerate(extents):
        struct.pack_into('<III', raw, 0x400 + i * 12, *extent)
    raw[0x500] = 1
    known = Patch('known', query_sites[0], b'', b'', {'branch_target_rva': hex(status_sites[0])})
    return Image(bytes(raw)), known, query_sites[1]


class DetachTests(unittest.TestCase):
    def test_input_relationships_survive_moved_code_data_and_image_base(self):
        for layout in [(0x1000, 0x4000, 0x180000000), (0x9000, 0xC000, 0x250000000)]:
            with self.subTest(layout=layout):
                image, known, query = fixture(*layout)
                patches = discover_additional_detach_queries(image, known)
                self.assertEqual(len(patches), 1)
                self.assertEqual(patches[0].rva, query)
                self.assertEqual(patches[0].after, bytes.fromhex('b8220000c0'))
                self.assertFalse(patches[0].evidence['saved_game_address_used'])

    def test_wrong_information_class_is_refused(self):
        image, known, _ = fixture(change='wrong_class')
        with self.assertRaisesRegex(ContainerError, 'query arguments'):
            discover_additional_detach_queries(image, known)

    def test_partial_output_overwrite_invalidates_initialization_proof(self):
        image, known, _ = fixture(change='partial_output')
        with self.assertRaisesRegex(ContainerError, 'initial output'):
            discover_additional_detach_queries(image, known)

    def test_changed_status_test_is_refused(self):
        image, known, _ = fixture(change='wrong_failure')
        with self.assertRaisesRegex(ContainerError, 'signed status'):
            discover_additional_detach_queries(image, known)

    def test_divergent_cleanup_is_refused(self):
        image, known, _ = fixture(change='different_failure')
        with self.assertRaisesRegex(ContainerError, 'share one'):
            discover_additional_detach_queries(image, known)

    def test_extra_control_flow_is_refused(self):
        image, known, _ = fixture(change='extra_branch')
        with self.assertRaisesRegex(ContainerError, 'control-flow edge'):
            discover_additional_detach_queries(image, known)


if __name__ == '__main__':
    unittest.main()
