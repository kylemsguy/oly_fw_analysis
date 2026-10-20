"""Independent synthetic guards; opt in to local exact fixtures with OM3_ACTUAL_FIXTURES=1."""

import json
import os
from pathlib import Path
import shutil
import struct
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from oly_container import encode, parse, replace_payload, sha256, sum32
from om3_patch_audit import apply_edits, new_output, validate_output, verified_transform
from om3_feature_patch import build_combined, guard_context, verify_allowed_delta


def fixture(count=2):
    parts = []
    for index in range(count):
        header = bytearray(32)
        header[:4] = b'OE\x12\x20'
        struct.pack_into('<IIHHH', header, 8, 0x50000000, 64, 0x1100, 0, index+1)
        payload = bytes(range(64))
        trailer = bytearray(header)
        struct.pack_into('<I', trailer, 28, -(2*sum32(header)+sum32(payload)) & 0xffffffff)
        parts.append(bytes(header)+encode(payload)+bytes(trailer))
    return b''.join(parts)


def edit(offset=36, expected='0405', replacement='cbcb', name='test'):
    return dict(name=name, offset=hex(offset), expected=expected, replacement=replacement)


class TransformTests(unittest.TestCase):
    def test_valid_payload_edit_and_repaired_roundtrip(self):
        blocks = parse(fixture())
        edits = [edit()]
        payloads, rows = apply_edits(blocks, edits, main_only=True)
        verify_allowed_delta(blocks[0].payload, payloads[0], edits, 32)
        updated = replace_payload(blocks[0], payloads[0])
        decoded = parse(updated.header+encode(updated.payload)+updated.trailer)[0]
        self.assertEqual(decoded.payload[4:6], b'\xcb\xcb')
        self.assertEqual(decoded.header, blocks[0].header)
        self.assertEqual(payloads[1], blocks[1].payload)
        self.assertEqual(rows[0]['bytes_changed'], 2)

    def test_bad_preimage_lengths_overlap_and_boundaries(self):
        blocks = parse(fixture())
        cases = [
            [edit(expected='ffff')],
            [edit(replacement='cb')],
            [edit(expected='', replacement='')],
            [edit(), edit(offset=37, expected='0506', name='overlap')],
            [edit(offset=31, expected='0000')],
            [edit(offset=95, expected='3f00')],
            [edit(offset=160, expected='0001')],
            [edit(offset=-1)],
            [edit(), edit(name='test', offset=40, expected='0809')],
            [{'name': 'bad', 'offset': 'no', 'expected': 'xx', 'replacement': 'cb'}],
            [None],
            [],
        ]
        for edits in cases:
            with self.subTest(edits=edits), self.assertRaises(ValueError):
                apply_edits(blocks, edits, main_only=True)

    def test_component_boundary_even_without_main_restriction(self):
        with self.assertRaisesRegex(ValueError, 'one component'):
            apply_edits(parse(fixture()), [edit(offset=95, expected='3f00')])

    def test_complete_delta_check_rejects_unknown_bytes(self):
        before = parse(fixture())[0].payload
        after = bytearray(before)
        after[4:6] = b'\xcb\xcb'
        after[40] ^= 1
        with self.assertRaisesRegex(ValueError, 'Unallowlisted'):
            verify_allowed_delta(before, after, [edit()], 32)
        with self.assertRaises(ValueError):
            verify_allowed_delta(before, after[:-1], [edit()], 32)

    def test_exact_stock_and_manifest_pins_precede_transform(self):
        with self.assertRaisesRegex(ValueError, 'manifest'):
            verified_transform(fixture(), b'{}')
        manifest = json.dumps(dict(original_sha256='wrong')).encode()
        with patch('om3_patch_audit.MANIFEST_SHA', sha256(manifest)):
            with self.assertRaisesRegex(ValueError, 'stock'):
                verified_transform(fixture(), manifest)

    def test_verified_transform_requires_both_release_hashes(self):
        source = fixture(6)
        blocks = parse(source)
        edits = [edit(offset=32+i, expected=f'{i:02x}', replacement='ff', name=f'p{i}')
                 for i in range(35)]
        payload = b'\xff'*35+blocks[0].payload[35:]
        rebuilt = replace_payload(blocks[0], payload)
        encoded = rebuilt.header+encode(payload)+rebuilt.trailer+source[128:]
        decoded = b''.join(b.header+(payload if b.index == 0 else b.payload)+b.trailer
                           for b in blocks)
        for bad in (None, 'encoded_sha256', 'decoded_sha256'):
            manifest = dict(original_sha256=sha256(source), encoded_sha256=sha256(encoded),
                            decoded_sha256=sha256(decoded), patches=edits)
            if bad:
                manifest[bad] = '0'*64
            manifest_bytes = json.dumps(manifest).encode()
            with patch.multiple('om3_patch_audit', STOCK_SHA=sha256(source),
                                MANIFEST_SHA=sha256(manifest_bytes),
                                ENCODED_SHA=manifest['encoded_sha256'],
                                DECODED_SHA=manifest['decoded_sha256']):
                if bad:
                    with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'release hash mismatch'):
                        verified_transform(source, manifest_bytes)
                else:
                    result = verified_transform(source, manifest_bytes)
                    self.assertEqual(result['encoded_sha256'], sha256(encoded))
                    self.assertEqual(result['decoded_sha256'], sha256(decoded))

    def test_truncated_and_corrupt_container_rejected(self):
        for data in (b'', fixture()[:-1], fixture() + b'x'):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                parse(data)
        bad = bytearray(fixture())
        bad[40] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            parse(bad)

    def test_context_failure_and_ambiguous_anchor_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Eligibility'):
            guard_context(b'\0'*64, b'\0'*64)
        payload = b'ABxxAB'
        with patch('om3_feature_patch.ELIGIBILITY', b''), \
             patch('om3_feature_patch.TRACE_SPANS', ()), \
             patch('om3_feature_patch.ANCHORS', ((0, '4142'),)):
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                guard_context(payload, payload)


class OutputTests(unittest.TestCase):
    def setUp(self):
        # Project-local scratch only: never use a system temporary directory.
        self.root = ROOT / 'generated' / ('om3-test-'+uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.source = self.root / 'input.bin'
        self.source.write_bytes(b'original')

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_existing_output_and_input_alias_rejected(self):
        for out in (self.source, self.root, self.source/'child'):
            with self.subTest(out=out), self.assertRaises(ValueError):
                validate_output(out, [self.source])
        with self.assertRaises(ValueError):
            validate_output(self.root/'absent'/'child', [self.source])

    def test_ignored_requirement_and_exclusive_writer(self):
        out = validate_output(self.root/'new', [self.source], ignored=True)
        with new_output(out) as write:
            write('output.bin', b'first')
            with self.assertRaises(FileExistsError):
                write('output.bin', b'second')
        self.assertEqual((out/'output.bin').read_bytes(), b'first')
        with patch('om3_patch_audit.subprocess.run') as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(ValueError, 'git-ignored'):
                validate_output(self.root/'not-ignored', [self.source], ignored=True)

    def test_failure_cleans_only_owned_files(self):
        out = self.root/'failed'
        with self.assertRaises(RuntimeError):
            with new_output(out) as write:
                write('ours', b'a')
                (out/'someone-elses').write_bytes(b'b')
                raise RuntimeError('simulated failure')
        self.assertFalse((out/'ours').exists())
        self.assertEqual((out/'someone-elses').read_bytes(), b'b')
        self.assertEqual(self.source.read_bytes(), b'original')

    def test_failure_leaves_no_empty_output(self):
        out = self.root/'failed'
        with self.assertRaises(RuntimeError):
            with new_output(out) as write:
                write('ours', b'a')
                raise RuntimeError('simulated failure')
        self.assertFalse(out.exists())


@unittest.skipUnless(os.environ.get('OM3_ACTUAL_FIXTURES') == '1',
                     'Set OM3_ACTUAL_FIXTURES=1 for exact local stock/manifest integration')
class ActualFixtureTests(unittest.TestCase):
    def test_exact_combined_build_in_memory(self):
        stock = ROOT/'oly-firm'/'om-3-1.1'/'E1479999.BIN'
        manifest = ROOT/'OM-3 patcher'/'patches'/'om3_pc_remote_v22.json'
        output, report = build_combined(stock.read_bytes(), manifest.read_bytes())
        self.assertEqual(report['output_size'], 240517120)
        self.assertEqual(report['decoded_bytes_changed'], 3557)
        self.assertEqual(report['output_sha256'],
                         '3e6fe11dacd247fc983e7c8857248c22c62f3799bfe57a5a8d80571c783e04d3')
        self.assertTrue(report['baseline_release_hashes_verified_before_composition'])
        self.assertEqual(parse(output)[0].payload[0x8e097e:0x8e0980], b'\xcb\xcb')
        print('\nCombined in-memory SHA-256:', report['output_sha256'])


if __name__ == '__main__':
    unittest.main()
