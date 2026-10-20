"""Guarded feature-port tests; optional local firmware fixtures never written."""

from dataclasses import replace
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import em1ii_feature_patch as feature
from oly_container import encode, parse, reconstruct, sha256, sum32


PATCHES = (
    feature.Patch("record", 17, bytes(range(17, 20)), b"\xcb\x70\xcb"),
    feature.Patch("focus", 64, bytes(range(64, 66)), b"\xcb\xcb"),
)


def block(payload: bytes, build: int, kind: int = 0x100) -> bytes:
    header = bytearray(32)
    header[:4] = bytes.fromhex("4f451250")
    struct.pack_into("<IIHHH", header, 8, 0x40560000, len(payload), build, 0, kind)
    trailer = bytearray(header)
    struct.pack_into("<I", trailer, 28, -(2 * sum32(header) + sum32(payload)) & 0xFFFFFFFF)
    return bytes(header) + encode(payload) + bytes(trailer)


def fixture(build: int = 0x3600) -> tuple[bytes, feature.BuildSpec]:
    payload = bytes(range(256))
    source = block(payload, build) + block(payload[::-1], 0x100, 0x101)
    return source, feature.BuildSpec(
        f"{build:04x}", sha256(source), len(source), source[:32], sha256(payload),
        block_count=2,
    )


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.source, self.spec = fixture()

    def test_exact_edits_mapping_checksums_and_unrelated_block_preserved(self):
        output, manifest = feature.patch_image(self.source, self.spec, PATCHES)
        original, result = parse(self.source), parse(output)
        expected = bytearray(original[0].payload)
        for edit in PATCHES:
            expected[edit.offset:edit.offset + len(edit.before)] = edit.after
        self.assertEqual(result[0].payload, expected)
        self.assertEqual(result[1:], original[1:])
        self.assertEqual(result[0].header, original[0].header)
        self.assertEqual(result[0].trailer[:28], original[0].trailer[:28])
        self.assertEqual(manifest["output_sha256"], sha256(output))
        declared = {int(c["offset"], 16) for c in manifest["encoded_payload_byte_changes"]}
        checksum = int(manifest["main_checksum"]["raw_offset"], 16)
        declared |= set(range(checksum, checksum + 4))
        changed = {i for i, (a, b) in enumerate(zip(self.source, output)) if a != b}
        self.assertTrue(changed <= declared)
        self.assertEqual(len(manifest["encoded_payload_byte_changes"]), 5)
        for record, edit in zip(manifest["patches"], PATCHES):
            self.assertEqual(record["runtime_address"], hex(self.spec.runtime_base + edit.offset))
            for i, mapping in enumerate(record["raw_byte_mapping"]):
                raw = int(mapping["raw_offset"], 16)
                self.assertEqual(output[raw] ^ 0xff, edit.after[i])
        self.assertIn("not performed", manifest["validation"]["native_execution"])

    def test_reject_wrong_and_already_patched_source(self):
        patched, _ = feature.patch_image(self.source, self.spec, PATCHES)
        for data in (self.source[:-1], self.source + b"x", patched):
            with self.subTest(size=len(data)), self.assertRaisesRegex(ValueError, "SHA-256"):
                feature.patch_image(data, self.spec, PATCHES)

    def test_reject_malformed_even_if_source_hash_pinned(self):
        bad = bytearray(self.source)
        bad[50] ^= 1
        cases = (bytes(bad), self.source[:-1], self.source + b"tail")
        for data in cases:
            spec = replace(self.spec, source_sha256=sha256(data), source_size=len(data))
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                feature.patch_image(data, spec, PATCHES)

    def test_reject_wrong_metadata(self):
        for spec in (
            replace(self.spec, block_count=1),
            replace(self.spec, model=b"\x12\x20"),
            replace(self.spec, build="3700"),
            replace(self.spec, main_header=bytes(32)),
            replace(self.spec, main_sha256="0" * 64),
        ):
            with self.subTest(spec=spec), self.assertRaisesRegex(ValueError, "metadata|count"):
                feature.patch_image(self.source, spec, PATCHES)

    def test_reject_preimage_overlap_and_invalid_ranges(self):
        edits = (
            (replace(PATCHES[0], before=b"bad"),),
            (PATCHES[0], replace(PATCHES[0], offset=18)),
            (replace(PATCHES[0], offset=-1),),
            (replace(PATCHES[0], offset=255),),
            (replace(PATCHES[0], before=b""),),
            (replace(PATCHES[0], after=b"\xcb"),),
        )
        for patches in edits:
            with self.subTest(patches=patches), self.assertRaises(ValueError):
                feature.patch_image(self.source, self.spec, patches)

    def test_reject_unrelated_encoded_mutation(self):
        def bad_reconstruct(blocks):
            output = reconstruct(blocks)
            if blocks[0].payload != parse(self.source)[0].payload:
                output = output[:-1] + bytes([output[-1] ^ 1])
            return output
        with patch.object(feature, "reconstruct", side_effect=bad_reconstruct):
            with self.assertRaisesRegex(ValueError, "unexpected encoded changes"):
                feature.patch_image(self.source, self.spec, PATCHES)

    def test_order_does_not_affect_firmware(self):
        first, _ = feature.patch_image(self.source, self.spec, PATCHES)
        second, _ = feature.patch_image(self.source, self.spec, PATCHES[::-1])
        self.assertEqual(first, second)


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.work = ROOT / "generated" / "em1ii_feature_port" / ("unit-" + uuid4().hex)
        self.work.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.source36, self.spec36 = fixture()
        self.source37, self.spec37 = fixture(0x3700)
        self.reference, _ = feature.patch_image(self.source36, self.spec36, PATCHES)
        self.stock36 = self.work / "stock36.bin"
        self.patched36 = self.work / "patched36.bin"
        self.stock37 = self.work / "stock37.bin"
        for path, data in ((self.stock36, self.source36), (self.patched36, self.reference),
                           (self.stock37, self.source37)):
            path.write_bytes(data)
        self.out = self.work / "output"
        for name, value in (("STOCK36", self.spec36), ("STOCK37", self.spec37),
                            ("PATCHED36_SHA256", sha256(self.reference)), ("PATCHES", PATCHES)):
            self.enterContext(patch.object(feature, name, value))

    def cleanup(self):
        # Only files inside this test's exclusively created directory are removed.
        for child in self.work.iterdir():
            if child.is_dir():
                for file in child.iterdir():
                    file.unlink()
                child.rmdir()
            else:
                child.unlink()
        self.work.rmdir()

    def build(self, target="37"):
        return feature.build(self.stock36, self.patched36, self.stock37, target, self.out)

    def test_build37_verifies_history_and_preserves_all_inputs(self):
        result = self.build()
        expected, _ = feature.patch_image(self.source37, self.spec37, PATCHES)
        self.assertEqual((self.out / "E1259999.BIN").read_bytes(), expected)
        self.assertEqual(json.loads((self.out / "manifest.json").read_text()), result)
        self.assertEqual(result["historical_reproduction"]["reconstructed36_sha256"],
                         sha256(self.reference))
        self.assertEqual(self.stock36.read_bytes(), self.source36)
        self.assertEqual(self.patched36.read_bytes(), self.reference)
        self.assertEqual(self.stock37.read_bytes(), self.source37)
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.build()
        self.assertEqual((self.out / "E1259999.BIN").read_bytes(), expected)

    def test_exact_stock36_reproduction(self):
        result = self.build("36")
        self.assertEqual((self.out / "E1259999.BIN").read_bytes(), self.reference)
        self.assertEqual(result["main_build"], "3600")

    def test_reference_required_and_verified_before_emission(self):
        self.patched36.write_bytes(self.source36)
        with self.assertRaisesRegex(ValueError, "reference SHA-256"):
            self.build()
        self.assertFalse(self.out.exists())

    def test_reproduction_gate_catches_incomplete_patch_set(self):
        with patch.object(feature, "PATCHES", PATCHES[:1]):
            with self.assertRaisesRegex(ValueError, "reproduction"):
                self.build()
        self.assertFalse(self.out.exists())

    def test_invalid_target_source_leaves_no_output(self):
        self.stock37.write_bytes(self.reference)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.build()
        self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(ValueError, "stock37"):
            feature.build(self.stock36, self.patched36, None, "37", self.out)

    def test_reject_input_output_alias_and_existing_directory(self):
        for out in (self.stock36, self.patched36, self.stock37):
            with self.subTest(out=out), self.assertRaisesRegex(ValueError, "input"):
                feature.build(self.stock36, self.patched36, self.stock37, "37", out)
        alias = self.work / "E1259999.BIN"
        alias.write_bytes(self.source37)
        with self.assertRaisesRegex(ValueError, "input"):
            feature.check_output_directory(self.work, (alias,))
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError, "exists"):
            self.build()

    def test_exclusive_writer_does_not_overwrite(self):
        self.out.mkdir()
        existing = self.out / "E1259999.BIN"
        existing.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            feature.write_output(self.out, b"replace", {})
        self.assertEqual(existing.read_bytes(), b"preserve")


@unittest.skipUnless(os.environ.get("EM1II_ACTUAL_FIXTURES") == "1",
                     "set EM1II_ACTUAL_FIXTURES=1 for optional local exact-image checks")
class ActualFixtureTests(unittest.TestCase):
    def test_exact_reproduction_and_deterministic37_without_emitting_firmware(self):
        stock36 = (ROOT / "oly-firm" / "em1_ii-3.6" / "OLY_E_125_3600_0000_0000.BIN").read_bytes()
        reference = (ROOT / "patched_fw" / "e-m1_ii-3.6" / "E1259999.BIN").read_bytes()
        stock37 = (ROOT / "oly-firm" / "em1_ii-3.7" / "E1259999.BIN").read_bytes()
        self.assertEqual(sha256(reference), feature.PATCHED36_SHA256)
        reproduced, manifest36 = feature.patch_image(stock36, feature.STOCK36)
        self.assertEqual(reproduced, reference)
        self.assertEqual(manifest36["output_sha256"], feature.PATCHED36_SHA256)
        del reproduced
        first, manifest37 = feature.patch_image(stock37, feature.STOCK37)
        output_hash = sha256(first)
        del first
        second, second_manifest = feature.patch_image(stock37, feature.STOCK37)
        self.assertEqual(output_hash, sha256(second))
        self.assertEqual(manifest37, second_manifest)
        self.assertEqual(len(manifest37["encoded_payload_byte_changes"]), 10)
        print(f"\nActual-fixture deterministic37 SHA-256: {output_hash}")


if __name__ == "__main__":
    unittest.main()
