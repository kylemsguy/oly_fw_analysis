"""Guarded feature-port tests; optional local firmware fixtures never written."""

from dataclasses import replace
from contextlib import redirect_stdout
import io
import itertools
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
                            ("PATCHED36_SHA256", sha256(self.reference)),
                            ("HISTORICAL_PATCHES", PATCHES),
                            ("TARGET_PATCHES", {"36": PATCHES, "37": PATCHES})):
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

    def build(self, target="37", *, features=None, reference=True):
        return feature.build(self.stock36, self.patched36 if reference else None,
                             self.stock37, target, self.out, features=features)

    def test_build37_verifies_history_and_preserves_all_inputs(self):
        result = self.build()
        expected, _ = feature.patch_image(self.source37, self.spec37, PATCHES)
        self.assertEqual((self.out / "E1259999.BIN").read_bytes(), expected)
        self.assertEqual(json.loads((self.out / "manifest.json").read_text()), result)
        self.assertEqual(result["historical_reproduction"]["reconstructed36_sha256"],
                         sha256(self.reference))
        self.assertTrue(result["historical_reproduction"]["reference_file_compared"])
        self.assertTrue(result["historical_reproduction"]["byte_identical"])
        self.assertEqual(result["selected_features"], ["record", "focus"])
        self.assertEqual(result["available_features"], ["record", "focus"])
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

    def test_supplied_reference_verified_before_emission(self):
        self.patched36.write_bytes(self.source36)
        with self.assertRaisesRegex(ValueError, "reference SHA-256"):
            self.build()
        self.assertFalse(self.out.exists())

    def test_reproduction_gate_catches_incomplete_patch_set(self):
        with patch.object(feature, "HISTORICAL_PATCHES", PATCHES[:1]):
            with self.assertRaisesRegex(ValueError, "reproduction"):
                self.build(features=["focus"], reference=False)
        self.assertFalse(self.out.exists())

    def test_optional_reference_uses_full_pinned_history_for_subset(self):
        self.patched36.unlink()
        result = self.build(features=["focus"], reference=False)
        history = result["historical_reproduction"]
        self.assertEqual(history["reconstructed36_sha256"], sha256(self.reference))
        self.assertTrue(history["pinned_hash_verified"])
        self.assertIsNone(history["patched36_path"])
        self.assertFalse(history["reference_file_compared"])
        self.assertIsNone(history["byte_identical"])
        self.assertEqual([p["feature"] for p in result["patches"]], ["focus"])

    def test_pinned_history_hash_is_mandatory_with_or_without_reference(self):
        for reference in (True, False):
            with self.subTest(reference=reference):
                with patch.object(feature, "PATCHED36_SHA256", "0" * 64):
                    with self.assertRaisesRegex(ValueError, "SHA-256"):
                        self.build(features=["record"], reference=reference)
                self.assertFalse(self.out.exists())

    def test_supplied_reference_also_requires_exact_bytes(self):
        bad_reference = self.reference[:-1] + bytes([self.reference[-1] ^ 1])
        self.patched36.write_bytes(bad_reference)
        with patch.object(feature, "sha256",
                          side_effect=lambda data: (sha256(self.reference)
                                                    if data == bad_reference else sha256(data))):
            with self.assertRaisesRegex(ValueError, "exactly match"):
                self.build()
        self.assertFalse(self.out.exists())

    def test_subsets_start_from_stock_for_each_target(self):
        for target, source, spec in (("36", self.source36, self.spec36),
                                      ("37", self.source37, self.spec37)):
            for edit in PATCHES:
                with self.subTest(target=target, feature=edit.feature):
                    self.out = self.work / (target + edit.feature)
                    result = self.build(target, features=[edit.feature], reference=False)
                    expected, _ = feature.patch_image(source, spec, (edit,))
                    self.assertEqual((self.out / "E1259999.BIN").read_bytes(), expected)
                    self.assertEqual(result["selected_features"], [edit.feature])
                    self.assertEqual(result["historical_reproduction"]["reconstructed36_sha256"],
                                     sha256(self.reference))

    def test_catalog_addition_groups_edits_and_keeps_history_independent(self):
        extra = (feature.Patch("burst", 100, b"\x64\x65", b"\x70\x70"),
                 feature.Patch("burst", 110, b"\x6e", b"\xcb"))
        catalog = (*PATCHES, *extra)
        with patch.object(feature, "TARGET_PATCHES", {"36": PATCHES, "37": catalog}):
            default = self.build(reference=False)
            self.assertEqual(default["selected_features"], ["record", "focus", "burst"])
            self.assertEqual(default["historical_reproduction"]["reconstructed36_sha256"],
                             sha256(self.reference))
            self.assertEqual(len(default["patches"]), 4)
            self.assertEqual(feature.resolve_features("36")[1], PATCHES)
            names = ("record", "focus", "burst")
            for size in range(1, 4):
                for selection in itertools.combinations(names, size):
                    self.out = self.work / ("subset-" + "-".join(selection))
                    result = self.build(features=list(reversed(selection)), reference=False)
                    selected_patches = tuple(p for p in catalog if p.feature in selection)
                    expected, _ = feature.patch_image(self.source37, self.spec37, selected_patches)
                    self.assertEqual((self.out / "E1259999.BIN").read_bytes(), expected)
                    self.assertEqual(result["selected_features"], list(selection))
                    self.assertEqual([p["feature"] for p in result["patches"]],
                                     [p.feature for p in selected_patches])

    def test_selection_order_produces_identical_firmware_and_manifest(self):
        first = self.build(features=["focus", "record"])
        first_output = (self.out / "E1259999.BIN").read_bytes()
        self.out = self.work / "second"
        second = self.build(features=["record", "focus"])
        self.assertEqual(first_output, (self.out / "E1259999.BIN").read_bytes())
        self.assertEqual(first, second)

    def test_invalid_selections_fail_before_reads_or_outputs(self):
        extra = feature.Patch("burst", 100, b"\x64", b"\x70")
        with patch.object(feature, "TARGET_PATCHES",
                          {"36": PATCHES, "37": (*PATCHES, extra)}):
            for target, selection, message in (
                ("37", [], "nonempty"), ("37", [""], "unknown"),
                ("37", ["all"], "unknown"), ("37", ["unknown"], "unknown"),
                ("37", ["record", "record"], "duplicate"),
                ("36", ["burst"], "unsupported"), ("37", "record", "sequence"),
            ):
                with self.subTest(selection=selection), patch.object(Path, "read_bytes") as read:
                    with self.assertRaisesRegex(ValueError, message):
                        self.build(target, features=selection)
                    read.assert_not_called()
                    self.assertFalse(self.out.exists())

    def test_cli_repeated_features_accumulate_and_report_canonical_selection(self):
        args = ["em1ii_feature_patch", "--stock36", str(self.stock36),
                "--stock37", str(self.stock37), "--out", str(self.out),
                "--features", "focus", "--features", "record"]
        stdout = io.StringIO()
        with patch.object(sys, "argv", args), redirect_stdout(stdout):
            feature.main()
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["selected_features"], ["record", "focus"])
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertFalse(manifest["historical_reproduction"]["reference_file_compared"])
        self.out = self.work / "duplicate"
        args[args.index("--out") + 1] = str(self.out)
        args[-1] = "focus"
        with patch.object(sys, "argv", args), self.assertRaisesRegex(ValueError, "duplicate"):
            feature.main()
        self.assertFalse(self.out.exists())

    def test_cli_rejects_empty_features(self):
        args = ["em1ii_feature_patch", "--stock36", str(self.stock36),
                "--out", str(self.out), "--features"]
        with patch.object(sys, "argv", args), redirect_stdout(io.StringIO()):
            with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as error:
                feature.main()
        self.assertEqual(error.exception.code, 2)
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
        symlink = self.work / "stock-alias"
        symlink.symlink_to(self.stock36)
        with self.assertRaisesRegex(ValueError, "input"):
            feature.build(self.stock36, None, self.stock37, "37", symlink)
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
    def test_all_seven_combinations_exact_changes_and_canonical_determinism(self):
        source = (ROOT / "oly-firm" / "em1_ii-3.7" / "E1259999.BIN").read_bytes()
        original = parse(source)
        names, _ = feature.resolve_features("37")
        self.assertEqual(names, ("recording-time-limit", "focus-stacking-eligibility",
                                 "pro-capture-l-lens-check"))
        for count in range(1, len(names) + 1):
            for selection in itertools.combinations(names, count):
                with self.subTest(features=selection):
                    selected, edits = feature.resolve_features("37", selection[::-1])
                    self.assertEqual(selected, selection)
                    output, manifest = feature.patch_image(source, feature.STOCK37, edits)
                    verified = parse(output)
                    payload = bytearray(original[0].payload)
                    expected_raw = bytearray(source)
                    expected_changes = []
                    for edit in edits:
                        payload[edit.offset:edit.offset + len(edit.before)] = edit.after
                        for index, (before, after) in enumerate(zip(edit.before, edit.after)):
                            raw = feature.raw_offset(edit.offset + index, original[0].offset + 32)
                            expected_raw[raw] = after ^ 0xff
                            if before != after:
                                expected_changes.append({
                                    "offset": hex(raw), "before": f"{before ^ 0xff:02x}",
                                    "after": f"{after ^ 0xff:02x}",
                                })
                    checksum = -(2 * sum32(original[0].header) + sum32(payload)) & 0xffffffff
                    checksum_offset = original[0].offset + 32 + len(payload) + 28
                    struct.pack_into("<I", expected_raw, checksum_offset, checksum)
                    self.assertEqual(output, expected_raw)
                    self.assertEqual(verified[0].payload, payload)
                    self.assertEqual(verified[0].header, original[0].header)
                    self.assertEqual(verified[0].trailer[:28], original[0].trailer[:28])
                    self.assertEqual(verified[1:], original[1:])
                    self.assertEqual(manifest["encoded_payload_byte_changes"],
                                     sorted(expected_changes, key=lambda c: int(c["offset"], 16)))
                    self.assertEqual([record["feature"] for record in manifest["patches"]],
                                     list(selection))
                    output_hash = sha256(output)
                    del output, verified, payload, expected_raw
                    _, forward_edits = feature.resolve_features("37", selection)
                    repeated, repeated_manifest = feature.patch_image(
                        source, feature.STOCK37, forward_edits)
                    self.assertEqual(sha256(repeated), output_hash)
                    self.assertEqual(repeated_manifest, manifest)
                    del repeated
                    print(f"\nActual-fixture {','.join(selection)} SHA-256: {output_hash}")
        self.assertEqual(sha256(source), feature.STOCK37.source_sha256)

    def test_real_default_builds_and_semantic_audit_without_emitting_firmware(self):
        from em1ii_pro_capture_probe import audit, schema_evidence

        stock36 = ROOT / "oly-firm" / "em1_ii-3.6" / "OLY_E_125_3600_0000_0000.BIN"
        stock37 = ROOT / "oly-firm" / "em1_ii-3.7" / "E1259999.BIN"
        reference = ROOT / "patched_fw" / "e-m1_ii-3.6" / "E1259999.BIN"
        source = stock37.read_bytes()
        main = parse(source)[0].payload
        evidence = audit(main)
        schema = schema_evidence(source, main)
        self.assertEqual(len(evidence["replay_cases"]), 40)
        self.assertEqual(schema["keys"][1156]["name"], "MODE_ZERO_TIME_LAG")
        self.assertEqual(evidence["pro_capture_l"]["value"], 39)
        self.assertEqual(evidence["pro_capture_h"]["value"], 38)
        selected, edits = feature.resolve_features("37")
        verified_edit = next(edit for edit in edits if edit.feature == "pro-capture-l-lens-check")
        self.assertEqual(verified_edit.offset, int(evidence["patch"]["decoded_offset"], 16))
        self.assertEqual(verified_edit.before.hex(), evidence["patch"]["original"])
        self.assertEqual(verified_edit.after.hex(), evidence["patch"]["replacement"])
        expected, _ = feature.patch_image(source, feature.STOCK37, edits)
        expected_hash = sha256(expected)
        del expected, main, source
        out = ROOT / "generated" / "em1ii_feature_port" / ("unit-dry-" + uuid4().hex)
        with patch.object(feature, "write_output") as write:
            manifest = feature.build(stock36, None, stock37, "37", out)
            write.assert_called_once()
            self.assertEqual(write.call_args.args[0], out)
            self.assertEqual(sha256(write.call_args.args[1]), expected_hash)
            self.assertEqual(manifest["selected_features"], list(selected))
            self.assertEqual(manifest["available_features"], list(selected))
            self.assertEqual(manifest["historical_reproduction"]["reconstructed36_sha256"],
                             feature.PATCHED36_SHA256)
            self.assertFalse(manifest["historical_reproduction"]["reference_file_compared"])
            basis = manifest["validation"]["semantic_basis"]
            self.assertIn("tools/em1ii_pro_capture_probe.py", basis)
            self.assertIn("not native execution", basis)
            self.assertIn("modeled lookup/status", basis)
            self.assertIn("null-lookup success path is unchanged", basis)
        self.assertFalse(out.exists())
        with patch.object(feature, "write_output") as write:
            manifest = feature.build(stock36, reference if reference.exists() else None,
                                     None, "36", out)
            write.assert_called_once()
            self.assertEqual(sha256(write.call_args.args[1]), feature.PATCHED36_SHA256)
            self.assertEqual(manifest["selected_features"],
                             list(feature.feature_names(feature.HISTORICAL_PATCHES)))
            self.assertEqual(manifest["historical_reproduction"]["reference_file_compared"],
                             reference.exists())
            self.assertNotIn("em1ii_pro_capture_probe.py",
                             manifest["validation"]["semantic_basis"])
        self.assertFalse(out.exists())
        self.assertEqual(sha256(stock36.read_bytes()), feature.STOCK36.source_sha256)
        self.assertEqual(sha256(stock37.read_bytes()), feature.STOCK37.source_sha256)

    def test_exact_reproduction_and_deterministic37_without_emitting_firmware(self):
        stock36 = (ROOT / "oly-firm" / "em1_ii-3.6" / "OLY_E_125_3600_0000_0000.BIN").read_bytes()
        reference_path = ROOT / "patched_fw" / "e-m1_ii-3.6" / "E1259999.BIN"
        stock37 = (ROOT / "oly-firm" / "em1_ii-3.7" / "E1259999.BIN").read_bytes()
        reproduced, manifest36 = feature.patch_image(stock36, feature.STOCK36,
                                                     feature.HISTORICAL_PATCHES)
        if reference_path.exists():
            reference = reference_path.read_bytes()
            self.assertEqual(sha256(reference), feature.PATCHED36_SHA256)
            self.assertEqual(reproduced, reference)
        self.assertEqual(manifest36["output_sha256"], feature.PATCHED36_SHA256)
        del reproduced
        # Pin this legacy combination even if the 3.7 catalog gains new features.
        first, manifest37 = feature.patch_image(stock37, feature.STOCK37,
                                                feature.HISTORICAL_PATCHES)
        output_hash = sha256(first)
        del first
        second, second_manifest = feature.patch_image(stock37, feature.STOCK37,
                                                      feature.HISTORICAL_PATCHES)
        self.assertEqual(output_hash, sha256(second))
        self.assertEqual(manifest37, second_manifest)
        self.assertEqual(len(manifest37["encoded_payload_byte_changes"]), 10)
        self.assertEqual(output_hash,
                         "26198780bdacf2ec242b130757a141dfef1774c8cd0908cc283f5ac225bc691d")
        self.assertEqual(sha256(stock36), feature.STOCK36.source_sha256)
        self.assertEqual(sha256(stock37), feature.STOCK37.source_sha256)
        print(f"\nActual-fixture deterministic37 SHA-256: {output_hash}")


if __name__ == "__main__":
    unittest.main()
