"""Synthetic read-only evidence checks; exact local firmware is opt-in."""
import os
from pathlib import Path
import shutil
import struct
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import em10ii_historical_diff as evidence
from oly_container import encode, sum32


def component(payload, kind=0x100, version=0x14):
    header = bytearray(32)
    header[:4] = b"OE\x12\x00"
    struct.pack_into("<IIHHH", header, 8, 0x40300000, len(payload), version, 0, kind)
    trailer = bytearray(header)
    struct.pack_into("<I", trailer, 28, -(2 * sum32(header) + sum32(payload)) & 0xFFFFFFFF)
    return bytes(header) + encode(payload) + bytes(trailer)


class DifferenceTests(unittest.TestCase):
    def test_exact_spans_include_both_boundaries_and_separate_clusters(self):
        self.assertEqual(evidence.differences(b"abcdef", b"XbcYZ!"), [
            {"offset": "0x0", "bytes": 1, "stock_hex": "61", "patched_hex": "58"},
            {"offset": "0x3", "bytes": 3, "stock_hex": "646566", "patched_hex": "595a21"},
        ])
        self.assertEqual(evidence.differences(b"same", b"same"), [])
        self.assertEqual(evidence.differences(b"", b""), [])
        with self.assertRaisesRegex(ValueError, "sizes"):
            evidence.differences(b"a", b"")

    def test_container_delta_checksum_metadata_and_unchanged_component(self):
        old = bytes(range(32))
        new = bytearray(old)
        new[7:9] = b"\x91\x92"
        unchanged = component(bytes(16), kind=0x101)
        stock = component(old) + unchanged
        patched = component(new) + unchanged
        report, a, b = evidence.compare_containers(
            stock, patched, {0: evidence.differences(old, new)})
        self.assertTrue(report["both_exact_roundtrips"])
        self.assertTrue(report["all_component_checksums_valid"])
        self.assertTrue(report["all_raw_differences_accounted"])
        self.assertEqual(report["decoded_changed_bytes"], 2)
        self.assertEqual(report["raw_changed_bytes"],
                         sum(x != y for x, y in zip(stock, patched)))
        accounting = report["raw_accounting"]
        self.assertEqual({span["category"] for span in accounting},
                         {"encoded_payload", "trailer_checksum"})
        for span in accounting:
            offset = int(span["offset"], 16)
            self.assertEqual(stock[offset:offset + span["bytes"]].hex(), span["stock_hex"])
            self.assertEqual(patched[offset:offset + span["bytes"]].hex(), span["patched_hex"])
        first, second = report["components"]
        self.assertEqual(first["stock_metadata"]["model_bytes"], "1200")
        self.assertTrue(first["headers_identical"])
        self.assertNotEqual(first["stock_checksum"], first["patched_checksum"])
        self.assertEqual(second["decoded_differences"], [])
        self.assertEqual(second["checksum_differences"], [])
        self.assertEqual(a[1], b[1])

    def test_reject_unexpected_delta_or_manifest_component(self):
        old, new = bytes(32), b"\x01" + bytes(31)
        for manifest in ({}, {0: []}, {1: []}, {-1: []}):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                evidence.compare_containers(component(old), component(new), manifest)

    def test_reject_metadata_even_when_checksums_valid(self):
        for changed in (component(bytes(16), version=0x15),
                        component(bytes(16), kind=0x106)):
            with self.subTest(changed=changed.hex()), self.assertRaisesRegex(ValueError, "metadata"):
                evidence.compare_containers(component(bytes(16)), changed, {})
        with self.assertRaisesRegex(ValueError, "count"):
            evidence.compare_containers(component(bytes(16)),
                                        component(bytes(16)) * 2, {})

    def test_reject_bad_checksum_truncation_and_trailing_data(self):
        valid = component(bytes(32))
        corrupt = bytearray(valid)
        corrupt[-1] ^= 1
        for bad in (bytes(corrupt), valid[:-1], valid + b"trailing", b""):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                evidence.compare_containers(valid, bad, {})

    def test_reject_roundtrip_failure(self):
        valid = component(bytes(16))
        with patch.object(evidence, "reconstruct", return_value=b"wrong"):
            with self.assertRaisesRegex(ValueError, "roundtrip"):
                evidence.compare_containers(valid, valid, {})

    def test_wrong_input_identity_rejected_before_parse(self):
        with patch.object(evidence, "parse") as parse:
            with self.assertRaisesRegex(ValueError, "stock input SHA-256"):
                evidence.analyze(b"wrong", b"wrong")
            parse.assert_not_called()
        # Exercise each hash branch with small data; the CLI pins are unchanged.
        with patch.object(evidence, "SOURCE_SIZE", 5):
            with self.assertRaisesRegex(ValueError, "stock input SHA-256"):
                evidence.analyze(b"wrong", b"wrong")
            with patch.object(evidence, "STOCK_SHA", evidence.sha256(b"stock")):
                with self.assertRaisesRegex(ValueError, "patched input SHA-256"):
                    evidence.analyze(b"stock", b"wrong")


class ListingTests(unittest.TestCase):
    def test_complete_contiguous_bytes_and_instructions(self):
        listing = (
            "header\n6052e52a:\t08          \tclr\td2\n"
            "6052e52b:\tfc cc 10 00 00 70 \tmov\t1879048208,d0\n")
        records = evidence.parse_listing(listing, bytes.fromhex("08fccc10000070"), 0x6052E52A)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["bytes"], "fccc10000070")

    def test_reject_gaps_partial_wrong_bytes_and_data_pseudo_instructions(self):
        for listing in (
            "1001: 08 \tclr d2\n",
            "1000: 08 \tclr d2\n",
            "1000: 09 60 \twrong\n",
            "1000: 08 60 \t.byte 0x08,0x60\n",
            "1000: 08 \tclr d2\n1000: 60 \tmov d0,(a0)\n",
        ):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                evidence.parse_listing(listing, b"\x08\x60", 0x1000)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "generated" / ("em10ii-test-" + uuid.uuid4().hex)

    def tearDown(self):
        if self.path.exists():
            shutil.rmtree(self.path)

    def test_output_requires_new_ignored_directory(self):
        self.assertEqual(evidence.validate_output(self.path), self.path.resolve())
        self.assertFalse(self.path.exists())
        with self.assertRaisesRegex(ValueError, "ignored"):
            evidence.validate_output(ROOT / ("em10ii-not-ignored-" + uuid.uuid4().hex))
        self.path.mkdir(parents=True)
        sentinel = self.path / "report.json"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "already exists"):
            evidence.main(["--stock", "absent-stock", "--patched", "absent-patched",
                           "--out", str(self.path)])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_wrong_input_creates_no_output(self):
        with self.assertRaises(OSError):
            evidence.main(["--stock", "absent-stock", "--patched", "absent-patched",
                           "--out", str(self.path)])
        self.assertFalse(self.path.exists())


@unittest.skipUnless(os.environ.get("EM10II_EXACT_FIXTURES") == "1",
                     "set EM10II_EXACT_FIXTURES=1 for the exact local pair")
class ExactLocalTests(unittest.TestCase):
    def test_hash_pinned_pair_complete_accounting(self):
        stock_path = ROOT / "oly-firm" / "em10_ii-1.4" / "E1209999.BIN"
        patched_path = ROOT / "patched_fw" / "e-m10_ii-1.4" / "e1209999.bin"
        report, stock, patched = evidence.analyze(stock_path.read_bytes(), patched_path.read_bytes())
        self.assertEqual((report["decoded_changed_bytes"], report["raw_changed_bytes"]), (12, 16))
        self.assertEqual(len(report["confirmed_calls"]), 7)
        self.assertEqual(stock[evidence.PATCH_START:evidence.PATCH_START + 12], evidence.BEFORE)
        self.assertEqual(patched[evidence.PATCH_START:evidence.PATCH_START + 12], evidence.AFTER)


if __name__ == "__main__":
    unittest.main()
