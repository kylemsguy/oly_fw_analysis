"""Focused control-flow checks for the dedicated stock Pro Capture L gate."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from em1ii_pro_capture_probe import replay


CODE = bytes.fromhex(
    "0800dd3730bdff000492ba00c82000dd2e43bdff00041ca8c816"
    "fad24404f84601f042f8c108f2111da9c9048a018814dfa00c")


class ProCaptureGateTests(unittest.TestCase):
    def test_only_nonzero_lens_identity_rejection_changes(self):
        for identity in (0, 1, 0x100, 0xFFFF):
            with self.subTest(identity=identity):
                stock = replay(CODE, True, 1, identity)
                patched = replay(CODE, True, 1, identity, 2)
                self.assertEqual(stock["result"], int(identity == 0))
                self.assertEqual(patched["result"], 1)
                self.assertEqual(stock["modeled_calls"], patched["modeled_calls"])
                self.assertIn("0x6065584e", patched["trace"])

    def test_retained_status_guard_and_normalization(self):
        for status in (0, 0x10000):
            with self.subTest(status=status):
                stock = replay(CODE, True, status, 1)
                patched = replay(CODE, True, status, 1, 2)
                self.assertEqual(stock, patched)
                self.assertEqual(patched["result"], 0)
                self.assertNotIn("0x6065583c", patched["trace"])
        self.assertEqual(replay(CODE, True, 0x10001, 1, 2)["result"], 1)

    def test_null_lookup_behavior_is_unchanged_not_new_readiness(self):
        stock = replay(CODE, False, 0, 1)
        patched = replay(CODE, False, 0, 1, 2)
        self.assertEqual(stock, patched)
        self.assertEqual(patched["result"], 1)
        self.assertEqual(patched["modeled_calls"], ["0x6022885b"])

    def test_unreviewed_code_or_branch_is_rejected(self):
        changed = bytearray(CODE)
        changed[0] ^= 1
        with self.assertRaises(ValueError):
            replay(changed, True, 1, 1)
        with self.assertRaises(ValueError):
            replay(CODE, True, 1, 1, 0)


if __name__ == "__main__":
    unittest.main()
