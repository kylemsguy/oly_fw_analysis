#!/usr/bin/env python3
"""Read-only, hash-pinned E-M10 II 1.4 historical comparison (static evidence).

Run with Linux/WSL Python and the repository's GNU 2.45 objdump. Firmware and
decoded components remain in memory; only JSON and bounded listings are saved.
"""
import argparse
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

from oly_container import parse, reconstruct, sha256


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OBJDUMP = ROOT / "toolchains" / "binutils-2.45-build" / "binutils" / "objdump"
SOURCE_SIZE = 69599232
STOCK_SHA = "ff9d302318ecf6e06c0b31c181fc6a185e93623e819749db31cec7977fa92052"
PATCHED_SHA = "cef7a8c1b47a894c7e4538d76f47ccd8d76ad8e637404f7022a2f601c1e2f577"
MAIN_SHAS = (
    "309682c05a96d3079ebcae598169d487fea7f8b2531d8ae99445d63e80ea7a39",
    "2bc4fac76dad4fd4df8eda5b821efef7ea41b837315f04486b323cbb5b007964",
)
OBJDUMP_SHA = "d34c7e54d64e62ce6395560af853d760825eae72303a1686db782a4f064ab743"
BASE = 0x60021000
PATCH_START = 0x50D52B
BEFORE = bytes.fromhex("1ca006c80ca003c808a004c8")
AFTER = bytes.fromhex("fccc1000007060881cdf8008")
WINDOWS = (
    ("function", 0x6052E525, 0x6052E566),
    ("override-wrapper", 0x6052E4FB, 0x6052E525),
    ("direct-consumer", 0x6052CD5A, 0x6052CF1E),
    ("boolean-consumer", 0x6052E15C, 0x6052E1F9),
)
CALLS = (
    (0x6052CEDC, 0x6052E52A, "cd4e168008"),
    (0x6052E51A, 0x6052E52A, "cd10008008"),
    (0x6052CE8A, 0x6052E4FB, "cd7116e010"),
    (0x6052E1A8, 0x6052E4FB, "cd5303e010"),
    (0x6051297F, 0x6052CD5A, "dddba30100f050"),
    (0x6052DB5B, 0x6052E161, "cd0606b020"),
    (0x6054F091, 0x6051295A, "ddc938fcffc01c"),
)


def differences(before, after):
    """Return every maximal contiguous differing span, with no unchanged bytes."""
    if len(before) != len(after):
        raise ValueError("different sizes")
    spans = []
    start = None
    for offset, (a, b) in enumerate(zip(before, after)):
        if a != b and start is None:
            start = offset
        elif a == b and start is not None:
            spans.append((start, offset))
            start = None
    if start is not None:
        spans.append((start, len(before)))
    return [
        {"offset": hex(start), "bytes": stop - start,
         "stock_hex": before[start:stop].hex(), "patched_hex": after[start:stop].hex()}
        for start, stop in spans
    ]


def compare_containers(stock, patched, expected):
    """Validate container integrity, metadata and an exact decoded-delta manifest.

    ``expected`` maps component indices to complete expected span lists. This
    lower-level helper permits small synthetic containers; the CLI never accepts
    alternative identities or manifests.
    """
    a, b = parse(stock), parse(patched)
    if len(a) != len(b) or any(i >= len(a) or i < 0 for i in expected):
        raise ValueError("unexpected component count")
    if reconstruct(a) != stock or reconstruct(b) != patched:
        raise ValueError("inexact container roundtrip")
    components = []
    expected_raw = []
    for x, y in zip(a, b):
        if x.offset != y.offset or x.header != y.header or x.trailer[:28] != y.trailer[:28]:
            raise ValueError(f"unexpected component metadata: {x.index}")
        delta = differences(x.payload, y.payload)
        if delta != expected.get(x.index, []):
            raise ValueError(f"unexpected decoded deltas: {x.index}")
        encoded_start = x.offset + 32
        encoded_stop = encoded_start + len(x.payload)
        encoded_delta = differences(stock[encoded_start:encoded_stop],
                                    patched[encoded_start:encoded_stop])
        checksum_start = encoded_stop + 28
        checksum_delta = differences(x.trailer[28:], y.trailer[28:])
        for category, spans, origin in (
                ("encoded_payload", encoded_delta, encoded_start),
                ("trailer_checksum", checksum_delta, checksum_start)):
            for span in spans:
                expected_raw.append(dict(span, offset=hex(origin + int(span["offset"], 16)),
                                         category=category, component=x.index))
        metadata = []
        for block in (x, y):
            item = block.metadata()
            item.pop("decoded_file")
            item["address_note"] = "container address, not runtime; main runtime base is 0x60021000"
            metadata.append(item)
        components.append({
            "index": x.index,
            "stock_metadata": metadata[0], "patched_metadata": metadata[1],
            "headers_identical": True, "trailer_metadata_identical": True,
            "decoded_differences": delta,
            "decoded_changed_bytes": sum(s["bytes"] for s in delta),
            "encoded_payload_differences": encoded_delta,
            "checksum_differences": checksum_delta,
            "stock_checksum": hex(struct.unpack_from("<I", x.trailer, 28)[0]),
            "patched_checksum": hex(struct.unpack_from("<I", y.trailer, 28)[0]),
        })
    # Compare byte maps, not span boundaries: adjacent regions could coalesce.
    def byte_map(spans):
        result = {}
        for span in spans:
            start = int(span["offset"], 16)
            for i, pair in enumerate(zip(bytes.fromhex(span["stock_hex"]),
                                         bytes.fromhex(span["patched_hex"]))):
                result[start + i] = pair
        return result

    raw = differences(stock, patched)
    if byte_map(raw) != byte_map(expected_raw):
        raise ValueError("unaccounted raw differences")
    return {
        "components": components,
        "raw_differences": raw,
        "raw_accounting": expected_raw,
        "raw_changed_bytes": sum(s["bytes"] for s in raw),
        "raw_payload_changed_bytes": sum(s["bytes"] for s in expected_raw
                                         if s["category"] == "encoded_payload"),
        "raw_checksum_changed_bytes": sum(s["bytes"] for s in expected_raw
                                          if s["category"] == "trailer_checksum"),
        "decoded_changed_bytes": sum(c["decoded_changed_bytes"] for c in components),
        "all_raw_differences_accounted": True,
        "all_component_checksums_valid": True,
        "both_exact_roundtrips": True,
    }, a, b


def analyze(stock, patched):
    for role, data, digest in (("stock", stock, STOCK_SHA), ("patched", patched, PATCHED_SHA)):
        if len(data) != SOURCE_SIZE or sha256(data) != digest:
            raise ValueError(f"requires exact E-M10 II 1.4 {role} input SHA-256 and size")
    expected = {0: [{"offset": hex(PATCH_START), "bytes": len(BEFORE),
                     "stock_hex": BEFORE.hex(), "patched_hex": AFTER.hex()}]}
    report, a, b = compare_containers(stock, patched, expected)
    if len(a) != 3 or [x.kind for x in a] != [0x100, 0x101, 0x106]:
        raise ValueError("unexpected E-M10 component layout")
    for block, digest in zip((a[0], b[0]), MAIN_SHAS):
        if sha256(block.payload) != digest:
            raise ValueError("unexpected decoded main SHA-256")
    if (a[0].header[2:4] != bytes.fromhex("1200")
            or struct.unpack_from("<H", a[0].header, 16)[0] != 0x1400):
        raise ValueError("unexpected model/version")
    if (report["raw_changed_bytes"] != 16
            or report["components"][0]["stock_checksum"] != "0xaf0a5a81"
            or report["components"][0]["patched_checksum"] != "0xc8d17746"):
        raise ValueError("unexpected checksum/raw difference accounting")
    diagnostic_pointer = a[0].payload[0x50D551:0x50D557]
    if (diagnostic_pointer[:2] != b"\xfc\xcd"
            or int.from_bytes(diagnostic_pointer[2:], "little") != BASE + 0x50D545):
        raise ValueError("unexpected diagnostic self-pointer mapping")
    report["confirmed_calls"] = []
    for site, target, encoding in CALLS:
        code = bytes.fromhex(encoding)
        width = 2 if code[0] == 0xCD else 4
        computed = site + int.from_bytes(code[1:1 + width], "little", signed=True)
        if computed != target or a[0].payload[site - BASE:site - BASE + len(code)] != code:
            raise ValueError("unexpected call encoding/target")
        report["confirmed_calls"].append({
            "site": hex(site), "target": hex(target), "bytes": encoding,
            "mask": hex(code[-2]), "frame_bytes": code[-1],
            "validation": "exact bytes and signed PC-relative destination; alignment from prior static trace",
        })
    report.update({
        "scope": "Static evidence only; no firmware execution, emulator model or camera tests",
        "analysis_base": hex(BASE),
        "mapping_evidence": "Independent E-M10 pointer/diagnostic/call trace; not PEN-F's 0x60021020 base",
        "mapping_consistency_check": {
            "decoded_instruction": "0x50d551", "bytes": diagnostic_pointer.hex(),
            "diagnostic_pointer": "0x6052e545", "diagnostic_decoded_offset": "0x50d545",
            "pointer_minus_decoded_offset": hex(BASE),
            "qualification": "self-pointer consistency check corroborates prior independent mapping trace",
        },
        "function_decoded_range": ["0x50d525", "0x50d566"],
        "patch_decoded_range": ["0x50d52b", "0x50d537"],
        "native_execution": {"performed": False,
                             "blocker": "Pinned GNU simulator source archive SHA-256 mismatch; not bypassed"},
        "modified_update_created": False,
        "decoded_components_written_to_disk": False,
        "static_findings_provenance": "Instruction-aligned E-M10 trace; reproduced bounded listings and exact call bytes below",
        "static_findings": {
            "classification": "validated mode selector replaced with unconditional u32 output and success",
            "stock": {"mode_normalization": "low16", "accepted_modes": {"3": 1740, "6": 1740, "4": 7200},
                      "success_return": 0, "other_modes_return": "0x9d06",
                      "other_modes": "diagnostic call; no local output store"},
            "patched": {"all_modes_u32_output": "0x70000010", "return": 0,
                        "output_bytes_le": "10000070", "invalid_modes_also_store": True,
                        "unreachable_from_normal_entries": ["0x6052e537", "0x6052e566"],
                        "dead_residual_note": "linear decoding after early RET is not executed on normal entry"},
            "abi": {"explicit_entry": "0x6052e525", "call_entry": "0x6052e52a",
                    "saved_register": "D2", "mask": "0x80", "frame_bytes": 8,
                    "output_pointer": "A0, unchecked", "mode_and_status": "D0",
                    "flags_equivalence_proven": False},
            "override_wrapper": "0x6052e4fb: state+351==1 writes u8[state+350] as u32 and returns 0; otherwise selector; unchanged",
            "direct_consumer": {
                "entry": "0x6052cd5a", "expression": "min(floor(u32 / 600), selector_limit), unsigned",
                "maximum_quotient": 7158278, "patched_limit": 1879048208,
                "patched_cap_nonbinding": True, "minimum_store": "0xa1c2eed8",
                "conditional_copy": "0xa1c2eed4",
                "qualification": "selector status checked; earlier validations and other gates retained"},
            "boolean_consumer": "0x6052e161 uses wrapper result via device-specific UDF01; outer gate can return 0x9d14",
        },
        "limitations": [
            "Static deductions, not measured execution or camera behavior.",
            "Mode labels and physical units/timebase unresolved; no unlimited-recording claim.",
            "UDF01/UDFU01 device-specific semantics unresolved.",
            "No proof of all callers, indirect entry paths, pointer validity, fault behavior or all stopping conditions.",
            "Patched invalid modes newly dereference A0; stock invalid path does not locally store.",
        ],
    })
    return report, a[0].payload, b[0].payload


def parse_listing(text, expected, start):
    """Require contiguous instruction addresses and exact complete byte coverage."""
    records = []
    cursor = start
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)(\S.*)$", line)
        if not match:
            continue
        address = int(match[1], 16)
        code = bytes.fromhex(match[2])
        instruction = match[3].strip()
        if address != cursor or instruction.startswith((".byte", ".short", "(bad)")):
            raise ValueError("disassembly has a gap, overlap or undecoded instruction")
        if code != expected[cursor - start:cursor - start + len(code)]:
            raise ValueError("disassembly bytes differ from input")
        records.append({"runtime": hex(address), "bytes": code.hex(), "instruction": instruction})
        cursor += len(code)
    if cursor != start + len(expected):
        raise ValueError("incomplete disassembly byte coverage")
    return records


def disassemble(payload, objdump, start, stop):
    if not hasattr(os, "memfd_create"):
        raise ValueError("Linux/WSL Python with memfd_create required; no decoded files are written")
    fd = os.memfd_create("em10-main", flags=0)
    try:
        with os.fdopen(fd, "wb", closefd=False) as memory:
            memory.write(payload)
        command = [str(objdump), "-b", "binary", "-m", "mn10300", "-D", "-z",
                   "--insn-width=16", f"--adjust-vma={BASE:#x}",
                   f"--start-address={start:#x}", f"--stop-address={stop:#x}",
                   f"/proc/self/fd/{fd}"]
        result = subprocess.run(command, capture_output=True, text=True, check=True,
                                pass_fds=(fd,), timeout=60)
        records = parse_listing(result.stdout, payload[start - BASE:stop - BASE], start)
        return result.stdout, {
            "command": command, "input_transport": "anonymous memory descriptor, no decoded disk file",
            "returncode": result.returncode, "stderr": result.stderr,
            "stdout_sha256": sha256(result.stdout.encode()),
            "complete_byte_coverage": True, "instructions": records,
        }
    finally:
        os.close(fd)


def validate_output(out):
    out = out.resolve()
    if out.exists():
        raise ValueError("output directory must be new (already exists)")
    if not out.is_relative_to(ROOT):
        raise ValueError("output directory must be inside the repository and ignored")
    ignored = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--quiet",
                              str(out / "report.json")], capture_output=True, check=False)
    if ignored.returncode != 0:
        raise ValueError("output directory must be git-ignored")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--patched", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--objdump", type=Path, default=DEFAULT_OBJDUMP)
    args = parser.parse_args(argv)
    out = validate_output(args.out)
    report, stock, patched = analyze(args.stock.read_bytes(), args.patched.read_bytes())
    objdump = args.objdump.resolve()
    if sha256(objdump.read_bytes()) != OBJDUMP_SHA:
        raise ValueError("requires the verified GNU 2.45 objdump SHA-256")
    version = subprocess.run([str(objdump), "--version"], capture_output=True,
                             text=True, check=True, timeout=30)
    report["objdump"] = {"path": str(objdump), "sha256": OBJDUMP_SHA,
                         "version_command": [str(objdump), "--version"],
                         "version_stdout": version.stdout, "version_stderr": version.stderr,
                         "version_returncode": version.returncode}
    report["sources"] = {
        role: {"path": str(path.resolve()), "sha256": digest, "size": SOURCE_SIZE,
               "decoded_main_sha256": MAIN_SHAS[index]}
        for index, (role, path, digest) in enumerate((
            ("stock", args.stock, STOCK_SHA), ("patched", args.patched, PATCHED_SHA)))
    }
    listings = {}
    report["disassembly"] = {}
    for role, payload in (("stock", stock), ("patched", patched)):
        for label, start, stop in WINDOWS:
            filename = f"{role}-{label}.asm"
            text, evidence = disassemble(payload, objdump, start, stop)
            listings[filename] = text
            report["disassembly"][filename] = dict(evidence, start=hex(start), stop_exclusive=hex(stop))
    # Reserve output only after all validations; never overwrite an existing path.
    out.mkdir(parents=True, exist_ok=False)
    for filename, text in listings.items():
        (out / filename).write_text(text, encoding="utf-8")
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(out / "report.json"),
                      "decoded_changed_bytes": report["decoded_changed_bytes"],
                      "raw_changed_bytes": report["raw_changed_bytes"],
                      "disassembly_listings": len(listings), "native_execution": False}))
    return report


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        sys.exit(f"error: {exc}")
