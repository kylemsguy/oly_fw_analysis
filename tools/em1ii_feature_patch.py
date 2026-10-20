#!/usr/bin/env python3
"""Build selected E-M1 II features from pinned stock v3.6 or v3.7.

Offline and experimental: static/manual ISA verification only, not native
execution, updater acceptance, camera operation, or safety validation.
"""

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import struct
import sys

from oly_container import DECODE_ORDER, parse, reconstruct, replace_payload, sha256


@dataclass(frozen=True)
class Patch:
    feature: str
    offset: int
    before: bytes
    after: bytes


HISTORICAL_PATCHES = (
    Patch("recording-time-limit", 0x3339B2,
          bytes.fromhex("c809ca0d2ccc06ca052c201c"),
          bytes.fromhex("c804ca0dfccc70707070cbcb")),
    Patch("focus-stacking-eligibility", 0x635A2A,
          bytes.fromhex("c904"), bytes.fromhex("cbcb")),
)
# Preserve the low-level patch_image() default independently of output catalogs.
PATCHES = HISTORICAL_PATCHES
TARGET_PATCHES = {
    "36": HISTORICAL_PATCHES,
    "37": (
        *HISTORICAL_PATCHES,
        # Retarget the dedicated lens-ID rejection to its existing success edge.
        Patch("pro-capture-l-lens-check", 0x63482C,
              bytes.fromhex("c904"), bytes.fromhex("c902")),
    ),
}
PATCHED36_SHA256 = "79a01d8648f1bfbe282047ca16efc46e15c7a33c2024ff874d51bb0f0b446105"


@dataclass(frozen=True)
class BuildSpec:
    build: str
    source_sha256: str
    source_size: int
    main_header: bytes
    main_sha256: str
    block_count: int = 5
    model: bytes = bytes.fromhex("1250")
    runtime_base: int = 0x60021020


STOCK36 = BuildSpec(
    "3600", "5fcd7314d808c06f8c867700e39eaaea4c0f240b86bfab94d4bb484c50ed0c07",
    93050944,
    bytes.fromhex("4f4512500000000000005640c0ff5f0100360000000100000000000000000000"),
    "f462e042fa6743c639e594a11f95cbe07955c9022cfdca8b0a6f64c5697e11b2",
)
STOCK37 = BuildSpec(
    "3700", "691a8a8e90af75b3848b70856a3a49ef24d72394cdfd2766fa37bdfe6325de70",
    93050944,
    bytes.fromhex("4f4512500000000000005640c0ff5f0100370000000100000000000000000000"),
    "0a41fb8e1105751f7817e5664f2edf2a1bdf399f070e91b4e3c84e6943113803",
)


def raw_offset(decoded_offset: int, payload_start: int) -> int:
    """Map one decoded byte through the container's 16-byte permutation."""
    return payload_start + (decoded_offset // 16) * 16 + DECODE_ORDER[decoded_offset % 16]


def patch_image(source: bytes, spec: BuildSpec,
                patches: tuple[Patch, ...] = PATCHES) -> tuple[bytes, dict]:
    if len(source) != spec.source_size or sha256(source) != spec.source_sha256:
        raise ValueError(f"stock {spec.build} size/SHA-256 mismatch (wrong or already modified input)")
    blocks = parse(source)
    if len(blocks) != spec.block_count:
        raise ValueError("unexpected block count")
    main = blocks[0]
    if (any(b.header[2:4] != spec.model for b in blocks)
            or main.header != spec.main_header
            or main.kind != 0x100
            or struct.unpack_from("<H", main.header, 16)[0] != int(spec.build, 16)
            or sha256(main.payload) != spec.main_sha256):
        raise ValueError("unexpected model/build/main metadata or decoded hash")
    if reconstruct(blocks) != source:
        raise ValueError("source reconstruction differs")
    previous_end = 0
    for patch in sorted(patches, key=lambda p: p.offset):
        end = patch.offset + len(patch.before)
        if not patch.before or len(patch.before) != len(patch.after):
            raise ValueError("patch must have nonempty equal-sized preimage/replacement")
        if patch.offset < previous_end:
            raise ValueError("overlapping or negative patch range")
        if end > len(main.payload):
            raise ValueError("patch outside main payload")
        if main.payload[patch.offset:end] != patch.before:
            raise ValueError(f"{patch.feature} preimage mismatch at {patch.offset:#x}")
        previous_end = end

    payload = bytearray(main.payload)
    raw_expected = bytearray(source)
    patch_records = []
    raw_changes = []
    for patch in patches:
        payload[patch.offset:patch.offset + len(patch.before)] = patch.after
        mapping = []
        for i, (before, after) in enumerate(zip(patch.before, patch.after)):
            decoded = patch.offset + i
            raw = raw_offset(decoded, main.offset + 32)
            mapping.append({"decoded_offset": hex(decoded), "raw_offset": hex(raw)})
            if source[raw] != before ^ 0xFF:
                raise ValueError("raw/decoded preimage mapping mismatch")
            raw_expected[raw] = after ^ 0xFF
            if before != after:
                raw_changes.append({"offset": hex(raw), "before": f"{before ^ 0xff:02x}",
                                    "after": f"{after ^ 0xff:02x}"})
        patch_records.append({
            "feature": patch.feature, "block_index": main.index,
            "decoded_offset": hex(patch.offset),
            "runtime_address": hex(spec.runtime_base + patch.offset),
            "before": patch.before.hex(), "after": patch.after.hex(),
            "raw_byte_mapping": mapping,
        })
    patched_main = replace_payload(main, bytes(payload))
    output = reconstruct([patched_main, *blocks[1:]])
    checksum_offset = main.offset + 32 + len(main.payload) + 28
    raw_expected[checksum_offset:checksum_offset + 4] = patched_main.trailer[28:32]
    if output != raw_expected:
        raise ValueError("unexpected encoded changes outside patches/main checksum")
    verified = parse(output)
    if (verified[0].payload != payload or verified[0].header != main.header
            or verified[0].trailer[:28] != main.trailer[:28]
            or verified[1:] != blocks[1:]):
        raise ValueError("unexpected decoded component or metadata changes")
    old_checksum = struct.unpack_from("<I", main.trailer, 28)[0]
    new_checksum = struct.unpack_from("<I", patched_main.trailer, 28)[0]
    manifest = {
        "model_bytes": spec.model.hex(), "main_build": spec.build,
        "source_size": len(source), "source_sha256": sha256(source),
        "output_size": len(output), "output_sha256": sha256(output),
        "main_runtime_base": hex(spec.runtime_base),
        "mapping_note": "Runtime base is independently established; header address is not the code base.",
        "source_blocks": [b.metadata() for b in blocks],
        "output_blocks": [b.metadata() for b in verified],
        "patches": patch_records,
        "encoded_payload_byte_changes": sorted(raw_changes, key=lambda c: int(c["offset"], 16)),
        "main_checksum": {
            "raw_offset": hex(checksum_offset), "before": main.trailer[28:32].hex(),
            "after": patched_main.trailer[28:32].hex(),
            "delta_u32": hex((new_checksum - old_checksum) & 0xFFFFFFFF),
        },
        "validation": {
            "source_roundtrip_identical": True, "output_checksums_valid": True,
            "only_declared_patches_and_main_checksum_changed": True,
            "semantic_basis": "Static manual decoding against Panasonic MN1030/MN103S Instruction Manual, Pub.No.13250-0; multi-anchor v3.7 mapping.",
            "native_execution": "Unavailable; not performed.",
            "camera_testing": "Not performed. No flashing or device access.",
            "limitations": "Experimental. No proof of updater acceptance, bootability, safety, physical lens compatibility, or removal of storage/thermal/other recording limits.",
        },
    }
    return output, manifest


def check_output_directory(out: Path, inputs: tuple[Path, ...]) -> None:
    resolved = out.resolve()
    for source in inputs:
        if resolved == source.resolve() or (out / "E1259999.BIN").resolve() == source.resolve():
            raise ValueError("output must not be an input")
    if out.exists():
        raise ValueError("output directory already exists")


def write_output(out: Path, output: bytes, manifest: dict) -> None:
    out.mkdir(parents=True, exist_ok=False)
    created = []
    try:
        for name, content in (
            ("E1259999.BIN", output),
            ("manifest.json", (json.dumps(manifest, indent=2) + "\n").encode("utf-8")),
        ):
            path = out / name
            with path.open("xb") as stream:
                created.append(path)
                stream.write(content)
    except BaseException:
        for path in created:
            path.unlink()
        out.rmdir()
        raise


def feature_names(patches: tuple[Patch, ...]) -> tuple[str, ...]:
    """Return canonical feature order, grouping all edits of each feature."""
    return tuple(dict.fromkeys(patch.feature for patch in patches))


def resolve_features(target: str, features: Sequence[str] | None = None
                     ) -> tuple[tuple[str, ...], tuple[Patch, ...]]:
    """Validate selection before I/O; catalog order, not request order, wins."""
    if target not in TARGET_PATCHES:
        raise ValueError("target must be 36 or 37")
    catalog = TARGET_PATCHES[target]
    available = feature_names(catalog)
    if features is None:
        selected = available
    else:
        if isinstance(features, str) or not features:
            raise ValueError("features must be a nonempty sequence of feature names")
        known = {edit.feature for patches in TARGET_PATCHES.values() for edit in patches}
        requested = set()
        for name in features:
            if not isinstance(name, str) or not name or name not in known:
                raise ValueError(f"unknown feature: {name!r}")
            if name in requested:
                raise ValueError(f"duplicate feature: {name}")
            if name not in available:
                raise ValueError(f"feature {name!r} is unsupported for target {target}")
            requested.add(name)
        selected = tuple(name for name in available if name in requested)
    patches = tuple(edit for name in selected for edit in catalog if edit.feature == name)
    return selected, patches


def build(stock36: Path, patched36: Path | None, stock37: Path | None,
          target: str, out: Path, *, features: Sequence[str] | None = None) -> dict:
    selected, patches = resolve_features(target, features)
    if target == "37" and stock37 is None:
        raise ValueError("--stock37 is required for target 37")
    inputs = tuple(path for path in (stock36, patched36, stock37) if path is not None)
    check_output_directory(out, inputs)
    reference = None
    if patched36 is not None:
        reference = patched36.read_bytes()
        if sha256(reference) != PATCHED36_SHA256:
            raise ValueError("historical patched36 reference SHA-256 mismatch")
    source36 = stock36.read_bytes()
    reproduced, manifest = patch_image(source36, STOCK36, HISTORICAL_PATCHES)
    reproduced_hash = sha256(reproduced)
    if reproduced_hash != PATCHED36_SHA256:
        raise ValueError("v3.6 reproduction SHA-256 does not match historical patched36")
    if reference is not None and reproduced != reference:
        raise ValueError("v3.6 reproduction does not exactly match historical patched36 reference")
    if target == "37":
        output, manifest = patch_image(stock37.read_bytes(), STOCK37, patches)
    elif patches == HISTORICAL_PATCHES:
        output = reproduced
    else:
        output, manifest = patch_image(source36, STOCK36, patches)
    manifest["historical_reproduction"] = {
        "stock36_path": str(stock36), "stock36_sha256": STOCK36.source_sha256,
        "patched36_path": str(patched36) if patched36 is not None else None,
        "patched36_sha256": PATCHED36_SHA256,
        "reconstructed36_sha256": reproduced_hash, "pinned_hash_verified": True,
        "reference_file_compared": reference is not None,
        "byte_identical": True if reference is not None else None,
        "unrelated_source_patch_changes": [],
    }
    manifest["selected_features"] = list(selected)
    manifest["available_features"] = list(feature_names(TARGET_PATCHES[target]))
    if "pro-capture-l-lens-check" in selected:
        manifest["validation"]["semantic_basis"] += (
            " Pro Capture L: pinned static dispatch and property1406 drive-rule proof"
            " (L39 only; H38 unchanged), plus bounded instruction-scoped replay in"
            " tools/em1ii_pro_capture_probe.py with modeled lookup/status helper returns;"
            " not native execution. The stock null-lookup success path is unchanged;"
            " this is not a missing-lens readiness gate."
        )
    manifest["source_path"] = str(stock37 if target == "37" else stock36)
    manifest["output_filename"] = "E1259999.BIN"
    check_output_directory(out, inputs)
    write_output(out, output, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock36", type=Path, required=True)
    parser.add_argument("--patched36", type=Path,
                        help="optional historical reference; hash and exact bytes verified if supplied")
    parser.add_argument("--stock37", type=Path)
    parser.add_argument("--target", choices=("36", "37"), default="37")
    parser.add_argument("--features", nargs="+", action="extend", metavar="NAME",
                        help="only these features; omission selects all verified features for the target")
    parser.add_argument("--out", type=Path, required=True, help="new output directory (must not exist)")
    args = parser.parse_args()
    manifest = build(args.stock36, args.patched36, args.stock37, args.target, args.out,
                     features=args.features)
    print(json.dumps({"output": str(args.out / "E1259999.BIN"),
                      "sha256": manifest["output_sha256"],
                      "selected_features": manifest["selected_features"],
                      "validation": "static/manual only; no native execution or camera testing"}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(f"error: {exc}")
