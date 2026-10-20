#!/usr/bin/env python3
"""Build independently named OM-3 V22-plus-focus-stacking experimental output.

Offline static experiment only, not physical compatibility or flashing advice.
Only local stock firmware and the locally supplied JSON manifest are read;
no third-party Python is imported or executed. No manifest is redistributed.
"""

import argparse
import json
from pathlib import Path

from oly_container import encode, parse, replace_payload, sha256
from om3_patch_audit import (
    BASE, DECODED_SHA, ENCODED_SHA, MANIFEST_SHA, STOCK_SHA,
    apply_edits, new_output, require, validate_output, verified_transform,
)


NAME = 'OM-3-1.1-V22-plus-focus-stacking-experimental'
STACKING = dict(name='focus_stacking_capability_result_bypass',
                offset='0x8e099e', expected='c904', replacement='cbcb')
ELIGIBILITY = bytes.fromhex(
    '08dde81c9fff000414a8c910ddd4c29fff000414a001c9048a01fca520363fa3'
    'faed0002c811fcdcccc8a3608814ddadb70d00a0188814df8008')
# Independently traced complete stock/V22 spans; payload coordinates, not file offsets.
TRACE_SPANS = (
    ('eligibility', 0x8e0968, 58, 'eea97532a3c608dcb4419c5aeca3643a1a0b2ad8bd26142e94b08dcbbde99b07'),
    ('guard-wrapper', 0x2d2651, 11, '87487460bccf44c9358d705c801731f95989d8dabcab77d8079652810febe991'),
    ('guard', 0x131a9f, 247, 'bf714c817d8be0e3408b795dd0b070a3cbf387d8056d385b43db8fb270831517'),
    ('query', 0x2dcc48, 27, '94089c98d329ea493b3d6ea5e2ebe3b6a95c7b3b35042382987a5842e1f8fd00'),
    ('lookup', 0x2d5440, 66, '15a51147b23f568654d0bf2042e8b107bbb342b0ba1d3930e70d6a7cf12bc5d4'),
    ('alternate-lookup', 0x2d5482, 61, 'd16a8d2bb3a243bdcadb86ac99904d85862500aace3f94b1b9ab618a6135e891'),
    ('unguarded-lookup', 0x2d54e9, 34, '5e0305b87c300931f903989652a4a9a1ad1dcc477f6d1c8b9f572ada70b6ec44'),
    ('status', 0x130b14, 12, 'a27782af02f3eb68974e608b92ac3aab8c4ae9e4a1fc0a6549b2fe6669766382'),
    ('class', 0x2d85d7, 31, 'f5738919a7f8c611c2a85d01eea5e0c37995df4e7e2d03679907005842c827ea'),
    ('flag-wrapper', 0x2d2646, 11, 'e2affac462015de178a6e4758f67cece5c55cf29d08779ec5baa8b90f730f6cf'),
    ('flag', 0x131a95, 10, '111f930a14658c49cae44cf1e786b85c672b67116b4afaf76dd93411c00b1c29'),
    ('lookup-preserved-call', 0x2d2b61, 60, 'c9bb56fba73f149dc5c02c69b7c85f69448ba7ffea78f7002fa6a508ae3ffcb0'),
    ('wrapper', 0x8df92a, 9, 'c69d799e54f4d1b98e60687b6a78f732d736c87a63314b3d24d4bdc2fa2f5ddf'),
    ('consumer', 0x4215bf, 143, '86d4d9ab404ef2424741b713e71fac25c68714cf633383923321a786bebe455b'),
    ('lookup-status-alternate', 0x130afc, 12, '871a6f4b49907bfa6accf34eb93304c64381e7731875eb3b2852e749ef852aaa'),
    ('lookup-mask-test', 0x2d8949, 17, '52575144e29df6c7311e6080fa59ef22138f495c9d40bdb7efdaa2bd3bccc42d'),
    ('lookup-mask-core', 0x2d8882, 52, '8225a7ec1fc3ac44a491a2582cd2a748f43e0d4f614771062511905bf56b85ac'),
    ('lookup-mask-present', 0x2d885c, 22, 'd938e11da20fb98e8ea76edc1283f20f73232622c6e0115aa3ec63585167ddcc'),
    ('lookup-id-test-wrapper', 0x2d26b8, 8, '66b971bd9b5a657783d9ed1e9098acb82897c2c61c1aed1285d8481b4043c504'),
    ('lookup-id-test', 0x2d8d0e, 24, 'e721ed0d64c92adf67fcb10e7c3ae4301719347cd36ccea8da5cdbb533fc54f8'),
    ('lookup-id-pointer', 0x2d861b, 13, '34f5380effb4756eae8cc59208254b2b8f617a1e6b0821c552337b15f8178328'),
    ('logger', 0x9bc143, 41, 'cd19835a09fdb74dd050f22ecf9a3cf7477ef1a50c846a54049e9adaf3098863'),
    ('logger-output', 0x9bc09c, 148, 'c6bb187b8f80ed40477a949971e3ab109d294b73c8dfc321bb8cb586d29ac54d'),
)
ANCHORS = (
    (0x8e096e, '000414a8c910'),
    (0x8e0979, '000414a001c9048a01fca520363fa3faed0002c8'),
    (0x8df92a, 'cd3e10800814df0004'),
    (0x2dcc4e, '00b000c80efc4433d10100a501c904800114df0004'),
)
LIMITS = [
    'Static-experimental composition gate only; no native execution or camera testing.',
    'Earlier guard retained: initial status != 1 rejects. Query and its subcalls still execute.',
    'Query-null false is ignored if reached; earlier guard pointer lifecycle is not proven safe.',
    'No claim of physical lens compatibility, bootability, recovery or hardware safety.',
    'Shared lens/focus services, USB state transitions, concurrency and V22 section residency remain assumptions.',
]


def guard_context(stock_main, v22_main):
    for payload in (stock_main, v22_main):
        require(payload[0x8e0968:0x8e09a2] == ELIGIBILITY, 'Eligibility preimage mismatch')
        for name, start, length, digest in TRACE_SPANS:
            require(sha256(payload[start:start+length]) == digest, f'Trace guard mismatch: {name}')
        for start, hex_bytes in ANCHORS:
            anchor = bytes.fromhex(hex_bytes)
            require(payload[start:start+len(anchor)] == anchor and payload.count(anchor) == 1,
                    'Anchor absent, moved or ambiguous')


def verify_allowed_delta(before, after, edits, origin=0):
    """Compare every byte, not just guarded preimages or a sample of differences."""
    require(len(before) == len(after), 'Unexpected payload length change')
    cursor = 0
    for edit in sorted(edits, key=lambda p: int(p['offset'], 16)):
        start = int(edit['offset'], 16)-origin
        old, new = (bytes.fromhex(edit[k]) for k in ('expected', 'replacement'))
        end = start+len(old)
        require(cursor <= start < end <= len(before) and len(old) == len(new),
                'Delta allowlist overlaps or exceeds payload')
        require(before[cursor:start] == after[cursor:start], 'Unallowlisted payload delta')
        require(before[start:end] == old and after[start:end] == new, 'Allowlisted delta mismatch')
        cursor = end
    require(before[cursor:] == after[cursor:], 'Unallowlisted payload delta')


def build_combined(original, manifest_bytes):
    baseline = verified_transform(original, manifest_bytes)
    blocks = baseline['blocks']
    main = blocks[0]
    v22_main = bytes(baseline['patched'][0])
    guard_context(main.payload, v22_main)
    manifest = json.loads(manifest_bytes)
    edits = manifest['patches'] + [STACKING]
    patched, rows = apply_edits(blocks, edits, main_only=True)
    combined_main = bytes(patched[0])
    verify_allowed_delta(main.payload, combined_main, edits, main.offset+32)
    verify_allowed_delta(v22_main, combined_main, [STACKING], main.offset+32)
    rebuilt = replace_payload(main, combined_main)
    output = bytearray(original)
    start = main.offset+32
    output[start:start+len(combined_main)] = encode(combined_main)
    output[start+len(combined_main):start+len(combined_main)+32] = rebuilt.trailer
    output = bytes(output)
    reparsed = parse(output)
    require(len(reparsed) == len(blocks), 'Component count changed')
    components = []
    for old, new in zip(blocks, reparsed):
        require(old.offset == new.offset and old.header == new.header and
                old.trailer[:28] == new.trailer[:28], 'Component metadata changed')
        require(new.payload == (combined_main if old.index == 0 else old.payload),
                'Unexpected component payload delta')
        end = old.offset+len(old.payload)+64
        if old.index != 0:
            require(output[old.offset:end] == original[old.offset:end], 'Nonmain encoded delta')
        require(output[old.offset+32:end-32] == encode(new.payload), 'Encoded roundtrip mismatch')
        components.append(dict(index=old.index, offset=hex(old.offset), size=len(new.payload),
                               header_identical=True, checksum_valid=True,
                               payload_sha256=sha256(new.payload),
                               trailer_checksum_before=old.trailer[28:].hex(),
                               trailer_checksum_after=new.trailer[28:].hex()))
    report = dict(
        name=NAME, validation_level='static-experimental-only',
        composition_gate='pass-for-experimental-static-in-place-composition',
        stock_sha256=STOCK_SHA, v22_manifest_sha256=MANIFEST_SHA,
        baseline_encoded_sha256=ENCODED_SHA,
        baseline_decoded_original_trailers_sha256=DECODED_SHA,
        baseline_release_hashes_verified_before_composition=True,
        output_sha256=sha256(output), output_size=len(output), output_filename='E1479999.BIN',
        main_analysis_base=hex(BASE), components=components,
        offsets='Decoded container including 32-byte component headers; not encoded offsets.',
        stacking_patch=STACKING, stacking_payload_offset='0x8e097e', stacking_runtime='0x6090199e',
        trace_guards=[dict(name=n, payload_offset=hex(s), length=l, sha256=h)
                      for n, s, l, h in TRACE_SPANS],
        complete_delta_allowlist_verified=True, v22_guard_records=35,
        guarded_bytes=sum(r['bytes_guarded'] for r in rows),
        decoded_bytes_changed=sum(r['bytes_changed'] for r in rows),
        attribution={
            'usb': 'kred: locally supplied OM-3 V22 manifest and patcher. '
                   'Independent repository audit/container implementation; '
                   'container transform reference: Altsoph/mx3 Olympus research. '
                   'No third-party script executed, imported, copied or redistributed.',
            'stacking': 'Independent OM-3 diagnostic, caller, guard and query static trace; '
                        'not a transplant of E-M1 II offsets or no-lens behavior.',
        },
        limitations=LIMITS,
        builder_sha256=sha256(Path(__file__).read_bytes()),
        audit_tool_sha256=sha256(Path(__file__).with_name('om3_patch_audit.py').read_bytes()),
        container_tool_sha256=sha256(Path(__file__).with_name('oly_container.py').read_bytes()),
    )
    return output, report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--stock', type=Path, required=True)
    ap.add_argument('--manifest', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True, help='new git-ignored directory; parent must exist')
    args = ap.parse_args()
    out = validate_output(args.out, [args.stock, args.manifest], ignored=True)
    require(not args.stock.samefile(args.manifest), 'Inputs alias each other')
    output, report = build_combined(args.stock.read_bytes(), args.manifest.read_bytes())
    report.update(stock_source=str(args.stock.resolve()), manifest_source=str(args.manifest.resolve()))
    with new_output(out) as write:
        write('E1479999.BIN', output)
        write('manifest.json', json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(name=NAME, output=str(out), sha256=report['output_sha256']), indent=2))


if __name__ == '__main__':
    main()
