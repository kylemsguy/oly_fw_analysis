#!/usr/bin/env python3
"""Independently audit the supplied OM-3 V22 manifest, without executing its code.

Reads stock firmware and JSON only. Reconstructs encoded/decoded release hashes
in memory, exports a decoded main component for disassembly, and never writes
an installable update package. Run from the workspace root.
"""

import argparse
import hashlib
import json
from pathlib import Path
from contextlib import contextmanager
import os
import struct
import subprocess

from oly_container import Block, encode, parse, replace_payload, sha256, sum32


BASE = 0x60021020
STOCK_SHA = '8c133084414533159f587bf46bfb4152714c4074312a47c8d8503e33d605696d'
MANIFEST_SHA = '8f520edb97995c7b5de3b43da725b33bff9a5f1ddb52d31d439a01609369505e'
ENCODED_SHA = '6b58d1b4fc832142f9fe6ffa43c3d28c05a90517e48cdf7db938a3bdff3a7bbf'
DECODED_SHA = '7b0d1e9794b85af8bab0132983251d91649d558564d0b1675739e2120cb48bcd'
DEFAULT_MANIFEST = Path('research/om3_patcher_20260929/extracted/OM-3 patcher/patches/om3_pc_remote_v22.json')
DEFAULT_STOCK = Path('firmware_archive/reference/OM-3/1.1/OLY_E_147_1100_0000_0000.BIN')
OBJDUMP = Path('toolchains/binutils-2.45-build/binutils/objdump')


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_output(out, inputs, ignored=False):
    require(not Path(out).is_symlink(), 'Output must not be a symlink')
    out = Path(out).resolve()
    require(not out.exists(), 'Use a new output directory')
    require(out.parent.is_dir(), 'Output parent must already exist')
    for source in inputs:
        source = Path(source).resolve(strict=True)
        require(out != source and source not in out.parents,
                'Output aliases an input')
        require(out != source.parent, 'Output must be separate from input directory')
    require(os.access(out.parent, os.W_OK), 'Output parent is not writable')
    if ignored:
        result = subprocess.run(['git', 'check-ignore', '--quiet', '--', str(out)],
                                capture_output=True)
        require(result.returncode == 0, 'Output directory must be git-ignored')
    return out


@contextmanager
def new_output(out):
    """Exclusive directory creation; clean only paths created by this writer."""
    out.mkdir(exist_ok=False)
    owned = []
    children = []

    def write(relative, data):
        path = out / relative
        require(path.parent == out, 'Output filenames must be direct children')
        with path.open('xb') as stream:
            owned.append(path)
            stream.write(data if isinstance(data, bytes) else data.encode('utf-8'))
    write.children = children
    write.owned = owned
    try:
        yield write
    except BaseException:
        for child, paths in reversed(children):
            for path in reversed(paths):
                path.unlink(missing_ok=True)
            try:
                child.rmdir()
            except OSError:
                pass
        for path in reversed(owned):
            path.unlink(missing_ok=True)
        try:
            out.rmdir()
        except OSError:
            pass
        raise


def apply_edits(blocks, edits, main_only=False):
    """Validate decoded-container edits before changing any payload."""
    require(isinstance(edits, list) and edits, 'Expected nonempty edit list')
    normalized = []
    names = set()
    for patch in edits:
        require(isinstance(patch, dict), 'Invalid edit record')
        try:
            name = patch['name']
            offset = int(patch['offset'], 16)
            before, after = (bytes.fromhex(patch[k]) for k in ('expected', 'replacement'))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError('Malformed edit') from exc
        require(isinstance(name, str) and name and name not in names, 'Invalid/duplicate edit name')
        names.add(name)
        require(before and len(before) == len(after), 'Invalid edit length')
        normalized.append((offset, before, after, patch))
    normalized.sort(key=lambda item: item[0])
    last_end = 0
    rows = []
    patched = {b.index: bytearray(b.payload) for b in blocks}
    for offset, before, after, patch in normalized:
        require(offset >= last_end, 'Overlapping edits')
        last_end = offset + len(before)
        owners = [b for b in blocks if b.offset+32 <= offset and last_end <= b.offset+32+len(b.payload)]
        require(len(owners) == 1, 'Edit outside one component payload')
        block, = owners
        require(not main_only or block.index == 0, 'Edit outside main component')
        local = offset-block.offset-32
        require(block.payload[local:local+len(before)] == before, f"Guard mismatch: {patch['name']}")
        patched[block.index][local:local+len(before)] = after
        changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
        row = dict(name=patch['name'], decoded_container_offset=hex(offset),
                   component_index=block.index, component_kind=hex(block.kind),
                   payload_offset=hex(local), bytes_guarded=len(before), bytes_changed=len(changed),
                   expected_all_ff=all(v == 255 for v in before),
                   expected=before.hex(), replacement=after.hex(),
                   changed_ranges=spans([offset+i for i in changed]))
        if block.index == 0:
            row['analysis_address'] = hex(BASE+local)
            for label, data in [('original', before), ('patched', after)]:
                if data[0] in (0xcc, 0xcd, 0xdc, 0xdd):
                    n = 2 if data[0] in (0xcc, 0xcd) else 4
                    if len(data) >= n+1:
                        row[f'{label}_initial_relative_target'] = hex(
                            BASE+local+int.from_bytes(data[1:1+n], 'little', signed=True))
        rows.append(row)
    return patched, rows


def spans(offsets):
    result = []
    for offset in offsets:
        if result and offset == result[-1][1]:
            result[-1][1] += 1
        else:
            result.append([offset, offset + 1])
    return [{'start': hex(a), 'end_exclusive': hex(b), 'bytes': b-a} for a, b in result]


def disassemble(image, start, end):
    return subprocess.check_output([
        str(OBJDUMP.resolve()), '-b', 'binary', '-m', 'mn10300', '-D', '-z',
        '--insn-width=16', f'--adjust-vma={BASE:#x}',
        f'--start-address={start:#x}', f'--stop-address={end:#x}', str(image)
    ], text=True)


def verified_transform(original, manifest_bytes):
    """Reproduce the pinned V22 baseline, returning reusable validated payloads."""
    require(sha256(manifest_bytes) == MANIFEST_SHA, 'Unexpected manifest')
    manifest = json.loads(manifest_bytes)
    require(sha256(original) == STOCK_SHA == manifest['original_sha256'], 'Unexpected stock')
    require(manifest['encoded_sha256'] == ENCODED_SHA and
            manifest['decoded_sha256'] == DECODED_SHA, 'Unexpected release identities')
    blocks = parse(original)
    require(len(blocks) == 6, 'Unexpected component count')
    patched, rows = apply_edits(blocks, manifest['patches'], main_only=True)
    require(len(rows) == 35, 'Unexpected edit count')

    encoded_hash, decoded_hash, repaired_decoded_hash = (hashlib.sha256() for _ in range(3))
    components = []
    for block in blocks:
        payload = bytes(patched[block.index])
        rebuilt = replace_payload(block, payload)
        encoded = encode(payload)
        stock_encoded = original[block.offset+32:block.offset+32+len(payload)]
        encoded_changed = sum(a != b for a, b in zip(encoded, stock_encoded)) if payload != block.payload else 0
        trailer_changed = sum(a != b for a, b in zip(rebuilt.trailer, block.trailer))
        for chunk in (block.header, encoded, rebuilt.trailer):
            encoded_hash.update(chunk)
        # The supplied builder leaves ORIGINAL checksum words in decoded output.
        for chunk in (block.header, payload, block.trailer):
            decoded_hash.update(chunk)
        for chunk in (block.header, payload, rebuilt.trailer):
            repaired_decoded_hash.update(chunk)
        require((sum32(rebuilt.header)+sum32(payload)+sum32(rebuilt.trailer)) & 0xffffffff == 0,
                'Independent rebuilt checksum failed')
        require(parse(rebuilt.header+encoded+rebuilt.trailer)[0].payload == payload,
                'Independent final decode failed')
        require(encode(block.payload) == stock_encoded, 'Stock codec roundtrip failed')
        components.append(dict(index=block.index, kind=hex(block.kind),
                               payload_size=len(payload),
                               stock_payload_sha256=sha256(block.payload),
                               patched_payload_sha256=sha256(payload),
                               payload_changed=payload != block.payload,
                               encoded_payload_changed_bytes=encoded_changed,
                               trailer_changed_bytes=trailer_changed,
                               header_identical=block.header == rebuilt.header,
                               trailer_metadata_identical=block.trailer[:28] == rebuilt.trailer[:28],
                               old_checksum=hex(struct.unpack_from('<I', block.trailer, 28)[0]),
                               new_checksum=hex(struct.unpack_from('<I', rebuilt.trailer, 28)[0]),
                               final_checksum_valid=True))
    require(encoded_hash.hexdigest() == manifest['encoded_sha256'], 'Encoded release hash mismatch')
    require(decoded_hash.hexdigest() == manifest['decoded_sha256'], 'Decoded release hash mismatch')
    return dict(blocks=blocks, patched=patched, rows=rows, components=components,
                encoded_sha256=encoded_hash.hexdigest(), decoded_sha256=decoded_hash.hexdigest(),
                repaired_decoded_sha256=repaired_decoded_hash.hexdigest())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument('--stock', type=Path, default=DEFAULT_STOCK)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--skip-disassembly', action='store_true')
    args = ap.parse_args()
    args.out = validate_output(args.out, [args.stock, args.manifest])
    if not args.skip_disassembly:
        require(OBJDUMP.is_file(), 'Missing GNU objdump; use --skip-disassembly for hash-only audit')
        subprocess.run([str(OBJDUMP.resolve()), '--version'], check=True, capture_output=True)
    result = verified_transform(args.stock.read_bytes(), args.manifest.read_bytes())
    blocks, patched, rows, components = (result[k] for k in ('blocks', 'patched', 'rows', 'components'))

    # Merge adjacent injected ranges into physical regions, preserving FF holes.
    caves = []
    for row in rows:
        if not row['expected_all_ff']:
            continue
        start = int(row['analysis_address'], 16); end = start+row['bytes_guarded']
        if caves and caves[-1]['end'] == start:
            caves[-1]['end'] = end
            caves[-1]['patches'].append(row['name'])
            caves[-1]['changed_bytes'] += row['bytes_changed']
        else:
            caves.append(dict(start=start, end=end, patches=[row['name']], changed_bytes=row['bytes_changed']))
    for cave in caves:
        cave['span_bytes'] = cave['end']-cave['start']
        cave['start'], cave['end_exclusive'] = hex(cave['start']), hex(cave.pop('end'))

    patched_main = args.out/'patched-main-analysis-only.bin'
    stock_main = args.out/'stock-main-analysis-only.bin'
    operands = {'control_uses_existing_tpc_transport', 'vendor_dispatch_table', 'vendor_dispatch_count',
                'device_info_operation_count','device_info_operation_list','control_property_usb_enable_event',
                'control_property_usb_disable_event','native_operation_list','native_operation_count',
                'native_event_list','native_event_count','device_info_event_count','device_info_event_list'}
    report = dict(source=str(args.stock), source_sha256=STOCK_SHA,
                  manifest=str(args.manifest), manifest_sha256=MANIFEST_SHA,
                  tool_sha256=sha256(Path(__file__).read_bytes()),
                  main_analysis_base=hex(BASE),
                  offset_convention='Manifest offsets are decoded CONTAINER offsets, including 32-byte component headers.',
                  scope='Independent packaging/hash and static edit audit only; no supplied Python executed, camera accessed, or installable package saved.',
                  patches=rows, components=components, injected_regions=caves,
                  patch_records=len(rows), guarded_bytes=sum(r['bytes_guarded'] for r in rows),
                  decoded_bytes_changed=sum(r['bytes_changed'] for r in rows),
                  injected_bytes_changed=sum(r['bytes_changed'] for r in rows if r['expected_all_ff']),
                  existing_bytes_changed=sum(r['bytes_changed'] for r in rows if not r['expected_all_ff']),
                  encoded_bytes_changed=sum(c['encoded_payload_changed_bytes']+c['trailer_changed_bytes'] for c in components),
                  encoded_sha256=result['encoded_sha256'], encoded_matches_manifest=True,
                  decoded_sha256=result['decoded_sha256'], decoded_matches_manifest=True,
                  decoded_with_repaired_checksums_sha256=result['repaired_decoded_sha256'],
                  decoded_checksum_note='Author decoded output retains stock checksum trailers; encoded update repairs checksums correctly.',
                  disassembly_caveat='Exact edit starts; operand-only records omitted. Cave blobs mix code, data and FF padding; linear decoding alone does not establish reachable instructions.')
    cols=['name','decoded_container_offset','analysis_address','bytes_guarded','bytes_changed','expected_all_ff']
    with new_output(args.out) as write:
        write(patched_main.name, bytes(patched[0]))
        write(stock_main.name, blocks[0].payload)
        if not args.skip_disassembly:
            # Keep historical assembly/ layout; the inner writer owns each file.
            with new_output(args.out/'assembly') as write_asm:
                for row in rows:
                    if row['name'] in operands:
                        continue
                    start = int(row['analysis_address'], 16); end = start+row['bytes_guarded']
                    for suffix, path in [('stock', stock_main), ('patched', patched_main)]:
                        write_asm(f"{row['name']}.{suffix}.asm", disassemble(path, start, end))
            write.children.append((args.out/'assembly', write_asm.owned))
        write('audit.json', json.dumps(report, indent=2)+'\n')
        write('edits.tsv', '\t'.join(cols)+'\n'+'\n'.join('\t'.join(str(r[c]) for c in cols) for r in rows)+'\n')
    print(json.dumps({k:report[k] for k in ['patch_records','guarded_bytes','decoded_bytes_changed','injected_bytes_changed','existing_bytes_changed','encoded_bytes_changed','injected_regions','encoded_matches_manifest','decoded_matches_manifest']},indent=2))


if __name__ == '__main__':
    main()
