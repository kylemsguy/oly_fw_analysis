#!/usr/bin/env python3
"""Pinned E-M1 II 3.7 Pro Capture L lens-gate static/replay audit.

This is NOT native MN103 execution or camera emulation. It replays only the
reviewed 51-byte predicate, with two explicitly modeled service returns, and
checks the stock declarative drive restrictions. No firmware is written.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct

from oly_container import DECODE_ORDER, parse

BASE = 0x60021020
MAIN_SHA256 = "0a41fb8e1105751f7817e5664f2edf2a1bdf399f070e91b4e3c84e6943113803"
ENTRY = 0x60655822
END = 0x60655855
BRANCH = 0x6065584C
PREDICATE_SHA256 = "583974cce5b4de309ba78e63842ddc8a5a42f445f70f10027fc40f34b585a4c1"
RULES = 0x6047AEC0
RULE_COUNT = 33
CONTAINER_SHA256 = "691a8a8e90af75b3848b70856a3a49ef24d72394cdfd2766fa37bdfe6325de70"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def word(data, address):
    return struct.unpack_from("<I", data, address - BASE)[0]


def hwords(data, address, count):
    return struct.unpack_from("<" + "H" * count, data, address - BASE)


def replay(code, present, status, identity, displacement=4):
    """Instruction-scoped replay, not a general CPU/ABI model.

    Service 0x6022885b returns a synthetic lookup pointer; 0x60229b5f
    returns the supplied status. CALL frames and their diagnostics are not
    executed. All byte reads belong to the synthetic four-byte lens ID.
    """
    if len(code) != END - ENTRY or sha(code) != PREDICATE_SHA256:
        raise ValueError("Unexpected predicate bytes")
    if displacement not in (2, 4):
        raise ValueError("Only reviewed stock/bypass branch edges are supported")
    code = bytearray(code)
    assert code[BRANCH - ENTRY:BRANCH - ENTRY + 2] == b"\xc9\x04"
    code[BRANCH - ENTRY + 1] = displacement
    d0 = d1 = d2 = a0 = a2 = 0
    equal = False
    pc = ENTRY
    trace, calls = [], []
    for _ in range(64):
        trace.append(hex(pc))
        p = pc - ENTRY
        op = code[p:]
        if op.startswith(b"\x08"):
            d2 = 0
            size = 1
        elif op.startswith(b"\x00"):
            d0 = 0
            size = 1
        elif op.startswith(b"\xdd"):
            target = pc + int.from_bytes(op[1:5], "little", signed=True)
            calls.append(hex(target))
            if target == 0x6022885B:
                a0 = 0x20000000 if present else 0
            elif target == 0x60229B5F:
                d0 = status
            else:
                raise AssertionError(f"Unmodeled service {target:#x}")
            size = 7
        elif op.startswith(b"\x92"):
            a2 = a0
            size = 1
        elif op.startswith(b"\xba\x00"):
            equal = a2 == 0
            size = 2
        elif op.startswith(b"\x1c"):
            d0 &= 0xFFFF
            size = 1
        elif op.startswith(b"\xa8"):
            equal = d0 == d2
            size = 1
        elif op.startswith(b"\xfa\xd2\x44\x04"):
            a2 += 1092
            size = 4
        elif op.startswith(b"\xf8\x46\x01"):
            assert present and a2 == 0x20000000 + 1092
            d1 = identity >> 8 & 0xFF
            size = 3
        elif op.startswith(b"\xf0\x42"):
            assert present and a2 == 0x20000000 + 1092
            d0 = identity & 0xFF
            size = 2
        elif op.startswith(b"\xf8\xc1\x08"):
            d1 = d1 << 8 & 0xFFFFFFFF
            size = 3
        elif op.startswith(b"\xf2\x11"):
            d1 |= d0
            size = 2
        elif op.startswith(b"\x1d"):
            d1 &= 0xFFFF
            size = 1
        elif op.startswith(b"\xa9"):
            equal = d1 == d2
            size = 1
        elif op.startswith(b"\x8a\x01"):
            d2 = 1
            size = 2
        elif op.startswith(b"\x88"):
            d0 = d2
            size = 1
        elif op.startswith(b"\x14"):
            d0 &= 0xFF
            size = 1
        elif op.startswith(b"\xc8") or op.startswith(b"\xc9"):
            take = equal if op[0] == 0xC8 else not equal
            pc += int.from_bytes(op[1:2], "little", signed=True) if take else 2
            continue
        elif op.startswith(b"\xdf\xa0\x0c"):
            return dict(result=d0, trace=trace, modeled_calls=calls)
        else:
            raise AssertionError(f"Unsupported instruction at {pc:#x}: {op[:7].hex()}")
        pc += size
    raise AssertionError("Predicate did not terminate within 64 instructions")


def rules(data):
    rows = []
    for index in range(RULE_COUNT):
        address = RULES + 16 * index
        conditions, nconditions, translation, nvalues = struct.unpack_from(
            "<4I", data, address - BASE)
        predicates = [struct.unpack_from("<HHI", data, conditions - BASE + 8 * i)
                      for i in range(nconditions)]
        pairs = [hwords(data, translation + 4 * i, 2) for i in range(nvalues)]
        rows.append(dict(index=index, runtime=hex(address),
                         conditions=predicates, pairs=pairs,
                         translation=hex(translation)))
    return rows


def audit(data):
    if sha(data) != MAIN_SHA256:
        raise ValueError("Requires exact stock E-M1 II 3.7 decoded main")
    code = data[ENTRY - BASE:END - BASE]
    assert sha(code) == PREDICATE_SHA256
    # Concrete constructor/vtable, not a guessed table base.
    assert data[0x60837C52 - BASE:0x60837C59 - BASE] == bytes.fromhex("fcccb4b5af6060")
    assert word(data, 0x60AFB5B4 + 844) == 0x6083C6F8
    # The other direct API consumer explicitly dispatches public key 1406.
    assert data[0x60863368 - BASE:0x6086336E - BASE] == bytes.fromhex("fac87e05c834")
    assert data[0x60327E36 - BASE:0x60327E3D - BASE] == bytes.fromhex("ddecd93200a00c")
    # Derived drive selector 2081 dependencies: contiguous int32 fixture slots.
    parameters = hwords(data, 0x6046DA20, 17)
    assert parameters == (2081, 1491, 1497, 1559, 0, 87, 1507, 166, 756, 762, 1156,
                          2000, 0, 0, 0, 0, 0)
    key, flags, records, values, size, stride, tail = struct.unpack_from(
        "<HHIIHHI", data, 0x604EE648 - BASE)
    assert (key, flags, records, values, size, stride, tail) == (
        2081, 128, 0x604D1BB0, 0x604D0018, 0x500, 64, 0x600)
    enums = struct.unpack_from("<20I", data, values - BASE)
    tuples = [struct.unpack_from("<16I", data, records - BASE + 64 * i)
              for i in range(20)]
    low = tuples[enums.index(39)]
    high = tuples[enums.index(38)]
    assert low[:10] == (1, 0, 1, 0, 2, 0, 0, 0, 1, 1)
    assert high[:10] == (1, 2, 1, 0, 2, 0, 0, 0, 1, 1)
    rows = rules(data)
    lens_rows = [r for r in rows if any(c[0] == 1406 for c in r["conditions"])]
    assert [r["index"] for r in lens_rows] == [22, 23, 30, 31]
    differences = []
    for rejected, accepted in zip(lens_rows[::2], lens_rows[1::2]):
        assert accepted["index"] == rejected["index"] + 1
        reject_conditions = rejected["conditions"]
        accept_conditions = accepted["conditions"]
        assert [(k, v, f) for k, v, f in reject_conditions if k != 1406] == [
            (k, v, f) for k, v, f in accept_conditions if k != 1406]
        assert [c for c in reject_conditions if c[0] == 1406] == [(1406, 0, 0)]
        assert [c for c in accept_conditions if c[0] == 1406] == [(1406, 1, 0)]
        delta = [(a, b, d) for (a, b), (c, d) in zip(rejected["pairs"], accepted["pairs"])
                 if (a, b) != (c, d)]
        assert delta == [(39, 0, 39)]
        assert dict(rejected["pairs"])[38] == dict(accepted["pairs"])[38] == 38
        differences.append(dict(false_rule=rejected["runtime"],
                                true_rule=accepted["runtime"], differences=delta))
    # Conditions are equality tests in the decoded first-matching-rule engine.
    # Adjacent paired rows with identical non-lens conditions prove that no
    # intervening rule can change priority when only property 1406 changes.
    domains = {}
    for row in rows:
        for key, value, callback in row["conditions"]:
            assert callback == 0
            domains.setdefault(key, set()).add(value)
    defaults = {key: max(values) + 1 for key, values in domains.items()}
    rule_controls = []
    for seed in rows:
        state = dict(defaults)
        state.update({key: value for key, value, _ in seed["conditions"]})
        outputs = []
        for supported in (0, 1):
            state[1406] = supported
            match = next((row for row in rows if all(
                state[key] == value for key, value, _ in row["conditions"])), None)
            outputs.append((match["index"] if match else None,
                            dict(match["pairs"]) if match else dict(zip(enums, enums))))
        changes = [(drive, outputs[0][1][drive], outputs[1][1][drive])
                   for drive in enums if outputs[0][1][drive] != outputs[1][1][drive]]
        assert changes in ([], [(39, 0, 39)])
        rule_controls.append(dict(seed_rule=seed["index"],
                                  selected_false=outputs[0][0], selected_true=outputs[1][0],
                                  differences=changes))
    assert any(not r["differences"] and r["selected_false"] is not None
               for r in rule_controls)
    cases = []
    for present, status, identity in itertools.product(
            (False, True), (0, 1, 2, 0x10000, 0x10001),
            (0, 1, 0x100, 0xFFFF)):
        stock = replay(code, present, status, identity, 4)
        bypass = replay(code, present, status, identity, 2)
        assert stock["result"] == int(not present or bool(status & 0xFFFF) and identity == 0)
        assert bypass["result"] == int(not present or bool(status & 0xFFFF))
        if not present or status & 0xFFFF == 0 or identity == 0:
            assert stock == bypass
        cases.append(dict(object_present=present, helper_status=hex(status),
                          id_first_two_bytes=hex(identity), stock=stock, bypass=bypass))
    offset = BRANCH - BASE
    raw = 0x20 + ((offset + 1) // 16) * 16 + DECODE_ORDER[(offset + 1) % 16]
    return dict(
        evidence="Pinned static disassembly and bounded instruction-scoped replay, NOT native execution",
        main_sha256=MAIN_SHA256, predicate_sha256=PREDICATE_SHA256,
        patch=dict(decoded_offset=hex(offset), runtime=hex(BRANCH),
                   original="c904", replacement="c902",
                   changed_decoded_offset=hex(offset + 1),
                   changed_runtime=hex(BRANCH + 1), changed_raw_offset=hex(raw),
                   raw_original="fb", raw_replacement="fd",
                   explanation="BNE target changes from the return block to the immediately following MOV 1,D2; only the dedicated lens-ID rejection is bypassed"),
        dispatch=["0x60d64c4c", "0x60837bf2", "vtable 0x60afb5b4 + 844",
                  "0x6083c6f8", "0x607d9107", "0x60327e15", "0x60655822"],
        selector_dependencies=parameters, pro_capture_l=dict(value=39, tuple=low),
        pro_capture_h=dict(value=38, tuple=high), property1406_rules=lens_rows,
        rule_pair_differences=differences, representative_rule_controls=rule_controls,
        replay_cases=cases,
        limitations=[
            "Lookup pointer and status helper are modeled, not executed.",
            "The stock null-object path already returns 1; this is not a missing-lens readiness gate.",
            "The retained helper==0 rejection remains; shared physical lens trouble checks are not changed.",
            "No complete camera scheduler, sensor, lens communication, updater or autofocus test.",
        ])


def schema_evidence(container, data):
    if sha(container) != CONTAINER_SHA256:
        raise ValueError("Requires exact stock E-M1 II 3.7 container")
    blocks = parse(container)
    assert next(b.payload for b in blocks if b.kind == 0x100) == data
    common = next(b.payload for b in blocks if b.kind == 0x106)
    start = 0x1E803E0
    count, offset, _, enums, *_ = struct.unpack_from("<7I", common, start)
    wanted = {1491: "MODE_TAKE", 1497: "MODE_CONTINUE_TAKE",
              1559: "MODE_CONTINUE_TAKE_SPEED_ONOFF", 762: "MODE_ELECTRIC_SHUTTER_ONOFF",
              756: "MODE_PIXSHIFT_SR", 1156: "MODE_ZERO_TIME_LAG"}
    found = {}
    for index in range(count):
        p = start + offset + index * 72
        key, kind = struct.unpack_from("<HB", common, p)
        if key not in wanted:
            continue
        name = common[p + 4:p + 56].split(b"\0")[0].decode("ascii")
        assert name == wanted[key] and kind == 1
        enum_start, enum_count = struct.unpack_from("<IH", common, p + 56)
        values = {}
        for item in range(enum_count):
            q = start + enums + enum_start + item * 56
            value = struct.unpack_from("<i", common, q)[0]
            values[value] = common[q + 4:q + 56].split(b"\0")[0].decode("ascii")
        found[key] = dict(name=name, values=values)
    assert set(found) == set(wanted)
    assert found[1497]["values"][0] == "MODE_CONTINUE_TAKE_NORMAL"
    assert found[1497]["values"][2] == "MODE_CONTINUE_TAKE_HIGH_SPEED"
    assert found[1156]["values"] == {0: "MODE_OFF", 1: "MODE_ON"}
    return dict(container_sha256=CONTAINER_SHA256, common_sha256=sha(common), keys=found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--stock37", type=Path,
                        help="Also verify the container and stock settings-schema enum names")
    args = parser.parse_args()
    data = args.main.read_bytes()
    report = audit(data)
    if args.stock37:
        report["schema_evidence"] = schema_evidence(args.stock37.read_bytes(), data)
    report["probe_sha256"] = sha(Path(__file__).read_bytes())
    with args.out.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(f"Verified dedicated gate, paired L-only rules and {len(report['replay_cases'])} replay cases.")
    print("No firmware written; replay is not native CPU or camera execution.")


if __name__ == "__main__":
    main()
