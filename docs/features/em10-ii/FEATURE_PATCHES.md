# E-M10 II v1.4: complete historical patch comparison

## Finding and evidence limits

The supplied patch makes **one 12-byte code replacement** and repairs the
main component's four-byte checksum. It replaces a mode-checked selector with
an unconditional **32-bit output of `0x70000010` (1,879,048,208) and status
zero**. Stock low-16-bit modes 3/6 select 1740; mode 4 selects 7200; all
others take a diagnostic path and return `0x9d06` without a local output store.
There is **no second feature edit**, stacking patch, or other changed payload.

GNU Binutils 2.45 disassembly, independent address mapping, ISA checks and
bounded caller tracing support these conclusions. They are **static findings,
not native execution or camera observations**. The native simulator build
refused a source archive whose SHA-256 did not match its provenance pin;
the check was not bypassed. No camera, boot, recording, storage, thermal,
pointer-fault or updater tests were performed. Container validity does not
establish operational safety or unlimited recording.

Unlike the separately analyzed E-M1 II v3.6 patch, which
retains mode validation, this E-M10 II patch also succeeds for previously
rejected modes. Historical resemblance is context, not evidence for importing
another model's addresses, modes, constants or calling convention.

## Inputs, preservation and complete byte accounting

Both containers are **69,599,232 bytes**. These are exact local identities,
not a claim that every file distributed under the same version has these bytes.

| Role | Repository-relative path | Container SHA-256 |
| --- | --- | --- |
| Stock | `oly-firm\em10_ii-1.4\E1209999.BIN` | `ff9d302318ecf6e06c0b31c181fc6a185e93623e819749db31cec7977fa92052` |
| Patched | `patched_fw\e-m10_ii-1.4\e1209999.bin` | `cef7a8c1b47a894c7e4538d76f47ccd8d76ad8e637404f7022a2f601c1e2f577` |

All three OE components in each input pass their additive checksums.
Decode/re-encode reconstructs each input byte-for-byte **in memory**; no
reconstructed update package was written. Headers, component order, sizes and
metadata match. Model bytes are `1200`; the main raw version field is `1400`.

| Component | Decoded bytes | Stock decoded SHA-256 | Patched decoded SHA-256 |
| --- | ---: | --- | --- |
| 0 / `0100`, main | 21,364,672 | `309682c05a96d3079ebcae598169d487fea7f8b2531d8ae99445d63e80ea7a39` | `2bc4fac76dad4fd4df8eda5b821efef7ea41b837315f04486b323cbb5b007964` |
| 1 / `0101` | 27,262,912 | `9060299579236c099ec3f318d186cddab004f27eb373b1e6da75e72c4e08179b` | identical |
| 2 / `0106` | 20,971,456 | `5666caec18c928175d09244fe7f48f061fde3f118b113fe6d81e40afd2e6e64c` | identical |

Both non-main components are **encoded and decoded identical**, including
headers and trailers. Their checksum words remain `0xe1680747` and
`0xa6e9c4ff`, respectively.

All ranges below are half-open. The **only decoded delta** is main
`[0x50d52b,0x50d537)`: all twelve bytes change.

```text
stock:   1c a0 06 c8 0c a0 03 c8 08 a0 04 c8
patched: fc cc 10 00 00 70 60 88 1c df 80 08
```

The **complete encoded-file delta** is sixteen bytes in these four ranges:

| Raw file range | Stock encoded bytes | Patched encoded bytes | Accounting |
| --- | --- | --- | --- |
| `[0x50d548,0x50d549)` | `e3` | `03` | 1 payload byte |
| `[0x50d54c,0x50d555)` | `375ff9f3375ff7fcfb` | `ff33efff778fe39f7f` | 9 payload bytes |
| `[0x50d556,0x50d558)` | `5f37` | `20f7` | 2 payload bytes |
| `[0x145fffc,0x1460000)` | `815a0aaf` | `4677d1c8` | 4 checksum bytes |

Thus the main trailer checksum word changes `0xaf0a5a81 → 0xc8d17746`.
Encoding permutes/inverts payload bytes, so the contiguous decoded edit is
split into three raw ranges. The checksum is container bookkeeping, not a
second executed feature. Every other byte is preserved.

## Address mapping and instruction authority

For this main component:

```text
runtime analysis address = 0x60021000 + decoded main offset
```

**Do not use `0x60021020`** from other models. The container payload address
`0x40300020` is also a different address space. Independent corroboration
includes 106 exact literal self-pointers across main, a startup reference
`0x6002439c` resolving to `CPU0!\n` at decoded `0x339c`, and diagnostic-PC
literals resolving to their local blocks. For example, the immediate at
decoded `0x50d551` names `0x6052e545`, precisely the local diagnostic block.
Signed relative calls independently corroborate control-flow consistency,
but alone cannot fix the absolute base. No secondary-component runtime
mapping or physical loader behavior is claimed.

The routine spans decoded `[0x50d525,0x50d566)`, runtime
`[0x6052e525,0x6052e566)`: **65 bytes**. Its instruction-aligned stock and
patched listings were checked to cover every actual byte in that interval.
The changed runtime interval is `[0x6052e52b,0x6052e537)`.

Disassembler: locally built **GNU Binutils 2.45**, target `mn10300`,
executable SHA-256
`d34c7e54d64e62ce6395560af853d760825eae72303a1686db782a4f064ab743`.
Source release SHA-256:
`c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2`,
checked against the [GNU release announcement](https://lists.gnu.org/archive/html/info-gnu/2025-07/msg00009.html).

ISA cross-check: Panasonic **MN1030/MN103S Instruction Manual,
Pub.No.13250-040E**, existing PDF SHA-256
`a0d9d14e059aafa36b2b41281a8e767352baaced27898184e510b7e931c00824`.
Printed pages: mask p.16; MOV pp.26–29; MOVM pp.38–39; EXTHU/CLR
pp.44–45; CALL pp.85–86; RET p.89; dual-entry convention p.157.

## Local functional change

### Entry convention and short instruction windows

The explicit prologue at `0x6052e525` is unchanged:
`cf80` saves D2 with MOVM; `f8fefc` reserves four additional stack bytes.
The confirmed **CALL entry** is `0x6052e52a`, whose `08` clears D2.
Observed CALLs use mask `80`, frame `08`, supplying the equivalent D2 save
and eight-byte frame while skipping the explicit prologue. Both versions
return with `df8008` (RET [D2],8). The explicit entry matches the documented
CALLS-compatible pattern, but no actual CALLS reachability was established.

D0 supplies the mode and returns the status; A0 is an unchecked output-word
pointer. Stock begins with EXTHU D0, compares 6/3/4, and selects these paths:

| Runtime site | Necessary stock instructions / meaning |
| --- | --- |
| `6052e52b..6052e53a` | EXTHU D0; compare 6, 3, 4; BEQ to constants; otherwise BRA diagnostic |
| `6052e53a` | `2ccc06`: MOV 1740,D0 |
| `6052e53d` | `60`: MOV D0,(A0), a **32-bit** store; then branch to status return |
| `6052e540` | `2c201c`: MOV 7200,D0; branch to the shared store |
| `6052e545` | `fcce069d0000`: MOV `0x9d06`,D2; prepare diagnostic arguments and call |
| `6052e561` | MOV D2,D0; EXTHU D0; RET [D2],8 |

The replacement, reached immediately after the unchanged CLR D2, is:

| Runtime site | Bytes | Instruction / effect |
| --- | --- | --- |
| `6052e52b` | `fccc10000070` | MOV `0x70000010`,D0 |
| `6052e531` | `60` | MOV D0,(A0): output bytes `10 00 00 70` |
| `6052e532` | `88` | MOV D2,D0: status zero |
| `6052e533` | `1c` | EXTHU D0 |
| `6052e534` | `df8008` | RET [D2],8 |

The old BEQ's displacement byte `0a` remains at `0x6052e537`.
A linear disassembly decodes it with the following bytes as
`movbu d2,(0xdca)`. **That is dead residual decoding, not a new executed
write.** The early RET makes `[0x6052e537,0x6052e566)` unreachable from
either normal entry, including the old constants, store, diagnostic and
epilogue. This does not exclude arbitrary transfers into interior code.

Conceptual pseudocode, not firmware execution or an emulation result:

```text
stock(mode, out):
    mode = mode & 0xffff
    if mode == 3 or mode == 6: *out = u32(1740); return 0
    if mode == 4:              *out = u32(7200); return 0
    diagnostic(0x39040009, 0x6052e545, 4106)
    return 0x9d06

patched(mode, out):
    *out = u32(0x70000010)
    return 0
```

### Complete local behavioral consequences

* **Accepted stock modes:** the stored value changes from 1740 or 7200 to
  1,879,048,208. Output width remains 32 bits; success status remains zero.
* **Rejected stock modes:** the patch removes normalization/validation,
  writes the constant and returns success instead of taking the diagnostic
  and returning `0x9d06`. Stock `0x10003` is mode 3; stock low16=0,1,2,5,7,
  8,9,65535 (and every other unsupported low16) takes the error path.
  Patched behavior ignores all 32 mode bits, assuming store/return complete.
* **Diagnostic bypass:** stock calls `0x60513020` at `0x6052e55a`, with
  D0=`0x39040009`, D1=`0x6052e545`, A0=4106. That service packs the
  arguments plus zero and calls `0x60512f42`; it is not passed the original
  output pointer in A0. The deepest service effects and any UI/log manifestation
  are unresolved. The patch bypasses this call and its side effects.
* **New dereference exposure:** an unsupported mode with an invalid/null
  output pointer previously avoided the local output dereference. Patched
  code dereferences it unconditionally. Neither image checks the pointer on
  paths that store. Actual faults were not tested.
* **Preservation and non-equivalence:** mask/frame and saved D2 are preserved.
  Patched code does not directly modify D1, D3, A0–A3 or MDR. D0 and condition
  codes change; PSW equivalence is **not** established. Stock error handling
  repurposes D0/D1/A0 and calls a service with its own scratch effects, so
  full-register/side-effect equivalence to that path must not be asserted.

## Confirmed callers and downstream effects

Whole-main raw CD/DD relative-call and literal-pointer scans were followed by
instruction-boundary, exact-encoding, signed-target, mask and frame checks.
These are the confirmed edges, not merely scanner hits:

| Call site | Exact bytes | Target | Mask / frame |
| --- | --- | --- | --- |
| `6052cedc` | `cd4e168008` | selector `6052e52a` | `80` / 8 |
| `6052e51a` | `cd10008008` | selector `6052e52a` | `80` / 8 |
| `6052ce8a` | `cd7116e010` | override wrapper `6052e4fb` | `e0` / 16 |
| `6052e1a8` | `cd5303e010` | override wrapper `6052e4fb` | `e0` / 16 |
| `6051297f` | `dddba30100f050` | direct consumer `6052cd5a` | `f0` / 80 |
| `6052db5b` | `cd0606b020` | boolean consumer `6052e161` | `b0` / 32 |
| `6054f091` | `ddc938fcffc01c` | public wrapper `6051295a` | `c0` / 28 |

No literal pointer to either selector entry, or CD/DD call to its explicit
prologue entry, was found. This bounded negative scan does **not** exclude
indirect/computed calls, aliases, cross-component references, other transfer
encodings or overlapping instruction streams.

### The unchanged override can bypass the patch

Wrapper `0x6052e4fb` preserves mode in D2 and output in A2, then obtains
state through `0x6051d658(0)`. If `u8[state+351] == 1`, it writes
`u8[state+350]` as a **u32** and returns zero. Otherwise it calls the
selector with low16(mode). Therefore not every request receives the patched
constant. The accessor selects among u16 indices at `a1c2be8a/8c/8e/90`,
performs device-specific `UDFU01 608,D2`, and adds `a1c2bee0`; interpreting
that custom operation as multiplication is not established.

### A confirmed unsigned cap becomes nonbinding

Consumer `0x6052cd5a` preserves mode and a caller output pointer.
At `0x6052cecb` it loads the pointed-to u32, clears MDR and divides
**unsigned by 600**, then calls the selector at `0x6052cedc` into a stack
word. A nonzero selector status exits before the cap-store sequence.
On success it takes an **unsigned minimum** of the quotient and selector
result. The minimum is stored at object+20 (`0xa1c2eed8`); when the byte
queried by `0x6052f964` is zero, it is also copied to object+16
(`0xa1c2eed4`). Accessor `0x6052f95a` supplies object `0xa1c2eec4`.

For this exact consumer:

```text
floor(0xffffffff / 600) = 7,158,278 < 1,879,048,208
```

Consequently the patched minimum always equals the quotient: this particular
numerical cap cannot bind. Stock instead caps that quotient at 1740 or 7200.
Previously rejected modes can now continue through this success sequence,
subject to other earlier validation. This is not an “unlimited” sentinel
test; the constant itself is finite.

The earlier wrapper call at `0x6052ce8a` also checks status and computes an
unsigned minimum into stack+24 before further custom operations/object
updates. Not every intermediate's later lifetime was resolved; those updates
must not all be equated to the final cap.

### Another consumer and a remaining gate

Boolean consumer `0x6052e161` initializes caller u32 output to zero, obtains
mode from byte `0xa1c2eeb3`, applies additional gates, and calls the override
wrapper into stack+16. On success it loads that result at `0x6052e1bd`,
executes `UDF01 D2,D0` at `0x6052e1c2`, and compares unsigned with
object+124. Other conditions inspect state+10 and object+16; qualifying
paths set the boolean to one. The selector can therefore affect more than
the stored-cap path, but the custom arithmetic's meaning is unresolved.
Outer caller `0x6052db5b` tests this boolean; when one, it writes `*A3=1`
and sets status `0x9d14`. This gate remains unchanged.

## Mode labels and physical units: unresolved, not assumed

The bounded trace followed both direct selector calls, both override-wrapper
calls, a public dispatch/input handoff, the boolean gate, object writes and a
stored-field reader. It did **not** recover a complete settings catalogue,
device-specific UDF semantics or the entire recorder/timer lifecycle.

* Public wrapper `0x6051295a` routes category 3 to `0x6052cd5a`, category 1
  to separate `0x6052a65b`, and rejects other categories. Settings wrappers
  `0x6053120f`/`0x60531238` query keys `0xf021`/`0xf051` through
  `0x60076b64`. Upstream `0x6054f091` obtains mode from a u16 stack field
  at +48 and passes a UDF-derived quantity. This does not identify a UI mode.
* Nearby code `0x6052db81..0x6052dbbf` maps **object+56**
  6→1920, 3→1280, 4→640. Its reaching definition was not connected to the
  selector input. Width-like numbers are not proof of FHD/HD/VGA labels here.
* Reader `0x6052f894` applies `UDFU01 1000` to `0xa1c2eed4` before copying
  to output+20; another field has custom scaling and /600. These are exact
  scaling observations, not calibrated seconds/milliseconds/timebase proof.
  The ISA manual p.10 identifies UDF instructions as access to device-specific
  add-on units requiring device documentation. No substitute multiplication
  or timing model was treated as execution evidence.

Thus “recording-limit-related selector” describes its traced role, not a
verified duration unit. The familiar values 1740 and 7200 do not alone prove
seconds. Other stopping conditions, camera-level reachability and actual
recording duration remain unknown; this patch is not evidence of unrelated
features or removal of every recording limit.

## Reproduction and validation record

The read-only analyzer interface is:
[`tools\em10ii_historical_diff.py`](../../../tools/em10ii_historical_diff.py)
with `--stock`, `--patched`, and `--out`. From a **WSL shell at repository
root** (the slashes inside this shell are Linux paths):

```bash
python3 -B tools/em10ii_historical_diff.py \
  --stock oly-firm/em10_ii-1.4/E1209999.BIN \
  --patched patched_fw/e-m10_ii-1.4/e1209999.bin \
  --out generated/em10ii_feature_analysis/repro
```

The analyzer was run on the exact pair into
`generated\em10ii_feature_analysis\report` and independently rerun into
`generated\em10ii_feature_analysis\final-verification`. Both runs accounted for
all twelve decoded changes and sixteen encoded changes, and produced eight
bounded listings with complete byte coverage (628 decoded instruction records
across the stock/patched windows). Each directory contains `report.json` and
the listings; neither contains a generated firmware update.
Generated JSON, decoded component evidence and small listings belong under
ignored `generated\em10ii_feature_analysis`, not in version control. They are
analysis outputs, not new update packages.

The completed baseline and trace recorded:

* Exact input hashes/sizes, all component checksums and exact in-memory
  reconstruction; complete 12+4-byte accounting and unchanged components.
* GNU `objdump --version` and `-i` confirmed 2.45/MN103 support; a synthetic
  `80 01` smoke input decoded to `mov 1,d0`.
* Actual stock and patched function disassembly used this bounded command
  form, with each role's decoded main substituted for `<decoded-main>`:

  ```bash
  toolchains/binutils-2.45-build/binutils/objdump \
    -b binary -m mn10300 -D -z --insn-width=16 \
    --adjust-vma=0x60021000 \
    --start-address=0x6052e525 --stop-address=0x6052e566 <decoded-main>
  ```

* `python3 -B generated/em10ii_feature_analysis/trace/verify_facts.py`
  completed successfully: rehashed both inputs/mains, checked the contiguous
  12-byte main delta, matched every byte of both 65-byte listings, and checked
  all seven call encodings/targets against saved aligned windows. This is a
  local session evidence helper, not a portable tracked test runner.

The twelve focused analyzer tests passed, including the opt-in exact local
firmware-pair check. The nine existing container tests also passed. The focused
tests cover complete delta accounting, metadata changes, malformed containers,
source identity rejection, unexpected modifications, disassembly coverage and
output collisions. They do not execute the firmware. From PowerShell at the
repository root:

```powershell
wsl -- env EM10II_EXACT_FIXTURES=1 python3 -B -m unittest discover -s tests -p test_em10ii_historical_diff.py -v
wsl -- python3 -B -m unittest discover -s tests -p test_oly_container.py -v
```

Persistent local provenance: `baseline\summary.json`,
`baseline\mapping_evidence.json`, and `trace\functional-facts.json` under the
generated root; aligned `stock-function.asm`, `patched-function.asm`,
`direct-caller-aligned.asm`, `wrapper-aligned.asm`,
`boolean-consumer-aligned.asm`, `public-wrapper-aligned.asm` and
`stored-limit-reader-complete.asm` under `trace`. Discovery windows can begin
inside neighboring instructions and are not substitutes for aligned evidence.

Native execution remains **unperformed**. The required simulator revision was
`87ffb882e0f4d73401a0746177ffabb8e8bbe4ac`, expected archive SHA-256
`a5e7cd02f844bb2873c25e0ac8e9a5b50a72c3e8e6570a6b7821d2e4c21178ad`.
Two downloaded archives instead hashed to
`1ec3749773a4b00fc051233c32370cddd46687e8084f586d44d983487c3e1516`
and `454bffa58e8d8a24644c64c2e12f7ce6ede08fdb15ad1e95b9d9cd439b2e85c0`.
`tools\build_mn103_emulator.py` correctly refused the first archive.
No unverified source was accepted; no native runner results or homemade
behavioral model are claimed. See [emulator limitations](../../tooling/EMULATOR.md).

No firmware generation/modification, port, installation instructions, flashing,
upload, commit or push forms part of this analysis.
