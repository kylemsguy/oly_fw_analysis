# E-M1 II feature patches and Pro Capture L lens eligibility

## Scope and validation status

This report covers **focus stacking** and the recording-limit-related routine
in the supplied E-M1 II v3.6 modification, plus a separately traced **Pro Capture
L lens-ID eligibility bypass for stock v3.7 only**. The two historical patch
sites are at the same decoded offsets in v3.7 as v3.6,
but the correspondence is established by multiple independent anchors and
local control flow, **not by copying offsets**.

Exact bytes, local instruction semantics, recording entry conventions, and
local v3.7 mapping have high-confidence static evidence. This does not
establish complete camera behavior. The original two-feature investigation
had no usable MN103-capable objdump or native emulator and checked instruction
boundaries manually against the authoritative ISA manual. The newer Pro Capture
trace additionally uses GNU static disassembly and bounded instruction-scoped
replay, described below; no native firmware execution was performed.
There was no camera, updater, boot, physical-lens, thermal, storage,
or long-recording test. Checksums and deterministic reconstruction are
container-integrity evidence, not operational safety or unlimited recording.

**Legacy two-feature experimental artifact:**
`generated\em1ii_feature_port\output37\E1259999.BIN` (93,050,944 bytes).
Its SHA-256 is
`26198780bdacf2ec242b130757a141dfef1774c8cd0908cc283f5ac225bc691d`.
The decoded-main SHA-256 is
`176385dfa949bc9fb4b377c3f7e7b08d156fb4e64527aefd87909301d3ddbb6b`.
The build manifest and independent final byte-verification results are beside
the firmware as `manifest.json` and `independent-validation.json`. These
identities establish the local artifact, not camera acceptance.

**Current all-feature 3.7 artifact:**
`generated/em1ii_feature_port/output37-all-features/E1259999.BIN`
(93,050,944 bytes), containing recording-time-limit, Focus Stacking and
Pro Capture L lens-ID edits. Its SHA-256 is
`310e1c138a13a2fb88d1f46000c13bfde26b376489260212d78f55659c81b695`;
the decoded-main SHA-256 is
`2fcdf173f784b4afad279f08aa62c67ee32906ded3bf1828dc3b36d6146aeb21`.
`manifest.json` and `independent-validation.json` are beside the firmware.
This is experimental local output, not camera-tested firmware.

## Selecting features

The offline builder supports these features:

| Feature | Target 3.6 | Target 3.7 |
| --- | --- | --- |
| `recording-time-limit` | Yes | Yes |
| `focus-stacking-eligibility` | Yes | Yes |
| `pro-capture-l-lens-check` | No | Yes |

Omitting `--features` applies every verified feature for the selected target.
An explicit list applies only the named features. Unknown, duplicate, empty or
target-unsupported selections fail before firmware reads or output creation.
Selection order does not change the firmware or canonical patch records;
repeated `--features` flags accumulate rather than replace earlier selections.

From the repository root, build the existing two-feature 3.7 combination:

```bash
python3 tools/em1ii_feature_patch.py \
  --stock36 oly-firm/em1_ii-3.6/OLY_E_125_3600_0000_0000.BIN \
  --stock37 oly-firm/em1_ii-3.7/E1259999.BIN \
  --features recording-time-limit focus-stacking-eligibility \
  --out generated/em1ii_feature_port/selected37
```

For stacking alone, replace the feature list with
`--features focus-stacking-eligibility`. Each output directory must be new.
The manifest and CLI summary identify the selected features; the manifest also
lists all available features. Each subset starts from pinned pristine stock,
not a previously patched image.

Every build first reconstructs the **complete historical two-feature 3.6
image**, regardless of the requested target or subset, and requires its pinned
whole-image SHA-256. `--patched36` is optional: when supplied, its hash and exact
bytes must additionally match that reconstruction. The manifest distinguishes
the mandatory hash verification from an actual reference-file comparison.
Omitting the reference does not disable historical verification.

Build all three 3.7 features by omitting the selection option:

```bash
python3 tools/em1ii_feature_patch.py \
  --stock36 oly-firm/em1_ii-3.6/OLY_E_125_3600_0000_0000.BIN \
  --stock37 oly-firm/em1_ii-3.7/E1259999.BIN \
  --out generated/em1ii_feature_port/rebuilt37-all-features
```

To apply only the Pro Capture L bypass, add
`--features pro-capture-l-lens-check` and choose another new output directory.

## Pro Capture L lens-ID bypass: stock 3.7

The minimal edit changes **one payload byte**, within a two-byte instruction
preimage. It is separate from the Focus Stacking patch:

| Address space | Location | Original | Replacement |
| --- | --- | --- | --- |
| Decoded main instruction | `0x63482c` | `c9 04` | `c9 02` |
| Runtime instruction | `0x6065584c` | `BNE +4` | `BNE +2` |
| Actual changed decoded byte | `0x63482d` | `04` | `02` |
| Actual changed raw container byte | `0x63484e` | `fb` | `fd` |

The main trailer checksum must also be repaired. Do not hex-edit just the raw
byte and assume the container remains valid; the builder repairs and verifies
the checksum and exact full-file delta.

### Dedicated predicate and dispatch

The stock predicate at runtime `0x60655822..0x60655855` returns:

```text
object = lookup(0)
if object is null:
    return 1
if uint16(status(0)) == 0:
    return 0
return uint16(object[1092] | (object[1093] << 8)) == 0
```

The tested word is the first two bytes of a four-byte lens ID. The edit changes
only its rejection edge: stock `BNE +4` branches to `0x60655850`, preserving
result zero; patched `BNE +2` targets the existing `MOV 1,D2` at `0x6065584e`.
The zero-ID fallthrough already reaches that instruction. All original helper
calls, ID reads and the status guard remain.

The named `checkZeroLagLensCondition` consumers at `0x60d3eda6` and
`0x60d3edef` query a service vtable at byte displacement 844. Its constructor at
`0x60837c52` installs vtable `0x60afb5b4`, whose slot at `0x60afb900` points to
`0x6083c6f8`. The resolved chain is:

```text
0x60d64c4c -> singleton 0x60837bf2 -> slot 844: 0x6083c6f8
    -> 0x607d9107 -> API 0x60327e15 -> predicate 0x60655822
```

Those consumers normalize the result and conditionally update public property
1406. A separate recomputed-property validator at `0x60863337` selects the same
API when the requested property is 1406. Patching only cached availability or
only a drive table would miss this additional consumer.

### Why this is L-specific

The stock derived drive selector, public key 2081, combines the named continuous
take, electronic shutter and `MODE_ZERO_TIME_LAG` settings. Its dependency tuple
maps **39 to Pro Capture L** and **38 to Pro Capture H**; the H tuple selects
`MODE_CONTINUE_TAKE_HIGH_SPEED`, whereas L selects normal/low-speed continuous
take. The rate descriptors at `0x604f374c` (public key 1157, L) and `0x604f3760`
(1158, H) provide additional anchors, not the eligibility proof by themselves.

The first-matching-rule registry at `0x6047aec0` contains 33 rules for selector
2081. Only rows 22/23 and 30/31 depend on property 1406. Within each adjacent
false/true pair, all other conditions are identical, and the sole translation
difference is **39 -> 0 versus 39 -> 39**. All other entries, including H38,
are identical. Other restriction rows remain unchanged and retain priority.
This establishes the scope of the lens-ID eligibility change in those rules,
not complete physical capture compatibility.

The separate named `getZeroLagLensTroubleState` path at `0x609c2c65`, API
`0x6032108d` and shared status routine `0x60229c52` are untouched. Globally
forcing shared status or manufacturer predicates to succeed would remove
unrelated checks and is not this patch.

### Reproducible evidence and limitations

[em1ii_pro_capture_probe.py](../../../tools/em1ii_pro_capture_probe.py) pins the
decoded-main hash, the complete 51-byte predicate hash, concrete constructor
and vtable bytes, selector tuples, and all 33 drive-rule records. With
`--stock37`, it also validates the complete container and schema enum names.
Supply a decoded main from the pinned stock container:

```bash
python3 tools/oly_container.py oly-firm/em1_ii-3.7/E1259999.BIN \
  --expect-sha256 691a8a8e90af75b3848b70856a3a49ef24d72394cdfd2766fa37bdfe6325de70 \
  --code-base 0x60021020 --out generated/em1ii_feature_port/pro-capture-stock37
python3 tools/em1ii_pro_capture_probe.py \
  --main generated/em1ii_feature_port/pro-capture-stock37/00_0100_40560020.decoded.bin \
  --stock37 oly-firm/em1_ii-3.7/E1259999.BIN \
  --out generated/em1ii_feature_port/pro-capture-audit.json
python3 -B -m unittest discover -s tests -p 'test_em1ii_pro_capture_probe.py' -v
```

The probe replays 40 bounded combinations of null/present lookup, normalized
helper status and zero/nonzero lens-ID words. Lookup and status responses are
explicit fixtures. This is a small instruction-scoped replay, **not native
MN103 execution**, a full ABI model or camera emulation. It verifies that only
the nonzero-ID rejection after the retained status guard changes.

The stock null-object path already returns 1 and is unchanged. Neither this
predicate nor its bypass proves missing-lens rejection elsewhere. Vendor/model
names for numeric lens IDs, autofocus, timing, capture scheduling, physical lens
communication, bootability and updater acceptance have not been tested.

Local detailed evidence is under
`generated/em1ii_feature_port/pro_capture_trace37/FINAL-PROOF.json`, with
`final-verification.json` and `dispatch-proof/`. This supersedes the preliminary
blocked findings in that directory. Generated disassembly remains local.

### Combined-output validation

All 30 focused tests passed with `EM1II_ACTUAL_FIXTURES=1`, including the seven
nonempty combinations of the three features and four predicate replay tests:

```bash
EM1II_ACTUAL_FIXTURES=1 python3 -B -m unittest discover -s tests -p 'test_em1ii_*.py' -v
```

The actual CLI default build was independently reread and checked against
explicit edit bytes and a separately computed checksum delta, not just its
manifest. Exactly **15 raw bytes** differ from stock: 11 encoded payload bytes
and four main-trailer checksum bytes. The main checksum at raw `0x15ffffc`
changes from `61f1cb05` to `4c9d8efe`. All five component checksums pass, the
container reconstructs exactly, all non-main components and unchanged metadata
are identical, and both original input hashes remain intact.

## Inputs and local evidence

All three source containers are 93,050,944 bytes:

| Role | Repository-relative input | Container SHA-256 |
| --- | --- | --- |
| stock36 | `oly-firm\em1_ii-3.6\OLY_E_125_3600_0000_0000.BIN` | `5fcd7314d808c06f8c867700e39eaaea4c0f240b86bfab94d4bb484c50ed0c07` |
| patched36 | `patched_fw\e-m1_ii-3.6\E1259999.BIN` | `79a01d8648f1bfbe282047ca16efc46e15c7a33c2024ff874d51bb0f0b446105` |
| stock37 | `oly-firm\em1_ii-3.7\E1259999.BIN` | `691a8a8e90af75b3848b70856a3a49ef24d72394cdfd2766fa37bdfe6325de70` |

The local baseline is `generated\em1ii_feature_port\baseline\summary.json`.
Each role's decoded main is
`generated\em1ii_feature_port\baseline\<role>\00_0100_40560020.decoded.bin`.
These are local analysis artifacts, not firmware to commit or upload.

| Role | Decoded-main SHA-256 |
| --- | --- |
| stock36 | `f462e042fa6743c639e594a11f95cbe07955c9022cfdca8b0a6f64c5697e11b2` |
| patched36 | `cff8958d2627d7f9b26d048695ee360df66960f9887a25a23c00c052363d8658` |
| stock37 | `0a41fb8e1105751f7817e5664f2edf2a1bdf399f070e91b4e3c84e6943113803` |

The main component is 23,068,608 decoded bytes, model bytes `1250`, kind
`0100`, raw version field `3600` or `3700`. All five components in each input
passed additive checksums; unchanged decode/re-encode reconstructed each
complete input exactly. Baseline instruction-boundary flags were deliberately
provisional: the later feature reports supply the manual verification below.

Address spaces must remain distinct:

```text
runtime analysis address = 0x60021020 + decoded main offset
flash/container payload address = 0x40560020 + decoded main offset
raw image offset = 0x20 + (decoded_offset // 16)*16
                   + DECODE_ORDER[decoded_offset % 16]
```

The last equation is for block 0 only. Raw bytes are inverted and permuted;
neither raw offsets nor flash addresses are instruction runtime addresses.
The baseline independently corroborated the E-M1 II runtime mapping with
`tools\em1ii_boot_audit.py`, startup operands and model-specific configuration.

## Complete supplied v3.6 delta

Exactly **10 decoded main bytes** change: eight in the recording envelope and
two in the stacking branch. Exactly **14 encoded file bytes** change: those
ten encoded payload bytes plus four main-trailer checksum bytes. Headers,
other metadata, every other decoded byte, and all four non-main components
are unchanged. There is no unexplained source-patch edit.

| Decoded offset / envelope | Stock bytes | Supplied replacement |
| --- | --- | --- |
| `3339b2..3339be` (12-byte envelope; 8 bytes actually differ) | `c809ca0d2ccc06ca052c201c` | `c804ca0dfccc70707070cbcb` |
| `635a2a..635a2c` (2 changed bytes) | `c904` | `cbcb` |

All ranges in this report are end-exclusive. The complete encoded delta is:

| Raw file range | Stock encoded bytes | Patched encoded bytes |
| --- | --- | --- |
| `3339d2..3339d3` | `f6` | `fb` |
| `3339d7..3339dc` | `d3d3fa35f9` | `038f8f8f8f` |
| `3339dd..3339df` | `dfe3` | `3434` |
| `635a48..635a4a` | `fb36` | `3434` |
| `15ffffc..1600000` (checksum) | `01deae4c` | `ec877145` |

The approximately 3.18 million differing bytes between vendor stock v3.6 and
stock v3.7 are a **different comparison**, not additional supplied patch
changes. They were not fully reverse engineered. In the baseline, vendor
changes affect the main and kind `0106` payload; kinds `0101`, `010e` and
`0102` retain identical decoded hashes. A port must start from stock37 and
preserve its unrelated vendor changes, not transplant the old main component.

## ISA evidence

Authority: Panasonic **MN1030/MN103S Instruction Manual,
Pub.No.13250-040E**, existing PDF SHA-256
`a0d9d14e059aafa36b2b41281a8e767352baaced27898184e510b7e931c00824`.
Page references are printed pages, not PDF viewer indices: register mask p.16;
little-endian operands pp.21–22; MOV pp.26–29 and tables pp.160–161;
MOVM pp.38–39; EXTHU/CLR pp.44–45; ADD p.47; CMP p.58; conditional
branches p.81; CALL pp.85–86; RET p.89; NOP p.97; dual CALL/CALLS entries
§4.4 p.157; opcode tables pp.160–175.

In particular, branch displacement is relative to the **opcode PC**, `c8`
is BEQ, `c9` is BNE, and `cb` is a one-byte NOP. The excerpts below are
bounded manual annotations, not automated disassembly or execution results.

## Recording-limit-related routine

### Entry, ABI and relevant instructions

The complete stock routine `[333999,3339f3)` is identical in stock36/stock37:
90 bytes, SHA-256
`813100dc63282f127605dca2bfd6efdb0b9b7b8f0cb4ae1886e1f664100a2a1a`.

There are **two entries**, not a single CALL entry at the diagnostic pointer:

* Decoded `333999`, runtime `603549b9`: `cf80` (MOVM [D2],(SP)), then
  `f8fee8` (ADD -24,SP). This explicit prologue allocates 28 bytes overall.
* Decoded `33399e`, runtime `603549be`: alternate **CALL entry**, skipping
  that prologue. CALL mask `80`, frame `1c` saves D2 and allocates the same
  28-byte frame; `df801c` restores/returns. This matches manual p.157.

The observed local contract is D0 low 16 bits = mode, A0 = output-word
pointer, D0 = zero-extended 16-bit returned status; D2 is preserved. It is
not a recovered global compiler ABI or source-level function declaration.
Two raw CALL candidates, corroborated by encoding, frame and local caller
context, target the alternate entry in both stocks:
`331fc9: cdd519801c` and `33398e: cd1000801c`.
The latter is preceded by `EXTHU D2; MOV A2,A0; MOV D2,D0`; returned status
is then used in D0/D3. Arbitrary indirect/global reachability is untraced.

| Decoded offset | Stock annotation | Patched36 / candidate37 annotation |
| --- | --- | --- |
| `33399e..3339b2` | CLR D2; EXTHU D0; compare modes 6,3,8,9, branching to `3339b6`; compare mode 4 | unchanged |
| `3339b2` | `c809`: BEQ `3339bb` for mode 4 | `c804`: BEQ `3339b6` |
| `3339b4` | `ca0d`: BRA invalid-mode block `3339c1` | unchanged |
| `3339b6` | `2ccc06`: MOV 1740,D0 | `fccc70707070`: MOV `0x70707070`,D0 (six bytes) |
| `3339b9` | `ca05`: BRA `3339be` | now inside six-byte immediate, not a branch |
| `3339bb` | `2c201c`: MOV 7200,D0 | now inside MOV / followed by two `cb` NOPs at `3339bc..3339be` |
| `3339be` | `60`: MOV D0,(A0), **32-bit word store** | unchanged |
| `3339bf` | BRA return-status block `3339ee` | unchanged |
| `3339c1..3339ee` | D2=`0x9d06`; prepare diagnostic arguments; CALL `60062a37`, mask `f0`, frame `50` | unchanged |
| `3339ee..3339f3` | MOV D2,D0; EXTHU D0; RET mask `80`, frame `1c` | unchanged |

There is no branch into the new immediate: all accepted modes reach its
start and fall through the two NOPs to the existing store. The complete
suffix `[3339be,3339f3)` remains identical across all three inputs.

```text
mode = D0 & 0xffff
if mode in {3, 6, 8, 9}:
    value = 1740                    # patched: 0x70707070
else if mode == 4:
    value = 7200                    # patched: 0x70707070
else:
    diagnostic(status=0x9d06, self=0x603549b9, ...)
    return 0x9d06                   # if diagnostic returns normally
store_word32(A0, value)
return 0
```

The patch **preserves mode validation**, accepting exactly normalized
low-16-bit modes `{3,4,6,8,9}` (thus raw `0x10003` also selects mode 3).
Other normalized values take the error path with no local store through A0.
Diagnostic callee side effects are not established. Accepted paths have no
local null/alignment check on A0; the pseudocode assumes a valid aligned
writable pointer. No hardware fault behavior was tested.

`0x70707070` is 1,886,417,008. The exact user-facing units, downstream
consumer interpretation, and camera mode names remain unknown. Historical
research makes seconds plausible (1740 seconds = 29 minutes, 7200 = two
hours), but this is not established for these exact builds. No trace proves
removal of independent file/chapter, capacity, codec, buffer, thermal, battery
or other stopping conditions.

### Why the v3.7 mapping is credible

The full routine and multiple preceding/following/error anchors each match
uniquely in the complete stock mains, rather than just matching twelve bytes:

| Anchor | Decoded location in both stocks | Evidence |
| --- | --- | --- |
| Recording preimage | `3339b2` | Exact 12-byte preimage above, unique |
| Complete routine | `333999..3339f3` | Identical 90-byte hash above, unique |
| Preceding context | `333944..333999` | Identical 85 bytes, unique |
| Error/diagnostic context | `3339c1..3339ef` | Identical 46 bytes, unique |
| Following region | `3339ef..333a2f` | Identical 64 bytes, unique |
| Maximal enclosing equal span | `333944..333ae8` | 420 bytes, SHA-256 `6fe918033cb84f6eb2252ec55df58b10c65230f2468d660055eaf1610b86860b` |

The diagnostic immediate at `3339d4` is the earlier-entry self-pointer
`603549b9`; the CALL at `3339e7` is `dd30e0d0fff050`, targeting
`60062a37` in both stocks. The two alternate-entry callers and matching
dispatch constants add independent corroboration. Local byte identity is
not whole-program equivalence.

## Focus stacking

### The actual bypass

The patch is decoded `635a2a: c904 -> cbcb`, runtime `60656a4a`.
It removes **BNE +4 after a capability-query Boolean**, not the earlier
lens-sensitive guard or the capability query itself.

| Decoded offset | Stock annotation | Patch effect |
| --- | --- | --- |
| `635a14` | `08`: CLR D2, result=false | unchanged |
| `635a15` | CALL lens-sensitive guard | still called |
| `635a1c..635a20` | EXTBU D0; CMP D2,D0; `c910`: BNE `635a2e` | earlier nonzero guard still rejects |
| `635a20` | CALL capability query | still called |
| `635a27..635a2a` | EXTBU D0; CMP 1,D0 | still executed |
| `635a2a` | `c904`: BNE `635a2e` | two NOPs, so comparison no longer gates result |
| `635a2c` | `8a01`: MOV 1,D2 | always reached if earlier guard permits |
| `635a2e..635a4e` | optional debug logging; return uint8(D2) | unchanged decision structure |

```text
result = false
if uint8(lens_sensitive_guard()) == 0:
    q = uint8(stacking_capability_query())       # still called
    if q == 1:                                 # patch removes this condition
        result = true
optional_debug_log(result)
return uint8(result)

stacking_capability_query():
    object = lookup(0)
    return object != NULL and byte(object + 0x1bc9f) == 1
```

The query's internal null check still returns false without dereferencing the
field. **The patched caller ignores that false result too**, if its earlier
guard permitted continuation. Consequently, retained effective missing-lens
rejection is **not proven**. A null lookup need not mean a physically absent
lens; underlying object lifecycle and pointer-validity invariants are unknown.

The earlier guard examines a status byte, class/state and four-byte IDs at
object+1092, and in one path object+4 bit 0 plus a secondary flag. Those
conditions are retained rejection logic, not the bypassed positive test.
An earlier status failure can return guard=0 and permit continuation; it is
not a proven readiness or missing-lens gate. The guard itself lacks an
explicit local null check before its object access. No lens marketing-name
mapping, physical compatibility, focus-drive ability or safe operation is
established by these firmware fields.

| Local condition (normal callee returns assumed) | Stock result | Patched local result |
| --- | --- | --- |
| earlier guard low byte != 0 | 0; query not called | 0; query not called |
| guard == 0; nonnull query object; capability byte == 1 | 1 | 1 |
| guard == 0; nonnull query object; capability byte != 1 | 0 | 1 |
| guard == 0; query lookup returns null | 0 | 1 |

These are static conditional deductions, **not executed missing-lens tests**.

### Independent v3.7 correspondence

The complete 58-byte routine retains instruction layout and branch edges.
Service and diagnostic addresses relocate:

| Reference | v3.6 runtime target | v3.7 runtime target |
| --- | --- | --- |
| Earlier guard | `602299ec` | `602299f0` |
| Capability query | `60233c30` | `60233c41` |
| Diagnostic string | `607473b1` | `6074750d` |
| Logger | `606f8aee` | `606f8c4c` |

The exact NUL-terminated string
`fcs_check_focus_stacking_enable stacking` is unique in each main, at decoded
`726391` / `7264ed`, and each routine's string load points to its own copy.
Additional signatures each match exactly once in each full stock main:

| Anchor | Bytes / hash | v3.6 decoded | v3.7 decoded |
| --- | --- | --- | --- |
| Prior guard return test | `a00c14a8c910` | `635a1a` | `635a1a` |
| Query return through debug test | `000414a001c9048a01fca538e92c62faed0002c8` | `635a25` | `635a25` |
| Direct caller wrapper | `cd0513800814df0004` | `63470f` | `63470f` |
| Query null/capability tail | `00b000c80efc449fbc0100a501c904800114df0004` | `212c16` | `212c27` |
| 234-byte retained-guard suffix | SHA-256 `b3ab2c43832aa553a7199749f14b0bfae8b11fb4ae600309cc2c78b8cc5fd434` | `2089d5` | `2089d9` |

The 243-byte guard differs only in one byte of its first CALL displacement.
The 27-byte capability query differs only in its lookup CALL displacement;
the complete local null/field decision logic is unchanged. Both outer
branches still target `635a2e`. The direct wrapper corroborates entry
`635a14`; indirect callers are not excluded.

For bounds `[635a14,635a4e)`, routine hashes are:

| Role | SHA-256 |
| --- | --- |
| stock36 | `8b1c9feebba524993a1d1c5e2f75f639e507bc5194f8432c5d4e8b1d589820d5` |
| patched36 | `a903def6504f52bcc0d953bc41d575fcb06bb331e02f5826e9011bd7562511b5` |
| stock37 | `5bbc200131ae18e2cd5f58c0750bdc408c930465d011a3cc9f96cec2e80006ad` |

## Historical v3.0 results are not interchangeable

The [historical audit](../HISTORICAL_HACKS.md) and
`tools\historical_hack_audit.py` concern E-M1 II build 3001:

* Recording: decoded `3333b8`,
  `1ca006c814a003c810a008c8 -> fccc1000007060881cdf801c`.
  That patch returns early with successful output `0x70000010`, even for
  previously unsupported mode inputs. The supplied v3.6 patch instead writes
  `0x70707070` **and keeps unsupported-mode rejection**.
* Stacking: decoded `631d6f`, `c807 -> cbcb`, a historical BEQ +7
  allowlist-failure bypass with separately analyzed prerequisite/null gates.
  Current `c904` is BNE +4 after a helper Boolean, not the old inline
  sentinel-table scan. Neither the old table address nor historical
  missing-lens behavior may be imported into v3.6/v3.7.

## Reproduction and delivery checklist

Run locally from the repository root. No external download or firmware upload
is needed. Preserve the three inputs and keep generated firmware out of Git.
Windows Python Store aliases did not work in the verified environment; the
existing WSL Ubuntu Python 3.12.3 was usable. The guarded builder is
`tools\em1ii_feature_patch.py`; its `--help` was checked against these commands.
PowerShell converts Windows paths for arguments interpreted by WSL Python:

```powershell
Push-Location tools
wsl -d Ubuntu -- python3 em1ii_feature_patch.py --help
Pop-Location

Get-FileHash -Algorithm SHA256 -LiteralPath 'oly-firm\em1_ii-3.6\OLY_E_125_3600_0000_0000.BIN','patched_fw\e-m1_ii-3.6\E1259999.BIN','oly-firm\em1_ii-3.7\E1259999.BIN'

function ConvertTo-WslPath([string]$Path) {
    wsl -d Ubuntu -- wslpath -a ($Path.Replace([char]92, [char]47))
}
$stock36 = ConvertTo-WslPath (Resolve-Path 'oly-firm\em1_ii-3.6\OLY_E_125_3600_0000_0000.BIN').Path
$patched36 = ConvertTo-WslPath (Resolve-Path 'patched_fw\e-m1_ii-3.6\E1259999.BIN').Path
$stock37 = ConvertTo-WslPath (Resolve-Path 'oly-firm\em1_ii-3.7\E1259999.BIN').Path
$out36 = ConvertTo-WslPath (Join-Path (Get-Location).Path 'generated\em1ii_feature_port\reproduced36')
$out37 = ConvertTo-WslPath (Join-Path (Get-Location).Path 'generated\em1ii_feature_port\rebuilt37')
Push-Location tools
wsl -d Ubuntu -- python3 em1ii_feature_patch.py --stock36 "$stock36" --patched36 "$patched36" --target 36 --out "$out36"
wsl -d Ubuntu -- python3 em1ii_feature_patch.py --stock36 "$stock36" --patched36 "$patched36" --stock37 "$stock37" --target 37 --out "$out37"
Pop-Location

Get-FileHash -Algorithm SHA256 -LiteralPath 'generated\em1ii_feature_port\reproduced36\E1259999.BIN','generated\em1ii_feature_port\rebuilt37\E1259999.BIN'
```

Both output directories must be new; the builder refuses existing ones rather
than overwriting them. Each contains `E1259999.BIN` and `manifest.json`;
target 37 also verifies exact historical v3.6 reproduction before writing.
The reproduction command uses `rebuilt37` to avoid colliding with the
delivered `output37` directory. Both produce the same firmware SHA-256 above.

## Legacy two-feature validation

The 15 focused patch-builder tests passed, including the optional real-image
test enabled with `EM1II_ACTUAL_FIXTURES=1`; the nine existing container tests
also passed. Tests cover exact supplied patched36 reproduction, deterministic
v3.7 generation, wrong/already-patched sources, model/build metadata, preimages,
invalid/overlapping ranges, malformed containers, unrelated mutations, input
preservation and output collisions.

The CLI generated the local v3.7 artifact identified above, after comparing its
v3.6 reconstruction byte-for-byte with the supplied patched36 reference.
Independent final verification reread the persisted artifact, validated all five
component checksums and exact reconstruction, and confirmed all original input
hashes. The complete v3.7 encoded delta contains exactly 14 changed bytes at
the same raw ranges listed for v3.6. Its main checksum changes from little-endian
bytes `61f1cb05` to `4c9b8efe`; all non-main components and all other metadata
and payload bytes remain unchanged. The final patched instruction windows
match the manually verified replacement instructions and preserve the
surrounding instructions exactly.

To rerun the targeted tests from the repository root in PowerShell:

```powershell
wsl -- env EM1II_ACTUAL_FIXTURES=1 python3 -m unittest discover -s tests -p test_em1ii_feature_patch.py -v
wsl -- python3 -m unittest discover -s tests -p test_oly_container.py -v
```

These are byte-integrity, reproducibility, guard-behavior and static-instruction
checks. There is no native execution or whole-program/camera validation.
The firmware is **experimental, statically analyzed, and not camera-tested**.
