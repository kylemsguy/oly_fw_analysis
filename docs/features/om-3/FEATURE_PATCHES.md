# OM-3 1.1: USB V22 and an experimental stacking eligibility edit

## Findings and evidence level

The supplied **kred V22 USB patch** is substantial added code, not a single
hidden-feature flag. Its 35 guarded edits repurpose the RAW USB menu entry for
native PC-control startup, add JPEG live view and capture/control glue, expose
native property services, and change notifications. It does **not** add RAW
sensor streaming or a focus-stacking engine.

An independently localized **two-byte stacking eligibility-result bypass**
passes the static composition gate. It ignores one capability-query Boolean,
not the preceding OM-3 guard. This supports an experimental in-place combined
build, **not physical lens compatibility, camera safety, or global independence
from USB behavior**. No stacking helper or code cave is added.

Validation here is container reconstruction, byte comparisons, table decoding,
and bounded GNU MN103 disassembly. No new native instruction execution, camera,
boot, update acceptance, flashing, live-view session, or stacking capture was
tested. Existing native section-loader tests in [CODE_SPACE](../../safety/CODE_SPACE.md)
are prior, modeled evidence, not tests performed for this report.

## Provenance and exact identities

The [source catalog](../../../provenance/SOURCES.md) attributes the supplied
patcher/manifest to **kred**, with a reported OM-1 II porting origin. The local
`OM-3 patcher` directory is retained unchanged; it is not moved or redistributed.
No accompanying redistribution license was supplied. This report describes
independently observed effects rather than copying the script or manifest.
The downloaded script was **not executed or imported**.

All hashes below are SHA-256:

| Input / reconstruction | Bytes | SHA-256 |
| --- | ---: | --- |
| Stock `oly-firm\om-3-1.1\E1479999.BIN` (encoded) | 240,517,120 | `8c133084414533159f587bf46bfb4152714c4074312a47c8d8503e33d605696d` |
| Local `OM-3 patcher\om_firmware_patcher_v2.py` | 16,825 | `7ea206514cd2e7d2a3f552743044da44e6c31e0686196d48ed807073ae99b18c` |
| Local `OM-3 patcher\patches\om3_pc_remote_v22.json` | 21,839 | `8f520edb97995c7b5de3b43da725b33bff9a5f1ddb52d31d439a01609369505e` |
| Stock decoded container | 240,517,120 | `5e8533738a26acee331bd8f6e068dffa9c07fd5177afb9d528ac13e4ae03c948` |
| V22 encoded release, independently reconstructed | 240,517,120 | `6b58d1b4fc832142f9fe6ffa43c3d28c05a90517e48cdf7db938a3bdff3a7bbf` |
| V22 decoded, **original stock trailers** (author's release convention) | 240,517,120 | `7b0d1e9794b85af8bab0132983251d91649d558564d0b1675739e2120cb48bcd` |
| V22 decoded, **repaired trailers** | 240,517,120 | `007e63cc752c23c5026eeacad929faed5909c4b5f14e7bc4fb1f862c11587871` |

The inspected archive identity recorded in the source catalog is
`8f2fbaca454bca581e4e9e6561ac2341590bf7be4301ac7351660f1e00647131`.
The manifest also names an upstream analysis manifest
`analysis/pc_remote_20260905/preset_raw_control_v22_manifest.json`
with hash `051816f928b8ff4e5f71d7c4d96f0c8fed4f1b452542869ba6de140e56ad60d2`;
that is attribution metadata, not a separately reproduced local input.

The independent baseline reproduces both manifest release hashes and a
byte-identical stock encode/decode round trip. The author's decoded release
retains **original checksum trailers**, so its patched main checksum is invalid
(`0xb744a77f` additive sum); it is an intermediate, not a checksum-valid decoded
patched container. Encoded V22 repairs the main trailer checksum from
`0x128b74d7` to `0x5b46cd58`. Repaired decoded output has a separate identity;
it must not be mistaken for failure to reproduce the author's decoded hash.

### All six components

Offsets include component headers; sizes and hashes in this table describe
**decoded payloads only**. Container addresses are not automatically execution
addresses. All stock checksums pass. V22 preserves every header and trailer
metadata field and changes only component 0's payload and four checksum bytes;
components 1–5 are unchanged.

| Index / kind / raw version | Container offset | Container payload address | Payload bytes | Stock payload SHA-256 |
| --- | --- | --- | ---: | --- |
| 0 / `0100` / `1100` | `0x0` | `0x50000020` | 33,554,368 | `5e8d376e9111a44ac0352f26030d7c1b17026d42c45f3600cfa02a0e8c5b7d59` |
| 1 / `0101` / `0100` | `0x2000000` | `0x41ec0020` | 60,817,344 | `6d2bef74b4b2fa089f271529482f96505a170b91e79ab9b1a13f3ce8f7918226` |
| 2 / `0106` / `0100` | `0x5a00000` | `0x458c0020` | 143,523,776 | `3d9fd4426b45fbe4b715599422af38c6d22392c08543a69f63c28291c5a0b059` |
| 3 / `010e` / `0001` | `0xe2e0000` | `0x00000020` | 262,080 | `b9200daf346a53aaae9fd2908740f5f17d867309ba958e703e70169cb114ca87` |
| 4 / `0102` / `1000` | `0xe320000` | `0x4e1a0020` | 2,097,088 | `494cd9ef134a91503a12e852e56fc6c42b7c94c07116b889991b38c0fcf74c09` |
| 5 / `0107` / `0000` | `0xe520000` | `0x08000020` | 262,080 | `9a9e7abef58daf72da495f8e18140043ecf2632b0ae5ea820e83be2ae2d0e377` |

V22 main payload SHA-256:
`2fa0238100f8072b449b8722ef03069975e2a0180443ea338bd50f08a0e79f49`.
There are **4,099 guarded bytes, 3,555 actually changed bytes**. Six all-FF
records account for 3,380 changes in three injection regions; the other 29
records account for 175. Guard length is not changed-byte count.

## Address and confidence conventions

Below, **O** is decoded-container offset, **A** is analysis/runtime address, and
**L** is guarded/replacement length in bytes. These are **not raw encoded-file
patch offsets**. Component 0 has a 32-byte header:

`payload offset = O - 0x20`; `A = 0x60021020 + payload offset`.

The native descriptors/loader corroborate the main mapping, rather than merely
assuming it from the container header. All intervals are end-exclusive.
**H** means exact local instructions, table contents, or control flow established.
**M** means those mechanisms are established but broader naming, lifetime, or
end-to-end interoperability remains conditional. Manifest names are identifiers,
not proof of their claimed semantics.

## Complete V22 edit inventory: 35/35

### Transport, startup, and registration

| Manifest edit | O / A | L | Local function / effect | Confidence |
| --- | --- | ---: | --- | --- |
| `control_uses_existing_tpc_transport` | `3e8089` / `60409089` | 1 | Operand in instruction at `60409088`: transport selector D3 changes 12→11 after native configuration A0=13; reuses an existing path. | H; M selector name |
| `preset_raw_control_startup` | `106d2fd` / `6108e2fd` | 2 | Startup switch result D0 changes 10→12, stored at `62b7f7f0`; another existing case already returns 12. | H |
| `omit_separate_control_row` | `129c7ec` / `612bd7ec` | 2 | Seeds menu output object+204 with zero, not one; with next edit selects six rows (`60380060=6`), not seven. | H |
| `usb_menu_query_skip` | `129c800` / `612bd800` | 2 | Replaces indirect query `0x874` call with NOPs, retaining that seed; not all menu checks are removed. | H |
| `raw_uses_control_startup` | `129ceb4` / `612bdeb4` | 3 | RAW case D0=3 now joins `612bdec3`, replacing startup event pair (26,26) with existing Control pair (26,27). | H |
| `register_capture_hook` | `18a9f87` / `618caf87` | 5 | Jumps to `6031eb90`, replays native registration init `618d082b`, adds 13 registrations, rejoins `618caf8c`. | H |
| `register_native_pc_properties` | `189ccb0` / `618bdcb0` | 5 | Tail jump to `6031ee00`: registers 291 native descriptors plus `60384e90` (`D1CE`); does not implement 299 new properties. | H |

### Capability validation and DeviceInfo advertisement

| Manifest edit | O / A | L | Local function / effect | Confidence |
| --- | --- | ---: | --- | --- |
| `vendor_dispatch_table` | `18a81a0` / `618c91a0` | 4 | Pointer operand replaces native table `61993624` with `60a8f400`; preserves old `94D9/94DA` handlers. | H |
| `vendor_dispatch_count` | `18a81c1` / `618c91c1` | 1 | Dispatch entries 2→15. | H |
| `native_operation_list` | `18a8fc1` / `618c9fc1` | 4 | Validator operation pointer→`619a9740`. | H |
| `native_operation_count` | `18a8fc6` / `618c9fc6` | 1 | Validator count 35→48. | H |
| `device_info_operation_list` | `18b54b6` / `618d64b6` | 4 | DeviceInfo uses same 48-operation list. | H |
| `device_info_operation_count` | `18b54b3` / `618d64b3` | 1 | DeviceInfo count 35→48. | H |
| `native_event_list` | `18a8fcb` / `618c9fcb` | 4 | Validator events→`6031ef40`. | H |
| `native_event_count` | `18a8fd0` / `618c9fd0` | 1 | Validator event count 6→12. | H |
| `device_info_event_list` | `18b554f` / `618d654f` | 4 | DeviceInfo uses same 12-event list. | H |
| `device_info_event_count` | `18b554c` / `618d654c` | 1 | DeviceInfo event count 6→12. | H |
| `native_property_case` | `18a8fd3` / `618c9fd3` | 10 | Jump to `60a8f330` supplies A0=`60a8f580`, D3=299; rejoins search `618c9fe0`, with NOP fill. | H |
| `device_info_full_property_case` | `18b55e5` / `618d65e5` | 8 | Aligned veneer `60a8f380` supplies D2=299, D0=`60a8f580`, rejoins serializer `618d65ed`; previously 11 properties. | H |

### Notifications, transitions, and AF

| Manifest edit | O / A | L | Local function / effect | Confidence |
| --- | --- | ---: | --- | --- |
| `property_notification_entry` | `189e866` / `618bf866` | 6 | Helper `60a8f300` emits `C108` when `a320fca2=1` instead of suppression; otherwise standard `4006`. | H |
| `object_added_native_hook` | `189c905` / `618bd905` | 6 | Helper `6031ef80` selects `C102` in control state 1 instead of suppression, `4002` otherwise. | H |
| `direct_store_notification_hook` | `189dc01` / `618bec01` | 8 | Helper `619a9706` retains nonzero-result `C113` route; zero-result obtains handle and sends `C104`, rejoins `618bec27`. | H; M storage-result meaning |
| `control_stop` | `189d455` / `618be455` | 26 | Calls `60a8f340` instead of suppression/equality block; now notifies state 1 with `C105`; native state update remains. | H |
| `control_stop_mode14` | `189d543` / `618be543` | 19 | Same helper for second mode-14 stop block; surrounding cleanup remains. | H |
| `control_set_mode14` | `18a2290` / `618c3290` | 27 | Same helper; retains mode 14, argument 3, `a320fc98=2` and temporary `a320fc02` gates/state handling. | H |
| `control_property_usb_enable_event` | `18a2120` / `618c3120` | 1 | Comparison at `618c311f` changes 12→11 for internal event `041b0084`; wait/ack and other cases remain. | H |
| `control_property_usb_disable_event` | `18a221f` / `618c321f` | 1 | Comparison at `618c321e` changes 12→11 for `041b0085`; other cases remain. | H |
| `af_multi_removed_branch` | `189b9bb` / `618bc9bb` | 3 | With control state 1, AF state `fc0c=1`, `fc24=1/3`, targets `618bcbcb` instead of `618bcbbf`, selecting `C111` not `C103`. | H; M AF field names |
| `af_frame_removed_body` | `189bbbf` / `618bcbbf` | 24 | Replaces lock/unlock-only body with entries calling `6031ee60/6031eee0`, then original exit `618bcf90`. AF event generation, **not eligibility bypass**. | H |

### Six all-FF injection records

| Manifest edit | O / A | L | Local function / contents | Confidence |
| --- | --- | ---: | --- | --- |
| `jpeg_liveview_cave` | `2fd920` / `6031e920` | 736 | JPEG fetch/queue consumer, bounded capture-transfer shim, synchronization veneers, registration trampoline, protocol data. | H flow; M runtime ownership |
| `capture_and_control_aligned_cave` | `2fdc00` / `6031ec00` | 896 | Capture/control sequence, command wrappers, coordinate helper, property registration, AF payload helpers, transfer rejection and event list. | H flow; M action names |
| `object_added_helper` | `2fdf80` / `6031ef80` | 36 | Event-selecting wrapper, native sender, ABI-compatible `RET [D2],8`. | H |
| `info_tail` | `2fdfa4` / `6031efa4` | 71 | `9495` serializer continuation: ≤9 string bytes, terminator/length, send, completion/free and shared epilogue. | H |
| `property_group_cave` | `a6e100` / `60a8f100` | 1,792 | Group serializer, registration/notification veneers, 299-property list, 15-entry dispatch table, full-list veneer, capture-info front half. | H flow; M interoperability |
| `property_events_cave` | `1988680` / `619a9680` | 384 | Incoming subscription setter, direct-store helper, 48-operation list, registration veneer. | H flow; M subscription lifecycle |

## USB protocol paths and native dependencies

### Operation table

All 35 original advertised operations remain; exactly these 13 are appended.
Native registration `618d07aa` receives code D0, argument count D1, metadata
A1=0, handler A0=`618c9150`. That common handler dispatches the 15 explicit
code/function pairs at `60a8f400`, including preserved native
`94D9→618c9343` and `94DA→618c9577`.

| Added code | Registered argument count | Target | Established behavior / limitations |
| --- | ---: | --- | --- |
| `9481` | 0 | `6031ec00` | Reads request+16; values 1–6 drive native state/event sequence below. Count zero despite parameter read is observed, not corrected here. |
| `9484` | 1 | `6031e920` | Fetches a bounded JPEG from native queue, sends through native data service. |
| `9489`, `948B` | 2 each | `619a9680` | Receive first/second property subscription group; native PC command selectors 10/11. |
| `9486`, `948A` | 1 each | `60a8f100` | Serialize first/second selected or complete native property group. |
| `9483` | 0 | `6031ed20` | Reads request halfwords +16/+18 into `a320fc52/54` under lock; selector 8 sends `041b0062`. AF-coordinate interpretation plausible, units unproven. |
| `9487`, `94B7` | 0 each | `6031ed40` | Native PC selector 5; result not propagated. Exact start/stop/mode meaning unproven. |
| `9488` | 0 | `6031edb0` | Inputs 1–4 send `041b003b..041b003e`; invalid input still reports success. Action names unresolved. |
| `9493` | 1 | `6031e9e8` | Capture-data bounds shim, then native transfer continuation `618c922a`. |
| `9494` | 0 | `6031ebc9` | Reconstructs native prologue, continues at `618c930b` for acknowledgment/completion, not capture-info serialization. |
| `9495` | 1 | `60a8f390` | New compact capture-info serializer, continuing at `6031efa4`. Field names/wire schema partly unresolved. |

For `9481`, native state query `60a8d630(1)` determines allowed sequences:

| Native state | Input | Internal events |
| --- | --- | --- |
| 0 | 1 / 3 | `02070100` / `02070100,02070101` |
| 1 | 2 / 5 | `02070101` / `02080100` |
| 2 | 4 / 6 | `02080101` / `02080101,02080100` |

Native selector state is updated and events posted through `618bd599`.
Input outside 1–6 returns `201D`; other native states return `2002`. Some
unmatched state/input pairs retain `201D` while passing later event preparation.
Half/full shutter press/release names are plausible, not established facts;
this is not unconditional successful shooting for every accepted number.

### Live view is JPEG, not RAW streaming

RAW is the **repurposed menu entry**, not the wire image format. Handler `9484`
requires `a320fc98=1`, snapshots `a320fda0`, and consumes three native 40-byte
queue records at `a320fd28` through helper `6031ea20`. Native lock veneers
`6031eb00/08→618be06c/78` use lock ID from `600435e6`; native memcpy is
`50002909`. Fresh-frame handling updates flags and clears `a320fda0`.

Before sending, it requires:

* Copied queue status equals 1.
* Length **2–153,600 bytes** (`0x25800`).
* Buffer is exactly **`b6e5c000`, `b6e81800`, or `b6ea7000`**.
* First halfword is `D8FF`, i.e. JPEG SOI bytes **`FF D8`**.

Native sender `618d092a` performs transfer. Success is `2001`, three response
parameters, first value 1. Check failures return `200F`, five parameters and
stage code `D7000000+stage` plus observations. **The native sender's return is
not checked at this JPEG call site before reporting success.**

No codec, new USB endpoint, sensor pipeline, arbitrary buffer discovery,
resolution/bit-depth negotiation, or producer initialization is added.
Producer lifetime, reuse during host transfer, DMA/cache ownership, and full
transaction atomicity are not proven by the small queue lock. Transport
selector 11 and preset startup result 12 are different enumerations.

### Capture transfer and completion

`9493` compares request handle+16 with `a320fdf8`. For a matching handle,
offset+20 and length+24 are bounded against total `a320fdfc`, using subtraction
to avoid an overflowing sum; invalid ranges return `201D` and one zero
parameter through `6031eebb`. A **handle mismatch proceeds to native validation**,
not that custom rejection. The shim recreates the native register-save/24-byte
prologue before jumping into `618c922a`. Native object checks, mode-14
transitions, and sender selection `618d092a/618d09ed` remain.

`9494` reconstructs its native prologue and checks availability/current handle.
Matching handle calls completion selector 4 through `618bd91e`; mismatch
returns `201D`. **No available object retains default success `2001` without
completion.** `9495` instead checks availability (`618bd987`), allocates
(`618d08da`), obtains the native capture record (`618bd992`), reorders five
32-bit fields, and copies at most nine string bytes. It sends `22+n` bytes,
calls native completion with selector 8 or 2, frees (`618d0903`), and uses
shared epilogue `6031ebd8`. Exact field meanings/string encoding remain unnamed.

### Events and AF payloads

The shared validator/DeviceInfo list at `6031ef40` is:
`4004,4005,4002,4009,4006,C113,C105,C108,C103,C111,C102,C104`.
The first six are stock. Vendor labels below describe local payload paths,
not a claimed comprehensive public Olympus protocol specification.

| Code | Observed route / payload |
| --- | --- |
| `4002` / `C102` | Standard ObjectAdded outside control state 1; handle notification `C102` inside it, replacing prior suppression. |
| `4006` / `C108` | Standard DevicePropChanged outside state 1; `C108` inside it, preserving property D1 and native A0/A1 argument mapping. |
| `C105` | Control transition in state 1; otherwise helper sends `4006` for property `D052`. Shared by three edited sites. |
| `C103` | AF frame-like payload: halfword state `a320fc0c`, packed pairs `fc0e/fc10` and `fc12/fc14`. |
| `C111` | AF aggregate/multi-like payload: state `fc0c`, 32-bit value `fc20`; units/bitmask convention unresolved. |
| `C113` / `C104` | Retained nonzero-result direct-store route / new zero-result handle route from `618bf9cc`. |

These use native sender `618be1f9`, retaining availability `a320fc02=1`
(with `C104/C114` exceptions), supported-event lookup `618c9f7e`, and final
send `618d0b49`. A new event call therefore does not ensure host delivery in
every mode. AF helpers snapshot native state under lock; the edits change
event selection/payload generation, **not focus-stacking lens eligibility**.

### Properties and subscriptions

| Table / path | Exact count or bound | Meaning |
| --- | --- | --- |
| `60a8f580` validator and DeviceInfo table | 299 halfword codes | Advertised/supported-code list, not 299 injected getters/setters. |
| Native descriptor pointers `61992595` + `60384e90` | 291 + 1 | Existing property implementations registered in PC mode 11; modes 12/14 take other native paths. Added descriptor is `D1CE`. |
| Advertised codes outside those 292 descriptors | `5001,5011,D405,D406,D407,D179,D17B` | Other native standard paths may handle them; universal usability or seven missing implementations is not established. |
| Subscription `9489/948B` | 4–602 bytes, count≤299, exact `4+2*count` | Requires native subscription pointer `a320fdac/fdb4`; native receive `618d0ac8`, selector 10/11 through `618bdb55`; success requires return zero; allocation freed. |
| Group `9486/948A` | Native and group counts≤299; output≤262,144 bytes | Uses `a320fda8/fdb0`; nonempty selection needs pointer; backing store `a320fda4` required. |

Group serialization enumerates/searches 20-byte native records at `62d34144`
under the property lock. It skips zero-length entries and missing selected
codes, validates lengths against record capacity and sources against the
16,448-byte backing-store window, then emits a 32-bit count followed by native
serialized records. It unlocks before sending, checks that sender's return,
and frees. Missing requested codes are not individually reported as failures.
Default error is `2002`. Lock duration, native storage ownership, subscription
lifecycle, and notification timing remain dependencies, not newly proven guarantees.

## Three injection/load dependencies, not generic free space

Use the existing [code-space evidence](../../safety/CODE_SPACE.md) and
[audit](../../../tools/om3_code_space_audit.py), rather than treating FF as
universally safe memory:

| Native section | Loaded interval | Qualified FF suffix | V22 write span |
| --- | --- | --- | --- |
| 1 | `60134000..6031f000` | `6031e910..6031f000` | `6031e920..6031efeb` (four adjacent records) |
| 4 | `60828000..60a8f800` | `60a8f088..60a8f800` | `60a8f100..60a8f800` |
| 9 | `61809000..619a9800` | `619a966c..619a9800` | `619a9680..619a9800` |

Descriptor table `60029b28`, end selector `60045e6c`, and loader `60045ed5`
qualify these bounds. The loader reads exactly end−start through `600232d1`
to uncached alias +`40000000` and sets loaded bit `a32de590`. Section 1's
neighboring table has an explicit end; sections 4/9 have zero-byte initializers.
Larger containing FF runs extend outside loads. Prior modeled native
load/reload tests do not prove physical cache coherence, MPU behavior, concurrent
reload safety, or update acceptance.

Cross-section calls require sections 1/4/9 resident together. Small hooks are
mostly section 9; menu hooks section 7; transport hook section 2. There is no
new scheduler exclusion or load-management code proving all interleavings safe.
RAM state lives in native `a320fc..fe..`, property records, JPEG buffers,
allocator/response/stack storage, not a newly persistent FF-tail state store.

The entry conventions matter: `6031eb90` is a jumped-to trampoline that replays
a call and returns by jump; `6031ee00` adjusts SP +4 for its replaced short-call
entry. `60a8f330/380` supply registers to native continuations, not standalone
functions. AF helpers use `[D2,D3],12`; capture shims synthesize native prologues
before mid-function jumps. Registration chains through `60a8f4a0→60a8f280→60a8f504`.
Embedded tables, padding, alternate entries, and shared epilogues must not be
reclaimed or casually relocated. In particular, linear disassembly through
table `60a8f370` is misleading; aligned entry `60a8f380` is established separately.

## Independently derived OM-3 stacking candidate

| Coordinate / instruction | Value |
| --- | --- |
| Routine | Runtime `[60901988,609019c2)`, **58 bytes** |
| Routine start | Payload `8e0968`, decoded-container `8e0988` |
| Candidate | **Decoded-container `8e099e`; payload `8e097e`; runtime `6090199e`** |
| Stock **and V22** preimage | **`c904`**, `BNE 609019a2` after `CMP 1,D0` |
| Experimental replacement | **`cbcb`**, two one-byte NOPs |
| Newly unconditional local fallthrough | `609019a0: MOV 1,D2` |
| Whole routine stock/V22 SHA-256 | `eea97532a3c608dcb4419c5aeca3643a1a0b2ad8bd26142e94b08dcbbde99b07` |

Localization is not an offset transplant. The NUL-terminated diagnostic
`fcs_check_focus_stacking_enable stacking` is unique in stock main at payload
`a1b8ac`, decoded-container `a1b8cc`, runtime `60a3c8cc`; its address operand
is inside the routine's instruction at `609019ae`. Unique guard/query/wrapper
anchors occur in both images. Direct caller `6090094a` establishes the routine
entry; consumer `60442601` calls that wrapper and propagates its Boolean through
native selector `0x200d9` property/menu helpers. Complete UI naming and computed
call reachability were not established by direct-call scans.

Only the following short instruction excerpt is needed to express the change:

```text
60901992  BNE 609019a2       ; earlier guard rejection RETAINED
60901994  CALL 602fdc68      ; capability query RETAINED
6090199b  EXTBU D0
6090199c  CMP 1,D0
6090199e  BNE 609019a2       ; c904 -> cbcb, remove ONLY this branch
609019a0  MOV 1,D2
```

The native routine begins with result D2=0, calls earlier guard wrapper
`602f3671→60152abf`, and returns low-byte D2 with its original
`RET [D2],8`. After the edit, normal-return behavior is:

| Condition | Stock / V22 | With eligibility edit |
| --- | --- | --- |
| Earlier guard low byte nonzero | Reject; query not called | Unchanged rejection |
| Guard=0, query object nonnull, byte **object+`1d133`=1** | Eligible | Eligible |
| Guard=0, nonnull object, capability byte not 1 | Reject | Eligible |
| Guard=0, query lookup returns null | Reject | Eligible **if this path is reached** |

Query `602fdc68` still calls lookup `602f6460(0)`, checks A0 for null, and only
then reads byte+`1d133`. Lookup uses pointer slot `a32c9c24` and status; its
status-one path retains call `602f3b81` and nested status/mask/ID helpers.
Removing the caller's result branch does not remove these calls or their effects.
The query's own null dereference protection remains, but its null-derived
failure result is conditionally ignored.

### Retained earlier guard and lens-safety limits

The OM-3 initial status byte `a32d3d32` **not equal to one returns reject=1**.
The guard then obtains the pointer via `602f6509(0)` and computes class from
u16 `a32c9c28` (special `0x0b0a`, otherwise mask `0x000a`). It retains
object+4 mask 1 and class-dependent four-byte ID tuples at object+1100 (`44c`).
Class-zero rejection includes `(0,0,8,1)` and portions of the `(1,0,*,*)`
family; class-nonzero rejection includes low-byte flag `a32d3d36=1` and
tuples `(6,0,1,10)` / `(2,0,11,10)` (tuple numbers here hexadecimal).
No marketing lens names or safe focus-drive characteristics are inferred.

**This is not a physical no-lens safety guarantee.** The earlier guard has no
explicit null check before its own object accesses. Status/pointer lifecycle,
attachment state, and races between guard and query are not proven. A
null-derived query failure is ignored only if the earlier guard permits
continuation; that is not proof a stable no-lens state can do so. Faults,
nonreturning native calls, incompatible drive behavior, and downstream engine
checks are not repaired.

The exact two-byte replacement preserves instruction locations, stack frame,
register-save conventions, call displacements, and return site. Both old BNEs
target `609019a2`; retained `MOV 1,D2` falls into the same block. No local edge
enters the second edited byte. Later debug logic tests freshly loaded flags
`a33f3620` mask `0x200`, not inherited condition codes. Diagnostic output would
report the changed result when enabled. This is local ABI/control-flow
qualification, not a claim about all computed callers or interrupts.

### E-M1 II comparison, not a recipe

The reference was read without checkout using
`git show em1ii-37-feature-patches:docs/features/em1-ii/FEATURE_PATCHES.md`,
at branch commit `92ceb5a2107e0116b4222562440ffe241f108831`.
The comparison pins that historical branch commit; the
[E-M1 II report](../em1-ii/FEATURE_PATCHES.md) is also available in this tree.

| Detail | E-M1 II 3.7 reference | Independently established OM-3 |
| --- | --- | --- |
| Candidate runtime / decoded-container | `60656a4a` / `635a2a` | `6090199e` / `8e099e` |
| Query | `60233c41` | `602fdc68` |
| Capability field | object+`1bc9f` | object+`1d133` |
| Guard ID tuple location | object+1092 | object+1100 |
| Initial status-failure behavior | Can permit caller continuation | **Rejects** |

The shared 58-byte skeleton corroborates, but does not establish, the OM-3
finding. Neither the older inline sentinel-table patch nor E-M1 II's
missing-lens behavior was imported.

## Composition decision and remaining regressions

`generated\om3_feature_analysis\composition-gate.json` records
**PASS for experimental static in-place composition**:

* The two stacking bytes overlap **none of all 35 V22 records**, including
  all six injection records. No stacking cave/helper/load dependency is added.
* **23 traced byte spans are unchanged** between stock and V22: eligibility,
  earlier guard/wrapper, query, lookup forms, status/class/flag helpers, preserved
  lookup subcalls and mask/ID helpers, direct wrapper/consumer, logger/output.
* V22 AF changes generate/select events; they do not replace that eligibility
  routine or guard.
* Eligibility and V22 property injection share **native section 4**
  `[60828000,60a8f800)`. Different feature labels do not mean separate residency.

No direct replacement-literal reference to the five traced core state addresses
was found, but that does not exclude computed access. Native lens/focus services,
property-driven state, capture engine, logging, scheduler, mode transitions,
and locks remain shared. **Global semantic independence and concurrency safety
are not proven.** The existing three V22 cave/load assumptions remain.

Behavior changes that can regress prior use:

* RAW USB/preset behavior becomes PC control; the separate Control row and
  query `0x874` are suppressed. Transport and enable/disable event selectors change.
* Prior control-state/equality notification suppression is replaced by vendor
  events at multiple sites; host assumptions may no longer hold.
* AF no-op/locking regions now emit payloads; exact coordinate and aggregate
  bit meanings remain unresolved.
* `9487/94B7`, out-of-range `9488`, JPEG sender failure, and no-object `9494`
  can report success without useful action or confirmed transfer/completion.
* Broad property advertisement does not establish every getter/setter in every
  mode; missing selected properties are silently skipped.
* Stacking changes eligibility, not physical drive compatibility, image quality,
  downstream capture success, recovery, or the underlying stacking engine.

The manifest author reports preset RAW live view confirmed at V22, popup RAW
at V21, and PC transfer at V17, explicitly not every inherited component.
Those are **author hardware claims**, not our measurements. The referenced
upstream hardware-result document is not independent local evidence. Likewise,
the contributor's recovery account is not a recovery guarantee.

## Reproduction, release policy, and artifact status

Use our independent tooling, not the downloaded script. Its script-relative
manifest lookup resolves incorrectly in the supplied layout. Its release-hash
guards also intentionally reject combining V22 with other changes; those
baseline identities must not be weakened or relabeled.

The independent [audit](../../../tools/om3_patch_audit.py) reconstructs release
identities in memory and exports analysis evidence, not an installable package.
The separate [builder](../../../tools/om3_feature_patch.py) emits the experimental
composition. Both CLI argument forms below were checked against actual `--help`.
From PowerShell at the repository root, using the verified WSL Python/GNU
environment and **new** output directories under an existing, git-ignored
parent (the slash-separated arguments below are interpreted inside WSL):

```powershell
wsl -- python3 -B tools/om3_patch_audit.py --stock "oly-firm/om-3-1.1/E1479999.BIN" --manifest "OM-3 patcher/patches/om3_pc_remote_v22.json" --out "generated/om3_feature_analysis/v22-reproduction"
wsl -- python3 -B tools/om3_feature_patch.py --stock "oly-firm/om-3-1.1/E1479999.BIN" --manifest "OM-3 patcher/patches/om3_pc_remote_v22.json" --out "generated/om3_feature_analysis/experimental-combined"
```

The second command is the separate experimental combined builder, not a new
V22 release. Exact stock/manifest pins, all preimages, component ownership,
nonoverlap, and exact baseline release reconstruction are prerequisites.
Only the proven stacking bytes and necessary checksum consequences may differ
from V22. Inputs and existing outputs must not be overwritten.

### Generated experimental artifact and completed checks

The delivered combined image is:

`generated\om3_feature_analysis\combined-rebuild\E1479999.BIN`

| Property | Verified value |
| --- | --- |
| Separate composition name | `OM-3-1.1-V22-plus-focus-stacking-experimental` |
| Encoded bytes | 240,517,120 |
| Encoded SHA-256 | `3e6fe11dacd247fc983e7c8857248c22c62f3799bfe57a5a8d80571c783e04d3` |
| Decoded main SHA-256 | `8ffe2a3226fb78b3037f3c487e56fb0a73430410fad3812761cf4c3700a6b9a9` |
| Combined main checksum word | `0x9444cd58` |
| Complete changes versus stock | 3,557 payload bytes + 4 checksum bytes = 3,561 encoded bytes |
| Complete changes versus V22 | 2 payload bytes + 2 checksum bytes = 4 encoded bytes |
| Additional raw stacking byte offsets | `0x8e099c`, `0x8e099f` |

The example command uses another output directory to avoid overwriting this
artifact. Do not substitute the V22 hash for a combined hash or call the
combined output V22.

The thirteen focused tests passed, including the opt-in exact stock/manifest
integration case, along with nine existing container tests. They exercise
source/release identity checks, preimage and context guards, overlap/component
boundaries, unallowlisted changes, malformed containers, input/output aliases,
exclusive creation and cleanup restricted to owned files. Rerun from PowerShell:

```powershell
wsl -- env OM3_ACTUAL_FIXTURES=1 python3 -B -m unittest discover -s tests -p test_om3_feature_patch.py -v
wsl -- python3 -B -m unittest discover -s tests -p test_oly_container.py -v
```

The full refactored audit also completed with disassembly and reproduced both
V22 release hashes without its former unrelated canonical-main dependency.
Two separately published combined outputs (`combined-output` and
`combined-rebuild`) have identical firmware hashes. The latter includes the
current builder/attribution provenance in `manifest.json`.

Independent final verification reread the persisted combined image and
reconstructed every allowed raw byte change directly from the permutation and
manifest, calculating the checksum adjustment from weighted decoded-byte
deltas. All six component checksums passed; exact decode/re-encode reproduced
the entire file; headers, trailer metadata and all five non-main components
remained unchanged. Reverting only the stacking bytes and checksum recovered
the exact V22 encoded release hash. Original firmware, downloaded script and
manifest hashes remained unchanged.

The final saved main's eligibility window was disassembled again: both new
instructions are NOPs, the earlier guard/query and surrounding routine remain
unchanged, and no other decoded difference from V22 exists.
`independent-validation.json`, `combined-stacking.asm` and the analysis-only
decoded main sit beside the delivered image. These checks establish integrity
and static composition, **not execution of the patched firmware**.

Persistent local evidence, intentionally not vendor binaries in documentation:

* `generated\om3_feature_analysis\baseline\audit.json`, `edits.tsv` and
  `artifacts.json`: six components, mappings, guards, checksums and release hashes.
* `generated\om3_feature_analysis\usb_trace\tables-and-edits.json`: decoded
  operation/event/property tables and per-edit effects; bounded assembly under
  that directory and baseline `assembly`.
* `generated\om3_feature_analysis\stacking\trace-facts.json`: exact routine,
  unique anchors, 23 span comparisons/hashes and stock/V22 assembly.
* `generated\om3_feature_analysis\composition-gate.json`: scope-limited decision.

These establish reproducible static evidence. Native execution, camera
interoperability, boot/update acceptance and flashing safety remain unvalidated.
