# Synthetic native matcher decision goldens

Four fixed mathematical cases exercise the real profile-9/type-12 matcher.
CI compares the exact length and every byte of the complete after-match gallery
against the approved DLL's own `templateGetPackedSize`/`templatePack` output.
A separate 144-byte native observation records decisions that gallery bytes
alone do not expose. No study call, mocked result, or runtime seam is involved.

## Cases and demonstrated native outcomes

| Case | Score | Physical winner | Direct x translation (Q8) | Relation count | Occupied queue slots | Packed gallery bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `bitmap-48` | 100 | 1 | 0 | 42 | 1 | 327,036 |
| `bitmap-56` | -7 | -1 | 0 | 0 | 1 | 327,036 |
| `order-1` | 100 | 1 | 0 | 42 | 0 | 331,804 |
| `order-2` | 100 | 2 | 1024 | 42 | 0 | 331,804 |

All native call statuses are zero. All routed affine observations are identity;
the zero-count rejected relation is initialized output, not an established
relation. Direct affines are identity apart from `order-2`'s translation.
Bitmap cases have physical queue ranks `[0, -1, ...]`; order cases have twenty
`-1` ranks. The test compares all twenty ranks, not just occupancy.

The bitmap pair preserves descriptors, positions, angles, masks and gallery
while flipping the first 48 or 56 bytes of all three probe maps. It distinguishes
recognition rejection from queue admission and successful lifecycle updates.
The order pair preserves physical features and changes their serialized
traversal order. A four-pixel-translated feature and its corresponding graph
relation distinguish selected direct affine from routed relation. They also
protect physical lifecycle ownership and skipping later active features.

These cases promote the construction used by `state-bitmap.c` and
`state-match-order.c` into independently reproducible native goldens. They add
different behavior from the competing study replacements in `native-study`.

## Origin and shared boundary

**All input material is mathematical. No biometric captures, images, templates,
seeds, derivatives, or historical binary datasets are used.**

`test-goodix53x5-milan-native-match-inputs.c` constructs the fixed cases from
`ordered_match_feature()` and `study_gallery()`: arithmetic descriptors,
regular coordinate grids, canonical angles and balanced bitmap patterns.
The exporter only constructs inputs; it never invokes matching or computes
expected outputs. It accepts an output directory, not input data.

Native and current receive the same frozen serialized probe and gallery. Native
unpacks using `templateUnPack`, selects the sole probe feature and calls the
actual dispatcher at RVA `0x5edb0`. The current test reconstructs the complete
match-info owner from that same serialized probe and calls
`goodix_milan_match_serialized_feature_result_queued()` with a fresh queue
initialized to state 0/counter 7, matching these galleries. Records are decoded
from the frozen bytes; current producers do not regenerate CI inputs.

This is a serialized matcher-boundary comparison, not extraction parity or
sensor/enrollment chronology. The probe's fixed all-valid rescue mask and
serialized record representation follow the existing mathematical producer.
Native initializes profile 9 and calibration parameters as in `native-study`.
Its final dispatcher argument is null; the gallery still naturally owns the
observed queue ranks. No queue entries or match evidence are supplied as input.

## Exact output contract

The `*-match.bin.gz` members contain **unmodified complete DLL-packed galleries**.
Comparison is before any decoded-output assertions; no normalization, field
filtering, or current-code expected-value calculation is applied to these bytes.
Four galleries total **1,317,680 bytes**.

Each `*-observation.bin.gz` member contains 36 little-endian 32-bit words:

| Words | Native observation | Current correspondence |
| --- | --- | --- |
| 0 | Dispatcher return status | Serialized matcher return status (success domain) |
| 1 | Returned score | `result.score` |
| 2 | Evidence `+0x648`, physical winner (-1 absent) | `matched_feature_index`, absent `SIZE_MAX` encoded as -1 |
| 3 | Evidence `+0x668`, relation count | `relation.relation_count` |
| 4–9 | Evidence `+0x650`, direct affine | `match_transform[6]` |
| 10–15 | Evidence `+0x66c`, routed affine | `relation.relation_values[1..6]` |
| 16–35 | Gallery `+0x8db0`, twenty physical ranks | `queue.entries[i].rank` |

The format header only encodes integer byte order. It does not implement native
decisions. Observations are taken before DLL packing. The complete expected
boundary is **1,318,256 bytes** including these four records. Diagnostic failures
identify case, boundary, byte offset and, for observation decoding, word index.

Queue coverage is explicitly a **rank projection**. Occupied-owner records,
bitmaps, lifecycle payload, pointers, allocation and destruction behavior are
not compared. No complete queue/owner parity, repeated-handle sequence, action 5,
multi-contributor scoring, non-100 positive scoring or entire-policy parity is
claimed. The negative case stops after matching; rejection is not represented
as a fabricated action-zero study.

## Compressed storage

All sixteen binary artifacts are single-member `.bin.gz` containers. Gzip is
lossless storage only: CI checks exact **decompressed native bytes**. Total raw
input/output size is **2,692,648 bytes**, stored in **85,472 compressed bytes**
with the original toolchain. The repository-root `.gitattributes` marks `*.bin.gz`
binary and Linguist-generated. Zero timestamp/no filename gzip headers also
contain NUL bytes, avoiding GitHub's text-line classification of some raw inputs.

Generation uses Python standard-library `gzip.GzipFile` with `mtime=0`,
`filename=''`, compression level 9. CI uses existing GIO `GZlibDecompressor`,
bounded by each fixed expected length plus one byte. It requires a complete
gzip member, validates the gzip CRC, consumes the entire compressed input and
requires the exact raw length. Truncation, CRC corruption, oversized or short
output, trailing bytes and concatenated members fail.

Provenance records **both raw and compressed hashes/sizes**. Native repetitions
compare complete uncompressed bytes before compression. `--verify` checks the
original container against its recorded compressed identity, then compares its
decompressed content to freshly produced inputs and native outputs. A different
zlib version may emit a different valid bitstream; that alone does not fail
reproduction or replace the original compressed evidence.

## Reproduction

Build this checkout's pinned overlay first:

```sh
GOODIX53X5_DEBUG=0 GOODIX_LIBFPRINT_OFFLINE=1 ./scripts/build-local.sh
python3 tests/native-match/generate.py \
  --dll /absolute/path/to/approved/GoodixEngineAdapter.dll \
  --wine-prefix /absolute/path/to/existing/prefix \
  --verify
```

Use `--output /new/directory` instead of `--verify` to create fresh containers
and provenance for review. The directory must not already exist. There is no
imported-capture option, external exporter option, prefix initialization or
dependency installation. The launcher verifies SHA-256
`6673db3874fea66a58e2da29e371d797b890c767ba0491134d4a372c5b27e3b4`, verifies the
existing prefix, checks exporter/driver overlay source identity, and uses the
same resolved-prefix lock as the maintained native runner. Each of the four
cases runs twice in fresh native processes and must reproduce both outputs and
logs exactly. Source/toolchain identities and native observations are recorded.

CI needs neither Wine nor the proprietary DLL:

```sh
meson test -C .build/libfprint/builddir --print-errorlogs \
  goodix53x5-milan-native-match
```
