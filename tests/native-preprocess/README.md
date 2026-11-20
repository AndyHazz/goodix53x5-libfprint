# Native preprocessing parity fixtures

Three synthetic-only cases protect independent preprocessing behavior with fixed
inputs and complete per-call DLL-observed output projections. CI executes real
production code linked with `libfprint_drivers`; no runtime substitution seam,
Wine, proprietary DLL, hardware, or expected-output generator is needed in CI.

**No personal biometric images, captures, templates, seeds, or derivatives were
used, including as inspiration or generator inputs.** The only input producer
is the fixed arithmetic in `generate.py`. It reproduces the mathematical frame
formula in `test-goodix53x5-milan-synthetic-support.c` and the normalized temporal
formula in `test-goodix53x5-milan-synthetic-temporal.c`. CI reads frozen binary
inputs rather than regenerating them through changing production producers.

## Cases and native authority

All cases use approved `GoodixEngineAdapter.dll` 2.0.310.900, SHA-256
`6673db3874fea66a58e2da29e371d797b890c767ba0491134d4a372c5b27e3b4`,
profile 9 / sensor type 12. Each case runs in a fresh process during generation.

| Case | Boundary and chronology | Observable distinction |
| --- | --- | --- |
| `natural` | `ppp_param_init(9)`, `preprocess_init_calidata`, `preprocessor_get_CalibParam`, `preprocessor_init`, then 24 exported `preprocessor` calls, purpose identify, both switches zero | Calls 1–4 succeed; calls 5–24 return `0x7531` while publishing substantive processed bytes. Calibration samples pause at 4 through call 22 while reference history and ages keep advancing. Calls 23/24 advance samples to 5/6. |
| `temporal-800` | Native publication wrapper RVA `0x6b290`, 22 normalized classifier-boundary calls | Final flat difference removes primary edges but retains 267 class-3 pixels; final status 0, mode 6, apply 1. |
| `temporal-0` | Same wrapper and chronology, without the 800-unit band | Call 21 crosses maturity: 3,024 class-3 pixels, status `0xc351`, mode 9, apply 1; these persist on the final flat difference. |

Current counterparts are `goodix_milan_preprocess` for `natural`, and
`goodix_milan_profile9_build_broken_mask` for temporal cases. Temporal CI also
calls the real `goodix_milan_profile9_build_contrast_mask` and compares its entire
result against the frozen contrast input supplied to the DLL.

The natural sequence uses normal native initialization and a fresh current reset.
It never assigns sample counts or imports calibration/history maps. Calls 1–22
repeat the first live plane; calls 23–24 use `live = setup - 600`.

The temporal cases are explicitly **valid manually supplied classifier
boundaries**, not complete raw acquisition/preprocessing sequences. After normal
profile/calibration-global initialization, the helper supplies the normalized
setup plane at workspace `+0x9924`, a full-one contrast plane, packed type-12
geometry `0x36160061`, and caller sample count 1 through 22. The current caller
supplies the identical inputs/counts. Neither side seeds internal reference
history or ages: the real classifier retains and evolves these across calls.
Calls 1–21 use the patterned difference; call 22 uses constant difference 6395.
Both modes finish with `preprocessor_exit` and DLL unload.

## Fixed binary protocol

There are no pointer values, C struct padding, hashes in place of planes, skipped
pixel bits, or output normalization. Integers are explicitly little-endian.
Input files contain three 9,504-word unsigned-16 planes in order: setup, first
live, final live. Temporal files additionally contain the 9,504-byte contrast
plane. Natural input length is 57,024 bytes; temporal input length is 66,528.
The call schedule above is fixed by the case, not inferred from output status.
Current temporal difference is the exact subtraction of these frozen setup/live
inputs, matching the native wrapper's source boundary.

Output files concatenate the following record for **every call**, in order:

| Field | Encoding | Natural | Temporal |
| --- | --- | --- | --- |
| Return status | i32 | yes | yes |
| Quality / classifier mode | i32 | quality | mode |
| Coverage / mask application | i32 | coverage | apply |
| Extraction auxiliary | 3 bytes | yes | yes |
| Full output plane | 9,504 bytes | processed image | published broken mask |
| Calibration sample count | u32 | yes | omitted |
| History count | u32 | yes | yes |
| Full history reference | 9,504 u16 words | yes | yes |
| Full reference ages | 9,504 bytes | yes | yes |

Auxiliary byte 1 is the fixed zero entry selector of this ordinary-call protocol;
current's state exposes only the two histogram bytes, so the projection includes
that supplied zero between them. Native bytes are read without modification.
Native quality/coverage output-pair order is coverage first, quality second;
the wire format explicitly labels and writes quality first. Native descriptor
quality/coverage are also checked against the returned pair.

Native history addresses are RVAs `0x1dc9a4` (count), `0x1dc9b0` (reference), and
`0x1e62d0` (ages). Calibration count is the first dword of the native calibration
owner. These addresses are meaningful only for the pinned DLL.

Natural records are 38,039 bytes (912,936 total); each temporal case has 22 records
of 38,035 bytes (836,770 total). The six binary artifacts total 2,776,556 bytes.
CI rejects truncated or trailing bytes, compares every field/plane before
independent behavior assertions, and reports case, call, field, byte offset,
record offset, and differing values.

This is the **complete defined observed projection**, not complete native state:
other calibration fields, component ages, internal class-1/2 planes, renderer
scratch and other unobserved state are outside it. There is no claim about
persisted history import, every possible frame, USB/hardware chronology,
matching, enrollment, extraction/packing, or authentication outcomes.

## Reproduction

Use an explicitly approved DLL and an already initialized Wine prefix with Z:
mapped to `/`. Existing Python 3, Wine, and `x86_64-w64-mingw32-gcc` suffice; the
launcher installs nothing and does not create or initialize a prefix.

```sh
python3 tests/native-preprocess/generate.py \
  --dll /absolute/path/to/approved/GoodixEngineAdapter.dll \
  --wine-prefix /absolute/path/to/existing-prefix \
  --verify
```

`--verify` regenerates all six artifacts in temporary storage, runs each case
twice in fresh native processes, requires byte-identical repetitions and exact
frozen artifact equality, and leaves fixtures/provenance untouched. To produce
a proposed fixture set, replace `--verify` with `--output /path/to/new-directory`;
the output directory must not exist. There is no external image, seed, template,
capture, or arbitrary exporter option. The small native executable is internal
to this launcher and is not a public capture runner.

The launcher verifies the DLL hash and existing prefix, and uses the same
resolved-prefix SHA-256 lock name as the Milan parity tooling's native runner,
under `${XDG_CACHE_HOME:-~/.cache}/milan-parity`. It never loads current production code
to compute expectations. Shared C helpers only encode/decode the wire format.
Provenance records all artifact identities, generator sources, native boundary
addresses, call observations, and tool versions. Reproduction reports tool/source
identity drift without rewriting original provenance; CI does not require a
particular generator toolchain or compare toolchain provenance.

Build and run:

```sh
GOODIX53X5_DEBUG=0 GOODIX_LIBFPRINT_OFFLINE=1 ./scripts/build-local.sh
meson test -C .build/libfprint/builddir --print-errorlogs goodix53x5-milan-native-preprocess
```

The fixture tooling is independent of the Milan parity tooling's command
surface. Suggested mutation checks include loss of retry output/history,
incorrect sample advancement, temporal maturity/promotion changes, and replacing
the percentile-gap temporal threshold with the old primary-mode cap.
