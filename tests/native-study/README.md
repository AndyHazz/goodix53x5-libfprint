# Synthetic native matcher → study byte goldens

This suite freezes two demonstrated sensor-type-12/profile-9 matcher-boundary
cases. Different candidate coverage selects slot 3; a complete tie selects the
first physical candidate, slot 1. Both use the actual score-100 match at slot 2
and naturally take study action 4. The real production matcher output, mutated
gallery and same initially empty queue feed the real production study function.
The executable links `libfprint_drivers`, without the runtime test seam.

The primary assertions compare every byte and the exact length of the complete
after-match and after-study serializations against DLL-packed expectations.
Comparison does not invoke a driver decoder or normalize output. Failures name
the phase and first differing byte offset. Admission, score, winner, action,
selection and empty-queue assertions provide additional diagnostics.

## Origin and native authority

**Every input is mathematical test material. No personal biometric capture,
image, template or derived data is used, including as a generation seed.**
The exporter uses the existing `study_candidate_feature`, `ordered_match_feature`
and `study_gallery` generators in the state test sources. Those create regular
150-record coordinate grids, arithmetic descriptors and bitmap patterns, with
zero anti-fake material on the competing features. The second candidate is
translated; candidate coverage is 70/100/69 or 70/100/70. Serialized order starts
at slot 2; the existing synthetic relation adjustment is retained.

The current codec packs **inputs only**, explicitly during regeneration. CI
reads the frozen input files and never runs their generator. Complete native
outputs come from `GoodixEngineAdapter.dll` package **2.0.310.900**, SHA-256
`6673db3874fea66a58e2da29e371d797b890c767ba0491134d4a372c5b27e3b4`.
The small x64 helper initializes profile 9, calls native matcher RVA `0x5edb0`,
passes its returned evidence directly into native study RVA `0x44fc0`, and calls
the DLL's `templateGetPackedSize`/`templatePack` at both boundaries. It checks
statuses, non-null owners, packed sizes and the demonstrated native outcomes.
Each case runs in two fresh processes and all native bytes must repeat exactly.
There is no probe-packer reconstruction or expectation calculated by current code.

These are synthetic serialized matcher-boundary transactions, **not raw sensor
or enrollment chronology**, positive raw-frame recognition, multi-operation
queue coverage, or a guarantee of universal native parity. The auxiliary
match-info rescue mask is the all-ones mask of the existing synthetic fixture;
it is not captured state. These cases leave the current queue empty. The native
matcher is called without a queue owner, as in the demonstrated boundary helper;
this suite makes no claim of complete native queue-state parity.

## Run CI locally

```sh
GOODIX53X5_DEBUG=0 ./scripts/build-local.sh
meson test -C .build/libfprint/builddir --print-errorlogs goodix53x5-milan-native-study
```

The build script copies the fixed fixtures into the pinned libfprint source
overlay. CI explicitly runs this suite; neither Wine nor the DLL is needed.
The seven uncompressed `.bin` files total about 2 MB, keeping byte inspection
simple and requiring no compression dependency.

## Explicit reproduction

Use an already initialized Wine prefix, an independently approved copy of the
exact DLL above, installed Wine and `x86_64-w64-mingw32-gcc`, and a fresh local
non-debug build. No dependencies or prefixes are installed by the generator.
It verifies the DLL hash and existing prefix, checks the source overlay against
this checkout, rebuilds the input exporter, and serializes Wine execution using
the same resolved-prefix lock as the maintained parity runner.

```sh
python3 tests/native-study/generate.py --dll "$APPROVED_DLL" \
  --wine-prefix "$EXISTING_WINEPREFIX" --verify

# Optional: write a NEW directory for explicit review, never overwrite goldens.
python3 tests/native-study/generate.py --dll "$APPROVED_DLL" \
  --wine-prefix "$EXISTING_WINEPREFIX" --output .build/native-study-regenerated
```

The public generator accepts no input files, corpus paths, capture paths, seeds,
or external exporter executable. It only uses freshly produced mathematical
inputs from tracked code. `native.c` is an internal subprocess of this launcher.
Do not invoke it with personal data. `--verify` compares all seven artifacts
without rewriting them. Source/toolchain provenance drift is reported separately
when bytes still reproduce; the original record is retained. `provenance.json`
records native identity, observed algorithm version/outcomes, generator-source
hashes, the input codec source identity and every complete artifact hash/size.
It contains no machine paths, private artifacts or reverse-engineering notes.
