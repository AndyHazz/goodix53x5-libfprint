# Synthetic native study fixtures

Only two mathematical competing-candidate matcher→study cases are covered:
different coverage chooses physical slot 3; a coverage tie retains slot 1.
Both naturally match slot 2 at score 100 and produce study action 4.

`probe.bin` and `*-gallery.bin` are frozen synthetic inputs. `*-match.bin` and
`*-study.bin` are complete outputs of the approved DLL's `templateGetPackedSize`
and `templatePack`, without masking or current-driver output calculation.
`provenance.json` records source and artifact SHA-256 identities.

See [the generator documentation](../README.md) for origin, reproduction and limits.
