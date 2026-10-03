# Mathematical native matcher fixtures

Four cases, each with compressed frozen probe, gallery, DLL-packed after-match
gallery and native decision/rank observation. No personal biometric material or
historical binary datasets were used. See `../README.md` for producers, exact
boundaries, limitations and reproduction.

Every `.bin.gz` is a single lossless gzip member with timestamp zero and no
filename. `provenance.json` seals raw and compressed hashes/sizes separately.
Native authority is the raw decompressed output, not a specific zlib bitstream.
Verification preserves the original container identity while allowing a fresh
compressor to reproduce identical raw bytes differently. Do not edit expected
bytes to fit current output; regenerate through the approved native observer.
