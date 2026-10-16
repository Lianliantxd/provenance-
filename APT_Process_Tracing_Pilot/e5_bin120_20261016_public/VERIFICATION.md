# Conditional verification (not executed in this round)

Approved file: `ta1-cadets-1-e5-official-2.bin.120.gz`

- Registered compressed size: `299647139` bytes.
- Official reference MD5: `09e6d64ac074582833eee1ab3cb2a34a`, from the already acquired official `bins.md5sum`.
- SHA-256: must be computed from actually received bytes; no received-file SHA-256 exists for this attempt.

For an existing independently authorized file, Python standard-library `Path.stat().st_size`, streaming `hashlib.md5()` and `hashlib.sha256()` can verify these values without decompression. The size and official MD5 above are reference values, not successful checks. Do not obtain another file or retry acquisition under this receipt.

The frozen conditional probe bounds are 250,000 total CDM records, 1 GiB expanded bytes, 600 seconds and a 4 GiB memory target. This probe was not launched because no input was received. Any later probe must count all decoded record types, distinguish limit termination from true gzip EOF, and report only the portion actually read. No whole-member coverage or target absence can be inferred here.

The public `SHA256SUMS` authenticates this report bundle's bytes only; it is not the missing member's checksum.
