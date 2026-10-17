# Verification and limits

Raw member: `ta1-cadets-1-e5-official-2.bin.120.gz`. Received size `299647139`; actual/official MD5 `09e6d64ac074582833eee1ab3cb2a34a`; computed SHA-256 `2d4369553a54abe3986b2d0482656a9813acafd4e978cb8a304b5cf7b5dddaf9`. Hashes were computed together in streaming passes over each user-supplied complete compressed copy, with stable file identities before/after. MD5 agreement binds the publisher reference; it is not a guarantee of semantic safety or label correctness.

The gzip and Avro OCF header, embedded schema, namespace and null codec were identified from this member. Event timestamps use the schema's explicit Unix epoch nanosecond definition; conversions split integer seconds/nanoseconds without floating point. Report-console alignment remains unverified.

Limits: at most 250000 total top-level records including non-Events; 1073741824 bytes delivered by gzip to the reader; 600 seconds; 4 GiB process address-space limit plus RSS supervision on Linux. Internal gzip read-ahead is not measured as exact decompressed output. No non-null inner codec is accepted. No full gzip test or full expanded file was produced.

`source_fields_used` and private locators are retained in the private summary. Record ordinals/block positions are sequential locators, not arbitrary random-access gzip byte offsets. A budget stop is not a parse failure and does not establish EOF. Null/zero aggregate values in this report refer only to measured scope.

Payload-free code is under `scripts/`; small synthetic checks are under `tests/`. Use an existing approved project interpreter with `PYTHONDONTWRITEBYTECODE=1`; no packages need installation. The bounded entry requires a private intake JSON containing the verified input identity/checksums and a private target reference. This publication intentionally omits that report-to-event mapping. The original reader's standalone unbounded inventory entry was not used.

`SHA256SUMS` authenticates this public report/code bundle only. The raw gzip is not stored in Git or Git LFS.
