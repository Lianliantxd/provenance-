# Fixed OPEN identity-scope read closure

All24 frozen exact-path OPEN anchors were queried against the two sealed indices, across the full member time scope and both object slots. All96 candidate statements completed using the existing subject index. No time-after-OPEN or application-name filter was used.

The query returned65 unique Events:24 OPEN,20 READ and21 CLOSE. All13 previously reviewed READs were recovered. Seven additional READs were found in the third host/object scope; these are new source positions relative to the previous candidate set. This expands the declared candidate range and does not establish attack membership.

There are20 OPEN-to-READ and21 OPEN-to-CLOSE relations, not41 new READ events. Within this scope,34 relations support prior OPEN context and7 have temporal/descriptor conflicts. Same identity alone is not a unique handle session. No assertion is made about complete descriptor lifecycles, other-object duplication, inherited handles, unknown OPENs, aliases or other members. Query-complete zero READ counts are limited to their declared identity scopes.

51 complete Event records and24 direct Subject definitions were reused privately. One conditional gzip replay extracted14 previously missing records, with14 total top-level decode attempts. It delivered1,917,320,658 expanded bytes including1,917,278,341 skipped bytes, and stopped after the highest target block sync. It did not reach EOF or revalidate full-stream CRC. Old index hashes were inherited from sealed receipts and checked by identity/schema/source metadata, not recomputed this round.

Final status: **OPEN24_QUERY_COMPLETE_WITH_ADDITIONAL_READ_CANDIDATES**. Report-to-execution binding remains unresolved and no attack handoff or source/path score was generated. No model, GPU, new data download, attack program or installation was used.

`identity_scope_helpers.py` contains generic helpers extracted from the private query/context entry point. It is not a standalone dataset runner. `PUBLIC_MANIFEST.json` gives checksums for the other public files and excludes itself. Complete records, application labels, private identities, locators and reference mappings are withheld.
