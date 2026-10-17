# E5 fixed-candidate rich-field mapping

76 frozen Event positions and 32 necessary entity definitions were extracted with one bounded sequential gzip replay. All108 records matched their frozen index fields and target block boundaries. No additional attack candidates were added.

13 object READ records involve12 actual subjects. Every core Event contains properties and an exec key; those values, private identifiers and complete records are withheld. Exec is an arbitrary sensor property, not a guaranteed complete command line. Positive size is recorded for11 READs, zero for2; a separate return-value key is absent for all13. This does not establish content exfiltration.

Final qualification: **CAND76_RICH_FIELDS_COMPLETE_B_UNRESOLVED**, with **B_RAW_EVENTS_KNOWN_REPORT_LINK_UNRESOLVED**. Host identity and report/sensor clock correspondence have no independent binding. Report naming/branch conflicts are retained. No single attack event or attack equivalence set has been asserted.

The replay delivered2,083,017,582 expanded bytes, including2,082,955,492 skipped bytes, while attempting108 top-level CDM decodes. It stopped after the highest requested block and sync. This run did not reach EOF or revalidate the full gzip CRC; historical EOF evidence remains separate. There was no new download, model call, GPU use, attack execution, installation or source/path scoring.

`summary.json` contains only aggregate results. `bounded_locator_helpers.py` contains generic helpers extracted from the private runner; it is not a standalone full-member scanner and contains no payload or case identifiers. Existing readers and private locators are deliberately omitted. Tool validation used small synthetic fixtures; these are not research performance results.

SHA256SUMS covers these public files, excluding itself. Raw Event properties, command labels, entity identifiers, host mappings, source databases, and report-to-event correspondence remain in the authorized private project stores. Source compressed-file integrity hashes are public checksums, not a release of the data.
