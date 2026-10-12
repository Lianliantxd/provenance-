# Stage B0 preflight report — 20261012T085941Z

## Host and workspace

- Host: [private-server]; user: [redacted-user] (uid 1004).
- SSH reached through the configured host [private-server-address] using the existing user key id_ed25519_vscode_traffic; no key material was printed or copied.
- User-designated parent directory exists literally as [private-project-workspace] (the name has a trailing space). It is user-owned, not a symlink, and not a Git worktree. Existing provenance files were left untouched.
- New project root: [private-project-workspace]/APT_Process_Tracing_Pilot/diagchain_l2_repro. It was absent before creation, is a direct user-owned child, and is not a symlink or Git worktree.
- Filesystem /home: 37 TiB total, 19 TiB available at preflight. RAM: 251 GiB total, 222 GiB available. 104 CPUs. Load average was 32.95/33.28/37.68 with 37 logged-in users; this is about 32% of the CPU count. Any later CPU job remains single-process, CPU-only, with at most two library threads.
- Host system Python is /usr/bin/python3, version 3.12.3. An existing user-managed interpreter at [preinstalled-python-base]/bin/python3 is 3.12.4.

## Source verification

- Frozen local release checkout: 60e04064f9b3cf59505ee159379cf851956b8394; local Git status was clean.
- Stage A and release package manifests were checked against the selected source files before transfer. Selected L2 input hashes are recorded in transfer_manifest.json and 04_case_input_manifest.json.
- No DiagChain PACKAGE_MANIFEST.json or source checkout was found in the expected server home search. Only a small, selected transfer package was copied into this new project. It contains the two published L2 input files, schemas, evaluator source and evaluator-only Gold. Retrieval docs/graphs were not copied because the T2 fixed-evidence pilot does not use active ECRAG.
- The available release tree did not contain an existing deterministic planner named DETERMINISTIC_PLANNER; the existing agentic controller is model/API-oriented. Do not substitute it or a newly invented heuristic and call it the existing baseline.

## Safety and scope

- No system packages, services, network settings, other project environments, original source trees, or original data were changed.
- No attack script, PoC, vulnerable service, model call, network retrieval, or evaluator was run.
- Gold files are under the project evaluator_only/ directory with restrictive permissions. This is filesystem organization under one account, not OS-level isolation.
