# Related tools, methods and research

Surveyed 2026-11-04 (web search, READMEs, project schemas, paper abstracts). Goal: sharpen the concept in [product.md](../product.md) and find features that address problems specific to this tool. Nothing here is decided; each candidate needs an H1 plan item, and those marked H2 need an ADR.

The two problems specific to this tool:

| # | Problem | Evidence |
|---|---|---|
| A | Too much outside the baseline | 69.1 % on a real Win11 host (P1-3b) against a < 5 % target (product.md §4) |
| B | NTFS metadata alone shows no file content, no creating process and no execution | product.md §1 "Out of reach" |

## Similar tools

| Tool | What it does | Difference from this tool |
|---|---|---|
| ntfs-forensic (SecurityRonin, MIT, 2026) | Severity-graded anomalies from `$MFT`/`$J`/`$LogFile`: timestomping, journal clearing, ransomware mass rename, ADS, MFTMirr mismatch; a `TriageEngine` with 12 built-in questions | Closest competitor and successor of `usnjrnl-forensic` (product.md §3 still lists the archived one). No baseline diff, no Sigma. Claims are from its README, not verified |
| IRFlow Timeline | GUI over CSV/EVTX/Plaso/raw `$MFT`/`$J`: ransomware analysis (5-min correlation window), timestomp detector, ADS analyzer, heatmap, stacking | Ranks findings by score; this tool does not score |
| Chainsaw (GPL-3.0) | Sigma hunting over event logs; MFT dump and data-stream search | No source shows Sigma applied to MFT records |
| THOR Lite / signature-base (DRL 1.1) | `filename-iocs.txt`: `REGEX;SCORE[;FP_REGEX]` path IOCs | Convertible to Sigma `TargetFilename\|re`, but product-named and scored (ADR 0019) |
| Velociraptor | `Windows.NTFS.MFT`, `Windows.Forensics.Usn`, `Windows.Detection.Yara.NTFS` (MFT filter, then YARA) | Live endpoints; the layer that reads content |
| Hayabusa / Takajo, Timesketch Sigma analyzer | Sigma over event logs / timelines | Complementary; covered by ADR P4-0e |
| MFTECmd, MFTMactime, MFTDigger, mft2bodyfile | Parsers / timelines | No guidance (product.md P4) |

## Research

| Work | Finding | Relevance |
|---|---|---|
| Oh, Lee, Hwang, "Forensic Detection of Timestamp Manipulation for Digital Forensic Investigation", IEEE Access 2024 | Journal-based detection is the most effective of the methods compared | Candidate 1 |
| Palmbach, Breitinger, "Artifacts for detecting timestamp manipulation in NTFS on Windows and their reliability", FSI:DI | No artifact withstands active manipulation | Timestomp rules stay below `critical` (ADR 0016) |
| Bouma et al., "Reconstructing Timelines: From NTFS Timestamps to File Histories", ARES 2023 | `$LogFile` validates timestamps | `$LogFile` is outside our inputs |
| Iman et al., "Anomalous File System Activity Detection Through Temporal Association Rule Mining", ICISSP 2023 | Temporal association rules over USN; 87.7 % of files affected by a ransomware case identified | Supports USN correlations (candidate 3) |
| Marková, Krišáková, Sokol, DFRWS EU 2024 | ECOD, Isolation Forest, LOF, PCA and formal concept analysis on NTFS records and event logs | Outlier scores; rejected below. Full text not read (HTTP 403) |
| Mandiant data stacking; Kansa `Get-LogparserStack` | Least-frequency analysis across hosts | Done outside the tool (UNIX philosophy) |

## Topics

| Topic | Use here | Verdict |
|---|---|---|
| LOLBAS (GPL-3.0) | `Full_Path` lists where each binary normally lives. Fact: a known LOLBin name outside its listed paths. Widens `system_binary_outside_system32` to ~200 binaries | Yes, as runtime data (ADR 0006) |
| HijackLibs (GPL-3.0) | `ExpectedLocations` and `VulnerableExecutables`. Facts: a hijackable DLL outside its expected locations; a vulnerable `.exe` and that DLL created in the same directory. DLL side-loading is visible from NTFS alone | Yes, the best fit |
| LOLBin | Execution and command lines are not visible; only file placement, copies and renames | Covered by LOLBAS |
| LOLRMM (Apache-2.0) | ADR 0019 removed product-named rules. Two other uses: (a) `InstallationPaths` as an explanatory label ("this path belongs to an RMM tool"); (b) USN write times of `Artifacts.Disk` logs (e.g. AnyDesk `connection_trace.txt`) as remote-session times even after event logs are wiped | Later; new ADR for the `tool-rules` repo. (b) needs `DATA_*` events, which are not emitted today |
| Sigma | Correlations (ADR P4-0c), incl. `value_count`; a written field convention for NTFS facts (`SiCreatedBeforeFnCreated` etc.), proposed upstream by a human | Yes |
| YARA | Only resident data (≲ 700 bytes) is readable. YARA on names/paths duplicates Sigma (one way to do a thing). Content scanning belongs to Velociraptor or THOR, fed with paths from our JSONL | No; a recipe in the manual |
| Statistics | Outlier scores break "no computed scores", determinism (Isolation Forest is randomized) and explainability. Allowed: counts as facts with thresholds in Sigma correlations; statistics in evaluation (per-rule false-positive counts on clean hosts, recall on the attack corpus, Wilson intervals) as evidence for ADR 0016 levels. Cross-host stacking stays in `jq`/Takajo | Evaluation and counts only |

## Candidates

| # | Candidate | Need | Problem | Notes |
|---|---|---|---|---|
| 1 | Fact: `$SI` created time earlier than the first `FILE_CREATE` of the same entry + sequence inside USN coverage | P1, P7 | A | Stronger than `$SI` < `$FN` (true for 76–90 % of files, [detection-gaps.md](detection-gaps.md)); backed by Oh et al. 2024. No new data |
| 2 | Facts from reference data: `KnownBinaryUnexpectedLocation` (LOLBAS), `HijackableDllUnexpectedLocation` (HijackLibs), `KnownVulnerableDriverName` (LOLDrivers); rules stay generic | P4, P7 | A, B | H2 (ADR 0006 implementation, ADR 0019). Name-only matching; renaming evades it |
| 3 | Ransomware correlations: mass rename to one new extension (`event_count`); one file name created in many directories (`value_count`) | P1 | B | Part of P4-9. Needs `FileName` / `ParentDirectory` fields, outside ADR P4-0c's current scope |
| 4 | Fact: `Zone.Identifier` `HostUrl` / `ReferrerUrl` (resident ADS) | P4 | B | Download origin for the primary user. P2-7 put it out of scope (H5) |
| 5 | Per-rule false-positive and recall statistics with intervals | ADR 0016 | A | Inside P4-0f / P4-19; nothing at runtime |
| 6 | Docs: update product.md §3 (ntfs-forensic, IRFlow, Chainsaw MFT); manual recipes for YARA/THOR hand-off and cross-host stacking with `jq` | P4, P6 | — | No code |

Suggested order: 1, 3, 2, 4. Candidates 1 and 3 fit existing Phase 4 items and add no dependency; 2 and 4 need decisions first.

Rejected: YARA in the binary, ML outlier scores, importing signature-base (product-named and scored; users can load a converted set with `--rules`).

## Caveats

- ntfs-forensic and IRFlow features are taken from their docs, not run.
- The DFRWS 2024 paper was read as an abstract only.
- No candidate's false-positive rate has been measured on real hosts yet.

## Sources

- ntfs-forensic: https://docs.rs/crate/ntfs-forensic/0.6.0/source/README.md
- IRFlow Timeline: https://r3nzsec.github.io/irflow-timeline/features/ntfs-analysis
- Chainsaw: https://www.helpnetsecurity.com/2025/01/13/chainsaw-open-source-tool-hunting-through-windows-forensic-artefacts
- signature-base: https://github.com/Neo23x0/signature-base/blob/master/iocs/filename-iocs.txt
- Velociraptor: https://docs.velociraptor.app/artifact_references/pages/windows.detection.yara.ntfs, https://docs.velociraptor.app/blog/2021/2021-02-13-digging-for-files-with-velociraptor-a1c0a21e242b/
- LOLRMM: https://github.com/magicsword-io/LOLRMM
- HijackLibs schema: https://github.com/wietze/HijackLibs/blob/main/docs/SCHEMA.md
- LOLBAS schema and API: https://github.com/LOLBAS-Project/LOLBAS/blob/master/YML-Schema.yml, https://lolbas-project.github.io/api/lolbas.json
- YARA external variables: https://docs.limacharlie.io/8-reference/yara-modules/; yara-x: https://docs.rs/yara-x
- Sigma 2.0 correlations: https://graylog.org/?p=32529, https://docs.sekoia.io/xdr/features/detect/sigma
- Oh et al. 2024: https://doaj.org/article/d947c8e3939540739ddeba26b1359767
- Palmbach, Breitinger: https://opus.bibliothek.uni-augsburg.de/opus4/frontdoor/index/index/docId/117569
- Bouma et al. 2023: https://cs.ou.nl/members/hugo/papers/ares23.pdf
- Iman et al. 2023: https://www.scitepress.org/Papers/2023/118051/118051.pdf
- Marková et al. 2024: https://dfrws.org/wp-content/uploads/2024/03/DFRWS_EU_2024_paper_5902.pdf
- Data stacking: https://vulners.com/fireeye/FIREEYE:1145757BEFBA97B5ECF2BB8580989592, https://trustedsignal.blogspot.com/2015/03/kansa-get-logparserstackps1.html
