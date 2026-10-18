<p align="center"><img src="docs/images/mozu.png" alt="mozu" width="480"></p>

# Mozu

**Find what to look at on a Windows host, even after the event logs were wiped.**

Mozu is a triage tool for the first look after a ransomware or EDR alert, built for responders who are not forensic specialists. It reads the NTFS metadata of one Windows host (`$MFT` and the USN journal), hides files that a clean Windows install also has, matches Sigma rules and writes one HTML report that shows which files to check first.

> Pre-alpha. Phases 1–3 of the [plan](docs/plan.md) are built; their gates are pending. Interfaces may change.

## Why Mozu

1. **Survives log clearing.** Reads only `$MFT` and the USN journal; deleted and renamed files are rebuilt from the journal.
2. **Hides normal Windows files.** What a clean install also has is filtered out; everything else stays visible, rule match or not.
3. **Readable rules, no scores.** A finding is a Sigma rule match, ordered by level, then time.

Light to run: a zip of tens to hundreds of MB instead of a disk image, a single binary, one offline HTML report (plus CSV / JSONL), no network. Same input → byte-identical output.

## How it works

```sh
mozu collect -o D:\PC-042.zip            # on the Windows host, as administrator
# extract the zip, then on any OS:
mozu analyze -i 'PC-042/$MFT' --usn 'PC-042/$J' --baseline win11.fst --rules testdata/rules -o PC-042.html
```

Open `PC-042.html`: Summary → Findings → Outside-baseline. Full walk-through in the [quick start](docs/quickstart.md).

## What it cannot tell you

- Who or which process created a file, or whether it ran
- File content
- Activity older than the USN journal
- "Outside baseline" is a lead, not proof of compromise

## Not yet

Reading the zip or a collection directory directly (extract it first), ready-made baselines, correlation rules, Timeline and File detail screens, Japanese UI (Phase 4). USN V4 records are reported, not parsed.

## Docs

| | |
|---|---|
| [Quick start](docs/quickstart.md) | Build, collect, analyze, open the report |
| [Use cases](docs/usecases.md) | Step-by-step recipes |
| [Product](docs/product.md) | Problems, users, MVP |
| [Architecture](docs/architecture.md) | Pipeline, output columns, rule support |
| [Plan](docs/plan.md) | Current phase and next items |
| [AGENTS.md](AGENTS.md) | Development rules |

## License

- Code: [AGPL-3.0-only](LICENSE)
- Detection rules: [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
