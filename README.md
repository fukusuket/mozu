<p align="center"><img src="docs/images/mozu.png" alt="mozu" width="480"></p>

# Mozu

**Find what to look at on a Windows host, even after the event logs were wiped.**

Reads `$MFT` and the USN journal of one Windows host and writes one HTML report of the files to check first. Built for the first look after a ransomware or EDR alert, by responders who are not forensic specialists.

> Pre-alpha. Phases 1–3 of the [plan](docs/plan.md) are built; their gates are pending. Interfaces may change.

## Why Mozu

| | |
|---|---|
| **Logs wiped? Still works.** | `$MFT` and the USN journal survive log clearing, deleted and renamed files included |
| **Noise removed.** | Files a clean Windows also has are hidden; the rest stay visible |
| **No black box.** | Every finding is a readable Sigma rule. No scores |
| **Small and offline.** | One binary, one zip, one HTML file. No network, same output every run |

## How it works

```sh
mozu collect -o D:\PC-042.zip   # Windows host, as administrator
# unzip, then on any OS:
mozu analyze -i 'PC-042/$MFT' --usn 'PC-042/$J' --baseline win11.fst --rules testdata/rules -o PC-042.html
```

Open the HTML in a browser. Step by step: [quick start](docs/quickstart.md).

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
