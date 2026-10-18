# ADR 0025: Release workflow

Status: proposed (2026-10-18)  <!-- a human changes this to accepted (AGENTS.md H2) -->

## Context
There is no release build: users build from source (quickstart.md), against product.md P3 "single binary, no install". ADR 0007 P9 requires releases behind a human-approved environment with provenance attestations; ADR 0024 leaves Phase 3 builds unsigned and makes signing a human step from v0.4. Agents never publish (AGENTS.md).

## Decision
| Topic | Decision |
|---|---|
| Trigger | Push of a `v*` tag, or `workflow_dispatch` with a required `tag` input (an existing tag). Both run the same jobs; not approving the release environment is the dry run. |
| Version check | The tag matches `^v[0-9]+\.[0-9]+\.[0-9]+$` and equals `v` + the workspace version, else the run fails. The tag is passed through `env:`, never inlined. |
| Targets | `x86_64-pc-windows-msvc` (collect, analyze), `aarch64-apple-darwin`, `x86_64-unknown-linux-musl` (analyze; static, no glibc version; the only C build dependency, `cc` for `iana-time-zone-haiku`, is not built for it). Each on its native runner. |
| Build | `cargo build --release --locked -p cli --target <t>` from the tag, no cache. `RUSTFLAGS` remaps the workspace to `mozu` and `$CARGO_HOME` to `cargo` (`--remap-path-prefix`); a step fails if the binary still contains `/home/runner`, `/Users/runner`, `D:\a\`, `C:\Users\runneradmin` or `.cargo/registry`. The Windows build links the CRT statically (`-C target-feature=+crt-static`), so `mozu.exe` runs on a host without the VC++ redistributable; a step fails if it still names `vcruntime140.dll`. |
| Archive | `mozu-<version>-<target>.zip` (Windows) or `.tar.gz`: the binary, `rules/` (`testdata/rules/*.yml`, DRL 1.1, no third-party rule data per ADR 0019), `LICENSE`, `NOTICE`, `README.md`. No baseline (P4-6). |
| Smoke test | Per target, the extracted binary prints the tag's version and analyzes a synthetic `$MFT` (`xtask synth-mft`) with the bundled `rules/`. |
| Provenance | `SHA256SUMS` over all archives; `actions/attest-build-provenance` (SHA-pinned; a new action) attests each archive. |
| Release | A job in the `release` environment (required reviewer: the maintainer) runs `gh release create <tag> --draft --verify-tag` with the archives and `SHA256SUMS`. A human reviews and publishes the draft. |
| Permissions | `permissions: {}` at the top; `contents: read` for builds; `id-token: write` and `attestations: write` for attest only; `contents: write` for the draft job only. `persist-credentials: false`; zizmor passes. |
| Signing | None in v0.3 (ADR 0024). Archives pass between jobs as workflow artifacts, so the v0.4 signing step fits between build and draft. |

## Consequences
- `.github/workflows/release.yml`: new.
- GitHub: a `release` environment with the maintainer as required reviewer (human).
- `docs/plan.md`: P3-R.
- `docs/quickstart.md`: download and checksum verification once the first release is published (follow-up, not in P3-R).
- musl's default allocator may slow `analyze` on large `$MFT`s; changing it would be a dependency (H2), proposed separately if measured.
