# ADR 0023: Show the matched rule's YAML, not the `explain_rule` trace

Status: proposed (2026-10-17)  <!-- a human changes this to accepted (AGENTS.md H2) -->

## Context
ADR 0003 rule 4 made the `explain_rule` trace the report's evidence. A Simulated-Case-1 review found it hard to read for the intended user, who knows a suspicious file but not NTFS or the engine: one finding's trace is 60+ lines of nested JSON (conditions, matchers, `value_mismatch` items). Sigma users read rules as YAML (e.g. in Hayabusa), and the matched value, the path, is already shown above the trace.

## Decision
| | Before | After |
|---|---|---|
| `sigma::Finding` | `explain`: the trace as JSON | `source`: the text of the rule's file, as read |
| HTML data | `explain` on every finding | `rules`: each matched rule's YAML once, keyed by id (sorted) |
| Finding detail pane | the trace, indented | the rule's YAML as written |
| `explain_rule` | called per match | not called |

- A file with several rules shows the whole file.
- Rule text gets the same control-character escaping as other text, except line breaks and tabs.
- CSV/JSONL never carried the trace; they do not change.

Supersedes ADR 0003 rule 4 only; the rest of ADR 0003 stands.

## Consequences
- `sigma`: `Finding::explain` becomes `Finding::source`; `Rules` keeps each loaded rule's file text; the `explain` test is replaced.
- `report`: `FindingItem::explain` is removed, `Data` gains `rules`; `viewer.js` drops `pretty` and shows the YAML.
- ADR 0003's status notes that rule 4 is superseded.
