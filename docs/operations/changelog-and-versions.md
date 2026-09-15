---
title: Changelog and versions
layout: default
parent: Operations
---

# Changelog and Versions

The server ships its own changelog and exposes it over MCP, so a running session
can find out what changed without reconnecting.

---

## The problem this solves

An MCP client caches `tools/list` when it connects. The model then forms
assumptions about how tools behave from the responses it has actually seen —
field names, what truncation means, which argument forms are accepted.

Update the server underneath a live session and **neither is refreshed**. The
session keeps calling tools the old way and gets different answers, with nothing
announcing that the contract moved. A newly added tool is at least discoverable
on reconnect; a *changed contract* is not — it produces confidently wrong
answers instead of visible failures.

This is most likely to bite a long-lived Claude Desktop session, or a central
HTTP deployment upgraded while analysts are connected.

---

## How to check

**As a tool** — `get-server-changelog`:

| Argument | Meaning |
|---|---|
| `since` | Only releases newer than this version, e.g. `"0.2.0"` |
| `unlearn_only` | Only the behaviour changes; omit the feature lists |

Needs no PCE connection — a session needs this precisely when it cannot trust
its cached view of the server, and requiring a PCE would gate it behind
unrelated configuration.

**As a resource** — `illumio://changelog`, for clients that read resources
rather than call tools. Returns the raw Markdown.

---

## The `unlearn` field

Each release lists **Unlearn** entries: assumptions formed against an earlier
build that are now wrong. They are surfaced first and separately from the
feature list, because they are the ones that cause harm.

Examples of what belongs there:

- A response field that was renamed or split — `truncated` became
  `findings_truncated` and `flows_truncated`, which mean different things.
- A value a tool no longer returns — `classify_destination` no longer reports
  `openai` for Azure-hosted endpoints.
- A behaviour that changes how the model should *react* — a stalled write tool
  is an approval prompt, not a hung server, so retrying queues a second PCE
  write.

A new tool does not belong there. It is discoverable.

---

## Versions

`server_version` comes from the newest entry in the shipped `CHANGELOG.md`,
not from distribution metadata.

That is deliberate. In an editable install (`pip install -e .`), the metadata
records whatever was written at install time and goes stale as soon as the
source tree moves ahead — it would report `0.1.0` while running `0.3.0` code.
`CHANGELOG.md` ships with the code, so its newest entry describes what is
actually running.

When the two disagree, both are reported along with a `version_note` explaining
why, rather than silently preferring one.

---

## Adding an entry

`CHANGELOG.md` at the repository root is the single source — the server parses
it at runtime. Do not duplicate entries into Python; that creates a second place
to forget, which is how the advertised tool list once drifted from the registry.

```markdown
## [0.4.0] — YYYY-MM-DD

### Added
- New capability.

### Unlearn
- What a session that connected before this release now believes incorrectly.
```

Bump `version` in `pyproject.toml` to match the new heading.
