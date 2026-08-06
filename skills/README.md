# Skills

Agent skills that ship with `qw`, so a coding agent (Claude Code, etc.) can
drive the CLI effectively.

## `qw` — Quickwit log search

Teaches an agent the `qw` workflow: setting up a context and logging in,
discovering indexes/fields before querying, the search/count/histogram/tail
commands, Quickwit query syntax, output formats for piping, and the read-only
guardrails.

**Install** (Claude Code, per-user):

```sh
mkdir -p ~/.claude/skills
cp -r skills/qw ~/.claude/skills/qw
```

Or per-project, commit it under `.claude/skills/qw/` in the repo where you use
`qw`. The skill activates automatically when you ask to search or investigate
logs; you can also invoke it explicitly with `/qw-logs`.
