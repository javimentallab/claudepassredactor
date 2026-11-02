# Changelog

## 1.0.0

First public version.

- Hooks for `UserPromptSubmit` and `PostToolUse`, with optional `SessionStart`.
- Replaces secrets in Markdown files inside Claude Code memory folders with `[REDACTED]`:
  by fingerprint, by token format, by label and in URL passwords.
- Label detection, hook messages and command messages in 15 languages: en, es, pt, fr, de, it, nl, pl, ru, uk, zh-CN,
  ja, ko, th, hi. `--help` and `status` are in English.
- Commands: `scan`, `redact`, `status`, `add`, `forget`, `reset`. `status` warns about a registered hook that has
  backslashes or points to a missing file.
- Optional `CLAUDEPASSREDACTOR_SHARED`: keeps fingerprints in step between computers through a file that a
  tool such as Syncthing synchronizes. `reset` leaves that file in place, because other computers use it.
- Standard library only. Test suite runs with one command in a temporary folder.
