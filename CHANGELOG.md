# Changelog

## 1.0.1

- A new data folder is created with mode `0700` on every system, Windows included. Explicit rules for SYSTEM,
  Administrators and OWNER RIGHTS are still removed afterwards.
- The READMEs now say what a wrong hook path does, checked with Claude Code 2.1.316 on Windows: Claude Code blocks every
  message, so it cannot be used until `settings.json` is corrected. They also say how to recognize and fix it.
- `status` now says that backslashes in a hook command can break it, rather than that they do: Git Bash removes them
  outside quotes, and inside double quotes they worked when tested.
- Removed from a code comment and a test a cause that was never proven for the rules kept on Windows.

## 1.0.0

First public version.

- Hooks for `UserPromptSubmit` and `PostToolUse`, with optional `SessionStart`.
- Replaces secrets in Markdown files inside Claude Code memory folders with `[REDACTED]`:
  by fingerprint, by token format, by label and in URL passwords.
- Label detection, hook messages and command messages in 15 languages: en, es, pt, fr, de, it, nl, pl, ru, uk, zh-CN,
  ja, ko, th, hi. `--help` and `status` are in English.
- Commands: `scan`, `redact`, `status`, `add`, `forget`, `reset`. `status` warns about a registered hook that has
  backslashes or points to a missing file, and about a data folder that is not private.
- Optional `CLAUDEPASSREDACTOR_SHARED`: keeps fingerprints in step between computers through a file that a
  tool such as Syncthing synchronizes. `reset` leaves that file in place, because other computers use it.
- Standard library only. Test suite runs with one command in a temporary folder.
