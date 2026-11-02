"""The hook as Claude Code runs it, as a subprocess, plus the command line and leak checks."""
import json
import os
import sys
import unittest
from unittest import mock

from tests import sandbox
from tests.sandbox import mr

TOKEN = "gh" + "p_" + "A1b2C3d4" * 5


def checked_json(result):
    return json.loads(result.out)


class TestHookProtocol(unittest.TestCase):
    def test_silent_when_there_is_nothing_to_say(self):
        box = sandbox.Box()
        result = box.prompt("just an ordinary message")
        self.assertEqual((result.returncode, result.out, result.err), (0, "", ""))

    def test_prompt_with_a_secret_warns_user_and_claude(self):
        box = sandbox.Box()
        out = checked_json(box.prompt("the password is Stored-Value-1"))
        self.assertIn(mr.TAG, out["systemMessage"])
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")
        self.assertIn("1 secret", out["hookSpecificOutput"]["additionalContext"])

    def test_write_tool_masks_and_tells_claude_to_reread(self):
        box = sandbox.Box()
        box.write("n.md", "password: Tool-Value-22\n")
        out = checked_json(box.tool({"file_path": box.note("n.md")}))
        self.assertEqual(box.read("n.md"), f"password: {mr.TAG}\n")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PostToolUse")
        self.assertIn("read it again", out["hookSpecificOutput"]["additionalContext"])
        self.assertIn("n.md", out["systemMessage"])

    def test_shell_command_reviews_changed_notes(self):
        box = sandbox.Box()
        box.write("n.md", "password: Shell-Value-33\n")
        box.tool({"command": "echo done"})
        self.assertEqual(box.read("n.md"), f"password: {mr.TAG}\n")

    def test_shell_command_with_no_changes_says_nothing(self):
        box = sandbox.Box()
        box.write("n.md", "nothing\n")
        self.assertEqual(box.tool({"command": "ls"}).out, "")
        self.assertEqual(box.tool({"command": "ls"}).out, "")

    def test_session_start_is_supported(self):
        box = sandbox.Box()
        box.write("n.md", "password: Start-Value-44\n")
        result = box.run("memory", payload={"hook_event_name": "SessionStart", "source": "startup"})
        self.assertEqual(checked_json(result)["hookSpecificOutput"]["hookEventName"], "SessionStart")
        self.assertEqual(box.read("n.md"), f"password: {mr.TAG}\n")

    def test_malformed_input_never_fails(self):
        box = sandbox.Box()
        for mode in ("prompt", "memory"):
            for data in (b"", b"not json", b"[]", b"3", b"null", b"\xff\xfe\xff", b'{"prompt": 5}',
                         b'{"tool_input": 5}', b'{"tool_input": {"file_path": 5}}',
                         b'{"tool_input": {"file_path": "a\\u0000b.md"}}', b'{"prompt": "\\ud83d"}'):
                result = box.run(mode, stdin=data)
                self.assertEqual((result.returncode, result.err), (0, ""), data)

    def test_lone_surrogate_in_a_prompt_with_a_secret(self):
        box = sandbox.Box()
        result = box.run("prompt", stdin=b'{"prompt": "\\ud83d the password is Stored-Value-55"}')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(box.fingerprints()), 1)

    def test_non_ascii_note_name_in_the_output(self):
        box = sandbox.Box()
        box.write("ñandú 日本語.md", "password: Name-Value-66\n")
        result = box.prompt("hello")
        self.assertEqual(result.returncode, 0)
        self.assertIn(mr.TAG, checked_json(result)["systemMessage"])

    def test_crash_is_silent_for_claude_and_logs_no_data(self):
        box = sandbox.Box()
        paths = box.paths()
        stdin = mock.Mock()
        stdin.buffer.read.return_value = b'{"prompt": "the password is Crash-Value-77"}'
        out = []
        boom = ValueError("the password is Crash-Value-77")
        with mock.patch.object(sys, "stdin", stdin), \
                mock.patch.object(sys, "stdout", mock.Mock(write=out.append)), \
                mock.patch.object(mr, "prompt_candidates", side_effect=boom):
            self.assertEqual(mr.run_hook("prompt", paths), 0)
        self.assertIn("status", "".join(out))
        log = box.log()
        self.assertIn("ERROR ValueError", log)
        self.assertNotIn("Crash-Value-77", log)
        self.assertNotIn("Crash-Value-77", "".join(out))


class TestNoLeaks(unittest.TestCase):
    """Whatever path is taken, a secret must not reach output, logs or stored files."""

    def assert_clean(self, box, secrets, results):
        stored = box.everything_stored()
        for secret in secrets:
            self.assertNotIn(secret.encode(), stored, secret)
            self.assertNotIn(secret, box.log(), secret)
            for result in results:
                self.assertNotIn(secret, result.out, secret)
                self.assertNotIn(secret, result.err, secret)

    def test_normal_flow(self):
        box = sandbox.Box()
        secrets = ["Leak-Value-1", "Leak-Value-2", TOKEN]
        box.write("n.md", "password: Leak-Value-1\n")
        results = [box.prompt("the password is Leak-Value-2 and the pin is 4471"),
                   box.prompt(f"token {TOKEN}"), box.tool({"command": "ls"}),
                   box.run("scan"), box.run("redact"), box.run("status")]
        self.assert_clean(box, secrets, results)

    def test_damaged_files_and_failures(self):
        box = sandbox.Box()
        paths = box.paths()
        box.prompt("hello")
        secrets = ["Leak-Value-3", "Leak-Value-4"]
        box.write("n.md", "password: Leak-Value-3\n")
        box.write_bytes("bad.md", b"\x00password: Leak-Value-3\x00")
        with open(paths.fingerprints, "wb") as f:
            f.write(b"[]")
        results = [box.prompt("the password is Leak-Value-4"), box.tool({"command": "ls"}), box.run("status")]
        with open(paths.key, "wb") as f:
            f.write(b"")
        results += [box.prompt("the password is Leak-Value-4"), box.run("scan"), box.run("status")]
        self.assert_clean(box, secrets, results)

    def test_scan_shows_no_value_even_with_two_on_one_line(self):
        box = sandbox.Box()
        line = "password: Line-Value-5 and password: Line-Value-6 and " + TOKEN
        box.write("n.md", line + "\n")
        for args in (("scan",), ("scan", "--context")):
            result = box.run(*args)
            self.assertEqual(result.returncode, 1)
            self.assertIn("n.md", result.out)
            for secret in ("Line-Value-5", "Line-Value-6", TOKEN):
                self.assertNotIn(secret, result.out, args)
            self.assertEqual(box.read("n.md"), line + "\n", "scan changes nothing")

    def test_scan_context_keeps_the_rest_of_the_line(self):
        box = sandbox.Box()
        box.write("n.md", "first password: Line-Value-7 last\n")
        self.assertIn("first password: <label> last", box.run("scan", "--context").out)

    def test_temporary_files_hold_no_secret(self):
        box = sandbox.Box()
        box.write("n.md", "password: Temp-Value-8\n")
        seen = []
        real_replace = os.replace

        def spy(source, target):
            if str(source).endswith(".tmp") and str(target).endswith(".md"):
                with open(source, "rb") as f:
                    seen.append(f.read())
            return real_replace(source, target)

        with mock.patch("os.replace", spy):
            mr.review(box.paths(), box.roots(), None, {}, {"files": {}})
        self.assertEqual(len(seen), 1)
        self.assertNotIn(b"Temp-Value-8", seen[0])

    def test_log_records_only_counts_names_and_kinds(self):
        box = sandbox.Box()
        box.write("n.md", "password: Log-Value-9\n")
        box.prompt("hello")
        self.assertIn("redacted 1 in n.md", box.log())
        self.assertNotIn("Log-Value-9", box.log())

    def test_log_is_rotated(self):
        box = sandbox.Box()
        paths = box.paths()
        with mock.patch.object(mr, "LOG_MAX_BYTES", 100):
            for i in range(10):
                mr.log_event(paths, "x" * 50)
        self.assertLess(os.path.getsize(paths.log), 200)
        self.assertTrue(os.path.exists(paths.log + ".1"))

    def test_log_keeps_one_line_per_event(self):
        box = sandbox.Box()
        paths = box.paths()
        mr.log_event(paths, "name\nwith\nbreaks\r\x1b[31m.md")
        self.assertEqual(len(box.log().splitlines()), 1)

    def test_exception_log_has_no_message(self):
        box = sandbox.Box()
        paths = box.paths()
        try:
            raise OSError(5, "Exposed-Value-10", "Exposed-Value-11.md")
        except OSError as exc:
            mr.log_exception(paths, exc)
        self.assertIn("ERROR OSError errno=5", box.log())
        self.assertNotIn("Exposed", box.log())


class TestRoots(unittest.TestCase):
    def test_default_covers_every_project_and_agent_memory(self):
        box = sandbox.Box()
        other = os.path.join(box.config, "projects", "other-project", "memory")
        agent = os.path.join(box.config, "agent-memory", "reviewer")
        a = box.write("a.md", "password: Root-Value-1\n", memory=other)
        b = box.write("b.md", "password: Root-Value-2\n", memory=agent)
        box.prompt("hello")
        for path in (a, b):
            self.assertIn(mr.TAG, open(path, encoding="utf-8").read(), path)

    def test_auto_memory_directory_from_user_settings(self):
        box = sandbox.Box()
        custom = os.path.join(box.root, "custom-memory")
        note = box.write("n.md", "password: Root-Value-3\n", memory=custom)
        with open(os.path.join(box.config, "settings.json"), "w", encoding="utf-8") as f:
            json.dump({"autoMemoryDirectory": custom}, f)
        box.prompt("hello")
        self.assertIn(mr.TAG, open(note, encoding="utf-8").read())

    def test_project_settings_cannot_redirect_the_tool(self):
        box = sandbox.Box()
        victim_dir = os.path.join(box.root, "important-docs")
        victim = box.write("n.md", "password: Root-Value-4\n", memory=victim_dir)
        repo = os.path.join(box.root, "cloned-repo")
        os.makedirs(os.path.join(repo, ".claude"))
        for name in ("settings.json", "settings.local.json"):
            with open(os.path.join(repo, ".claude", name), "w", encoding="utf-8") as f:
                json.dump({"autoMemoryDirectory": victim_dir}, f)
        box.run("prompt", payload={"prompt": "hello", "cwd": repo})
        self.assertNotIn(mr.TAG, open(victim, encoding="utf-8").read())

    def test_broken_settings_file_is_harmless(self):
        box = sandbox.Box()
        box.write("n.md", "password: Root-Value-5\n")
        for content in ("{", "[]", '{"autoMemoryDirectory": 5}', '{"autoMemoryDirectory": "relative/path"}'):
            with open(os.path.join(box.config, "settings.json"), "w", encoding="utf-8") as f:
                f.write(content)
            self.assertEqual(box.prompt("hello").returncode, 0, content)
        self.assertIn(mr.TAG, box.read("n.md"))

    def test_data_folder_can_be_moved(self):
        box = sandbox.Box()
        moved = os.path.join(box.root, "moved-data")
        box.prompt("the password is Root-Value-6", CLAUDEPASSREDACTOR_DATA=moved)
        self.assertTrue(os.path.exists(os.path.join(moved, "key.bin")))
        self.assertFalse(os.path.exists(box.data))

    def test_missing_memory_folder(self):
        box = sandbox.Box()
        os.rmdir(box.memory)
        self.assertEqual(box.prompt("the password is Root-Value-7").returncode, 0)


class TestSandboxGuard(unittest.TestCase):
    def test_defaults_stay_in_the_sandbox(self):
        paths = mr.Paths()
        self.assertTrue(sandbox.is_inside(paths.data, sandbox.ROOT))
        for root in mr.memory_roots(paths):
            self.assertTrue(sandbox.is_inside(root, sandbox.ROOT))

    def test_guard_stops_a_location_outside(self):
        paths = mr.Paths()
        paths.key = os.path.join(os.path.dirname(sandbox.ROOT), "elsewhere", "key.bin")
        with self.assertRaises(SystemExit):
            sandbox.assert_sandboxed(paths)

    def test_subprocess_environment_is_built_from_scratch(self):
        box = sandbox.Box()
        env = box.env()
        self.assertNotIn("CLAUDEPASSREDACTOR_DIRS", env)
        self.assertTrue(sandbox.is_inside(env["HOME"], sandbox.ROOT))
        self.assertTrue(sandbox.is_inside(env["USERPROFILE"], sandbox.ROOT))
        self.assertTrue(sandbox.is_inside(env["CLAUDE_CONFIG_DIR"], sandbox.ROOT))


class TestCommandLine(unittest.TestCase):
    def test_scan_clean(self):
        box = sandbox.Box()
        box.write("n.md", "nothing\n")
        result = box.run("scan")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Nothing to redact", result.out)

    def test_scan_creates_nothing(self):
        box = sandbox.Box()
        box.write("n.md", "password: Cli-Value-1\n")
        self.assertEqual(box.run("scan").returncode, 1)
        self.assertFalse(os.path.exists(box.data))

    def test_scan_reports_unreadable_notes(self):
        box = sandbox.Box()
        box.write_bytes("bad.md", b"\x00\x00")
        result = box.run("scan")
        self.assertEqual(result.returncode, 2)
        self.assertIn("bad.md", result.out)

    def test_redact_reports_a_total(self):
        box = sandbox.Box()
        box.write("n.md", "password: Cli-Value-2\n")
        result = box.run("redact")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Redacted: 1", result.out)

    def test_add_and_forget_work_from_a_pipe_without_echo(self):
        box = sandbox.Box()
        box.write("n.md", "it is horse battery staple here\n")
        result = box.run("add", stdin=b"horse battery staple\n")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("horse", result.out)
        self.assertEqual(box.read("n.md"), f"it is {mr.TAG} here\n")
        self.assertEqual(len(box.fingerprints()), 1)
        self.assertEqual(box.run("forget", stdin=b"horse battery staple\n").returncode, 0)
        self.assertEqual(box.fingerprints(), [])
        self.assertEqual(box.run("forget", stdin=b"horse battery staple\n").returncode, 1)

    def test_add_refuses_a_too_short_value(self):
        box = sandbox.Box()
        self.assertEqual(box.run("add", stdin=b"abc\n").returncode, 2)
        self.assertEqual(box.fingerprints(), [])

    def test_a_value_is_never_a_command_line_argument(self):
        box = sandbox.Box()
        result = box.run("add", "Argv-Value-3")
        self.assertEqual(result.returncode, 2)

    def test_reset_needs_confirmation(self):
        box = sandbox.Box()
        box.prompt("the password is Cli-Value-4")
        self.assertEqual(box.run("reset").returncode, 2)
        self.assertTrue(os.path.exists(os.path.join(box.data, "key.bin")))
        self.assertEqual(box.run("reset", "--yes").returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(box.data, "key.bin")))
        self.assertEqual(box.fingerprints(), [])

    def test_status(self):
        box = sandbox.Box()
        box.write("n.md", "nothing\n")
        box.prompt("the password is Cli-Value-5")
        result = box.run("status")
        self.assertEqual(result.returncode, 0)
        self.assertIn("key: ok", result.out)
        self.assertIn("fingerprints: 1", result.out)
        self.assertIn("notes: 1", result.out)
        self.assertIn("hooks registered in user settings: no", result.out)

    def test_status_notices_the_registered_hook(self):
        box = sandbox.Box()
        entry = [{"hooks": [{"type": "command", "command": "python3 -I claudepassredactor.py x"}]}]
        with open(os.path.join(box.config, "settings.json"), "w", encoding="utf-8") as f:
            json.dump({"hooks": {"UserPromptSubmit": entry, "PostToolUse": entry}}, f)
        self.assertIn("hooks registered in user settings: yes", box.run("status").out)

    def test_scan_and_redact_look_at_the_same_notes(self):
        box = sandbox.Box()
        name = os.path.join(".versions", "old.md")
        box.write(name, "password: Hidden-Value-1\n")
        for command in ("scan", "redact"):
            result = box.run(command)
            self.assertEqual(result.returncode, 0, command)
            self.assertIn("Nothing to redact", result.out, command)
        self.assertIn("Hidden-Value-1", box.read(name))

    def test_scan_all_finds_what_redact_all_masks(self):
        box = sandbox.Box()
        name = os.path.join(".versions", "old.md")
        box.write(name, "password: Hidden-Value-2\n")
        result = box.run("scan", "--all")
        self.assertEqual(result.returncode, 1)
        self.assertIn("old.md", result.out)
        self.assertIn("Hidden-Value-2", box.read(name), "scan changes nothing")
        self.assertEqual(box.run("redact", "--all").returncode, 0)
        self.assertEqual(box.read(name), f"password: {mr.TAG}\n")
        self.assertEqual(box.run("scan", "--all").returncode, 0)

    def test_scan_all_never_enters_git(self):
        box = sandbox.Box()
        box.write(os.path.join(".git", "n.md"), "password: Hidden-Value-3\n")
        self.assertEqual(box.run("scan", "--all").returncode, 0)

    def test_help_of_every_command(self):
        for command in ("prompt", "memory", "scan", "redact", "status", "add", "forget", "reset"):
            box = sandbox.Box()
            result = box.run(command, "--help")
            self.assertEqual(result.returncode, 0, command)
            self.assertIn(f"claudepassredactor.py {command}", result.out, command)
            self.assertFalse(os.path.exists(box.data), command)

    def test_a_hook_without_help_still_reads_its_input(self):
        box = sandbox.Box()
        box.prompt("the password is Help-Value-1")
        self.assertEqual(len(box.fingerprints()), 1)

    def test_a_value_next_to_help_is_not_stored(self):
        box = sandbox.Box()
        result = box.run("add", "Help-Value-2", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("Help-Value-2", result.out + result.err)
        self.assertEqual(box.fingerprints(), [])

    def test_reset_help_explains_yes(self):
        self.assertIn("go ahead", sandbox.Box().run("reset", "--help").out)

    def test_status_reports_a_bad_key(self):
        box = sandbox.Box()
        os.makedirs(box.data)
        with open(os.path.join(box.data, "key.bin"), "wb") as f:
            f.write(b"bad")
        result = box.run("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("key: key_invalid", result.out)

    def test_version(self):
        self.assertIn(mr.__version__, sandbox.Box().run("--version").out)

    def test_no_command_shows_usage(self):
        self.assertEqual(sandbox.Box().run().returncode, 2)


class TestHookPaths(unittest.TestCase):
    """status warns about a registered path that would stop the hook from running."""

    def settings(self, box, command, event="UserPromptSubmit", **extra):
        entry = [{"hooks": [dict({"type": "command", "command": command}, **extra)]}]
        with open(os.path.join(box.config, "settings.json"), "w", encoding="utf-8") as f:
            json.dump({"hooks": {event: entry}}, f)

    def script(self, box, folder="hooks"):
        path = os.path.join(box.config, folder, "claudepassredactor.py")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# stand-in\n")
        return path.replace("\\", "/")

    def test_an_existing_file_with_forward_slashes_is_fine(self):
        box = sandbox.Box()
        self.settings(box, f"python -I {self.script(box)} prompt")
        result = box.run("status")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("warning", result.out)

    def test_a_backslash_is_reported(self):
        box = sandbox.Box()
        self.settings(box, "python -I C:\\Users\\you\\.claude\\hooks\\claudepassredactor.py prompt")
        result = box.run("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("backslashes", result.out)

    def test_a_backslash_only_in_the_interpreter_is_reported(self):
        box = sandbox.Box()
        self.settings(box, f"C:\\Python\\python.exe -I {self.script(box)} prompt")
        self.assertIn("backslashes", box.run("status").out)

    def test_a_missing_file_is_reported(self):
        box = sandbox.Box()
        self.settings(box, f"python -I {box.config.replace(chr(92), '/')}/nowhere/claudepassredactor.py prompt")
        result = box.run("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not exist", result.out)

    def test_a_relative_path_is_reported(self):
        box = sandbox.Box()
        self.settings(box, "python -I claudepassredactor.py prompt")
        self.assertIn("does not exist", box.run("status").out)

    def test_every_event_is_looked_at(self):
        box = sandbox.Box()
        self.settings(box, "python -I /nowhere/claudepassredactor.py memory", event="SessionStart")
        self.assertIn("does not exist", box.run("status").out)

    def test_home_is_expanded(self):
        box = sandbox.Box()
        self.script(box)
        for start in ("~", "$HOME", "${HOME}"):
            self.settings(box, f"python -I {start}/.claude/hooks/claudepassredactor.py memory")
            self.assertEqual(box.run("status").returncode, 0, start)

    def test_a_quoted_path_with_spaces(self):
        box = sandbox.Box()
        self.settings(box, f'python -I "{self.script(box, "my hooks")}" prompt')
        self.assertEqual(box.run("status").returncode, 0)
        self.settings(box, f'python -I "{box.config.replace(chr(92), "/")}/no such/claudepassredactor.py" prompt')
        self.assertIn("does not exist", box.run("status").out)

    def test_powershell_may_use_backslashes(self):
        box = sandbox.Box()
        script = self.script(box).replace("/", "\\")
        self.settings(box, f"python -I {script} prompt", shell="powershell")
        if os.name == "nt":
            self.assertNotIn("backslashes", box.run("status").out)
            self.assertEqual(box.run("status").returncode, 0)
        else:                            # a backslash is not a separator here: the file is not found
            self.assertIn("does not exist", box.run("status").out)

    @unittest.skipUnless(os.name == "nt", "Git Bash paths exist only on Windows")
    def test_a_git_bash_path_on_windows(self):
        box = sandbox.Box()
        drive, rest = os.path.splitdrive(self.script(box))
        self.settings(box, f"python -I /{drive[0].lower()}{rest} prompt")
        self.assertEqual(box.run("status").returncode, 0)

    def test_other_hooks_are_ignored(self):
        box = sandbox.Box()
        self.settings(box, "C:\\tools\\other.exe --flag")
        result = box.run("status")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("warning", result.out)

    def test_malformed_hooks_are_harmless(self):
        box = sandbox.Box()
        for hooks in (5, [], {"PostToolUse": 5}, {"PostToolUse": [5]}, {"PostToolUse": [{"hooks": 5}]},
                      {"PostToolUse": [{"hooks": [5, {"command": 5}]}]}):
            with open(os.path.join(box.config, "settings.json"), "w", encoding="utf-8") as f:
                json.dump({"hooks": hooks}, f)
            self.assertEqual(box.run("status").returncode, 0, hooks)


class TestInstallDocs(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(sandbox.REPO, name), encoding="utf-8") as f:
            return f.read()

    def test_the_two_readmes_have_the_same_shape(self):
        english, spanish = self.read("README.md").splitlines(), self.read("README.es.md").splitlines()
        self.assertEqual(len(english), len(spanish))
        for a, b in zip(english, spanish):
            for mark in ("#", "|", "- ", "```", "python", "> "):
                self.assertEqual(a.startswith(mark), b.startswith(mark), (a, b))

    def test_the_readmes_say_where_to_get_it_and_how_to_write_a_windows_path(self):
        for name in ("README.md", "README.es.md"):
            text = self.read(name)
            self.assertIn("https://github.com/javimentallab/claudepassredactor", text, name)
            self.assertIn("python -I C:/Users/<", text, name)
            self.assertIn('"env"', text, name)
            self.assertIn("scan --all", text, name)
            self.assertIn("(NOTICE)", text, name)

    def test_notice_names_the_only_third_party_module(self):
        self.assertIn("Pillow", self.read("NOTICE"))

    def test_changelog_matches_the_version(self):
        with open(os.path.join(sandbox.REPO, "CHANGELOG.md"), encoding="utf-8") as f:
            self.assertIn(f"## {mr.__version__}", f.read())

    def test_readme_hook_block_is_valid_and_points_at_the_modes(self):
        for name in ("README.md", "README.es.md"):
            with open(os.path.join(sandbox.REPO, name), encoding="utf-8") as f:
                text = f.read()
            start = text.index("```json") + len("```json")
            block = json.loads(text[start:text.index("```", start)])
            commands = json.dumps(block)
            self.assertIn("UserPromptSubmit", block["hooks"])
            self.assertIn("PostToolUse", block["hooks"])
            self.assertIn("claudepassredactor.py", commands)
            self.assertIn(" prompt", commands)
            self.assertIn(" memory", commands)
