"""What a review may and may not do to files: encodings, atomic writes, links, boundaries."""
import errno
import os
import stat
import subprocess
import unittest
from unittest import mock

from tests import sandbox
from tests.sandbox import mr

KEY_TOKEN = "password: Note-Value-11"
MASKED = f"password: {mr.TAG}"


def review_all(box, **kw):
    paths, roots = box.paths(), box.roots()
    state = kw.pop("state", {"files": {}})
    return mr.review(paths, roots, None, {}, state, **kw), state


class TestEncodings(unittest.TestCase):
    def check(self, data, expected):
        box = sandbox.Box()
        box.write_bytes("n.md", data)
        report, _ = review_all(box)
        self.assertEqual(report.failed, [])
        self.assertEqual(box.read_bytes("n.md"), expected)

    def test_utf8_with_bom(self):
        self.check(b"\xef\xbb\xbf" + KEY_TOKEN.encode() + b"\n", b"\xef\xbb\xbf" + MASKED.encode() + b"\n")

    def test_secret_at_the_very_start_after_a_bom(self):
        box = sandbox.Box()
        box.write_bytes("n.md", b"\xef\xbb\xbfGiven-Value-12 and more\n")
        key = b"k" * mr.KEY_BYTES
        index = mr.build_index(mr._entries_for(key, "Given-Value-12", "strong"))
        mr.review(box.paths(), box.roots(), key, index, {"files": {}})
        self.assertEqual(box.read_bytes("n.md"), b"\xef\xbb\xbf" + mr.TAG.encode() + b" and more\n")

    def test_utf16_le_as_written_by_powershell_5(self):
        self.check("﻿password: Note-Value-11\r\n".encode("utf-16-le"),
                   f"﻿{MASKED}\r\n".encode("utf-16-le"))

    def test_utf16_be(self):
        self.check("﻿password: Note-Value-11\n".encode("utf-16-be"), f"﻿{MASKED}\n".encode("utf-16-be"))

    def test_utf32_le(self):
        self.check(b"\xff\xfe\x00\x00" + "password: Note-Value-11\n".encode("utf-32-le"),
                   b"\xff\xfe\x00\x00" + f"{MASKED}\n".encode("utf-32-le"))

    def test_crlf_is_preserved(self):
        self.check(f"a\r\n{KEY_TOKEN}\r\nb\r\n".encode(), f"a\r\n{MASKED}\r\nb\r\n".encode())

    def test_stray_invalid_bytes_are_preserved(self):
        clean = "contraseña: Note-Value-11\n".encode()
        self.check(b"caf\xe9 " + clean, b"caf\xe9 " + f"contraseña: {mr.TAG}\n".encode())

    def test_latin1_note_keeps_every_byte_and_finds_keywords(self):
        data = "Año: contraseña: Note-Value-11 ñandú\n".encode("latin-1")
        expected = f"Año: contraseña: {mr.TAG} ñandú\n".encode("latin-1")
        self.check(data, expected)

    def test_binary_file_is_reported_not_rewritten(self):
        box = sandbox.Box()
        data = b"\x00\x01password: Note-Value-11\x00\xff"
        path = box.write_bytes("b.md", data)
        report, _ = review_all(box)
        self.assertEqual(report.failed, [path])
        self.assertEqual(box.read_bytes("b.md"), data)

    def test_bad_utf16_is_reported_not_rewritten(self):
        box = sandbox.Box()
        data = b"\xff\xfe" + b"\x00\xd8" + b"a"     # truncated surrogate
        path = box.write_bytes("b.md", data)
        report, _ = review_all(box)
        self.assertEqual(report.failed, [path])
        self.assertEqual(box.read_bytes("b.md"), data)

    def test_too_large_is_reported_not_read(self):
        box = sandbox.Box()
        path = box.write("big.md", KEY_TOKEN)
        with mock.patch.object(mr, "MAX_NOTE_BYTES", 5):
            report, _ = review_all(box)
        self.assertEqual(report.failed, [path])
        self.assertEqual(box.read("big.md"), KEY_TOKEN)


class TestTimeBudget(unittest.TestCase):
    def test_notes_not_reached_stay_unmarked(self):
        box = sandbox.Box()
        box.write("n.md", f"{KEY_TOKEN}\n")
        state = {"files": {}}
        report, _ = review_all(box, state=state, deadline=0)
        self.assertEqual(report.failed, [])
        self.assertEqual(state["files"], {})
        self.assertEqual(box.read("n.md"), f"{KEY_TOKEN}\n")
        review_all(box, state=state)
        self.assertEqual(box.read("n.md"), f"{MASKED}\n")

    def test_a_note_that_runs_out_of_time_is_reported_and_left_until_it_changes(self):
        box = sandbox.Box()
        path = box.write("slow.md", "password " * 5000)
        state = {"files": {}}
        far = mr.time.monotonic() + 1000
        with mock.patch.object(mr, "_read_note", side_effect=mr.TooSlow()), mock.patch.object(mr, "HOOK_BUDGET", 0):
            report, _ = review_all(box, state=state, deadline=far)
        self.assertEqual(report.failed, [path])
        self.assertIn(os.path.normcase(path), state["files"], "must not delay every later message")
        report, _ = review_all(box, state=state, deadline=far)
        self.assertEqual(report.failed, [])
        self.assertEqual(report.changed, [])

    def test_prompt_detection_keeps_format_matches_when_out_of_time(self):
        token = "gh" + "p_" + "A1b2C3d4" * 5
        found = mr.prompt_candidates("password " * 5000 + token, deadline=0)
        self.assertEqual(found, [(token, "strong")])

    def test_review_by_hand_has_no_budget(self):
        box = sandbox.Box()
        path = box.write("n.md", f"{KEY_TOKEN}\n")
        self.assertEqual(box.run("redact").returncode, 0)
        self.assertEqual(open(path, encoding="utf-8").read(), f"{MASKED}\n")


class TestAtomicWrites(unittest.TestCase):
    def assert_untouched(self, box, report, path, original):
        self.assertEqual(report.failed, [path])
        self.assertEqual(report.changed, [])
        self.assertEqual(box.read("n.md"), original)
        self.assertEqual([n for n in os.listdir(box.memory) if n != "n.md"], [], "no temporary file left")

    def test_failed_replace_leaves_the_original_and_no_temporary_file(self):
        box = sandbox.Box()
        original = f"{KEY_TOKEN}\nmore text\n"
        path = box.write("n.md", original)
        with mock.patch.object(mr, "REPLACE_DELAYS", (0, 0)), \
                mock.patch("os.replace", side_effect=PermissionError(errno.EACCES, "locked")) as replace:
            report, _ = review_all(box)
        self.assertEqual(replace.call_count, 3, "retries before giving up")
        self.assert_untouched(box, report, path, original)

    def test_disk_full_leaves_the_original(self):
        box = sandbox.Box()
        original = f"{KEY_TOKEN}\n"
        path = box.write("n.md", original)
        with mock.patch("os.fsync", side_effect=OSError(errno.ENOSPC, "no space")):
            report, _ = review_all(box)
        self.assert_untouched(box, report, path, original)

    def test_failed_write_is_retried_on_the_next_pass(self):
        box = sandbox.Box()
        box.write("n.md", f"{KEY_TOKEN}\n")
        state = {"files": {}}
        with mock.patch.object(mr, "REPLACE_DELAYS", ()), \
                mock.patch("os.replace", side_effect=PermissionError(errno.EACCES, "locked")):
            review_all(box, state=state)
        self.assertEqual(state["files"], {}, "must not be marked as reviewed")
        report, _ = review_all(box, state=state)
        self.assertEqual(report.total, 1)
        self.assertEqual(box.read("n.md"), f"{MASKED}\n")

    def test_replace_retries_through_a_brief_lock(self):
        box = sandbox.Box()
        box.write("n.md", f"{KEY_TOKEN}\n")
        real_replace = os.replace
        calls = []

        def flaky(source, target):
            calls.append(target)
            if len(calls) < 3:
                raise PermissionError(errno.EACCES, "locked")
            return real_replace(source, target)

        with mock.patch.object(mr, "REPLACE_DELAYS", (0, 0, 0)), mock.patch("os.replace", flaky):
            report, _ = review_all(box)
        self.assertEqual(report.failed, [])
        self.assertEqual(box.read("n.md"), f"{MASKED}\n")

    def test_one_failure_does_not_stop_the_other_notes(self):
        box = sandbox.Box()
        box.write_bytes("a-binary.md", b"\x00\x00")
        box.write("b-good.md", f"{KEY_TOKEN}\n")
        report, _ = review_all(box)
        self.assertEqual(len(report.failed), 1)
        self.assertEqual(box.read("b-good.md"), f"{MASKED}\n")

    def test_note_changed_while_being_read_is_not_overwritten(self):
        box = sandbox.Box()
        path = box.write("n.md", f"{KEY_TOKEN}\n")
        real_read = mr._read_note
        newer = f"{KEY_TOKEN}\nThis line arrived while the review was running.\n"
        calls = []

        def read_then_change(p):
            result = real_read(p)
            if not calls:
                calls.append(p)
                box.write("n.md", newer)
                st = os.stat(p)
                os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1000))
            return result

        with mock.patch.object(mr, "_read_note", read_then_change):
            report, _ = review_all(box)
        self.assertEqual(report.failed, [])
        self.assertEqual(box.read("n.md"), newer.replace(KEY_TOKEN, MASKED))
        self.assertTrue(os.path.exists(path))

    def test_stored_json_is_replaced_whole(self):
        box = sandbox.Box()
        paths = box.paths()
        mr.save_fingerprints(paths, [])
        before = open(paths.fingerprints, "rb").read()
        with mock.patch("os.fsync", side_effect=OSError(errno.ENOSPC, "no space")), self.assertRaises(OSError):
            mr.save_fingerprints(paths, [{"h": "a" * 64, "l": 8, "f": "strong"}])
        self.assertEqual(open(paths.fingerprints, "rb").read(), before)
        self.assertEqual([n for n in os.listdir(paths.data) if n.endswith(".tmp")], [])


@unittest.skipIf(os.name == "nt", "POSIX permission bits")
class TestPosixModes(unittest.TestCase):
    def test_note_mode_is_preserved(self):
        for mode in (0o600, 0o640, 0o644):
            box = sandbox.Box()
            path = box.write("n.md", f"{KEY_TOKEN}\n")
            os.chmod(path, mode)
            review_all(box)
            self.assertEqual(box.read("n.md"), f"{MASKED}\n")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)

    def test_fifo_does_not_hang(self):
        box = sandbox.Box()
        os.mkfifo(box.note("pipe.md"))
        box.write("n.md", f"{KEY_TOKEN}\n")
        report, _ = review_all(box)
        self.assertEqual(box.read("n.md"), f"{MASKED}\n")
        self.assertEqual(report.failed, [])

    def test_reading_refuses_a_link_even_if_it_appeared_after_the_check(self):
        box = sandbox.Box()
        target = box.write("real.md", f"{KEY_TOKEN}\n")
        link = box.note("link.md")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            mr._read_note(link)

    def test_symlink_to_a_file_outside_is_not_followed(self):
        box = sandbox.Box()
        outside = box.write("victim.md", f"{KEY_TOKEN}\n", memory=box.root)
        link = box.note("link.md")
        os.symlink(outside, link)
        review_all(box)
        self.assertEqual(open(outside, encoding="utf-8").read(), f"{KEY_TOKEN}\n")
        self.assertTrue(os.path.islink(link))

    def test_symlinked_directory_is_not_followed(self):
        box = sandbox.Box()
        outside = os.path.join(box.root, "outside")
        victim = box.write("victim.md", f"{KEY_TOKEN}\n", memory=outside)
        os.symlink(outside, box.note("linkdir"))
        review_all(box)
        self.assertEqual(open(victim, encoding="utf-8").read(), f"{KEY_TOKEN}\n")

    def test_tool_path_through_a_symlink_out_of_memory_is_refused(self):
        box = sandbox.Box()
        outside = os.path.join(box.root, "outside")
        victim = box.write("victim.md", f"{KEY_TOKEN}\n", memory=outside)
        os.symlink(outside, box.note("linkdir"))
        box.tool({"file_path": os.path.join(box.memory, "linkdir", "victim.md")})
        self.assertEqual(open(victim, encoding="utf-8").read(), f"{KEY_TOKEN}\n")

    def test_memory_root_may_itself_be_a_symlink(self):
        box = sandbox.Box()
        real = os.path.join(box.root, "real-memory")
        os.makedirs(real)
        os.rmdir(box.memory)
        os.symlink(real, box.memory)
        note = box.write("n.md", f"{KEY_TOKEN}\n", memory=real)
        box.tool({"file_path": os.path.join(box.memory, "n.md")})
        self.assertEqual(open(note, encoding="utf-8").read(), f"{MASKED}\n")


@unittest.skipUnless(os.name == "nt", "Windows junctions")
class TestWindowsJunctions(unittest.TestCase):
    def setUp(self):
        self.box = sandbox.Box()
        self.outside = os.path.join(self.box.root, "outside")
        self.victim = self.box.write("victim.md", f"{KEY_TOKEN}\n", memory=self.outside)
        self.link = self.box.note("junction")
        subprocess.run(["cmd", "/c", "mklink", "/J", self.link, self.outside], capture_output=True, check=True)
        self.addCleanup(os.rmdir, self.link)

    def test_walk_does_not_enter_a_junction(self):
        review_all(self.box)
        self.assertEqual(open(self.victim, encoding="utf-8").read(), f"{KEY_TOKEN}\n")

    def test_tool_path_through_a_junction_is_refused(self):
        self.box.tool({"file_path": os.path.join(self.link, "victim.md")})
        self.assertEqual(open(self.victim, encoding="utf-8").read(), f"{KEY_TOKEN}\n")

    def test_short_and_long_paths_are_the_same_note(self):
        import ctypes
        note = self.box.write("n.md", f"{KEY_TOKEN}\n")
        buffer = ctypes.create_unicode_buffer(500)
        if not ctypes.windll.kernel32.GetShortPathNameW(note, buffer, 500):
            self.skipTest("no short names on this volume")
        self.box.tool({"file_path": buffer.value})
        self.assertEqual(self.box.read("n.md"), f"{MASKED}\n")


class TestBoundaries(unittest.TestCase):
    def outside(self, box, name="victim.md"):
        return box.write(name, f"{KEY_TOKEN}\n", memory=os.path.join(box.root, "elsewhere"))

    def assert_outside_untouched(self, path):
        self.assertEqual(open(path, encoding="utf-8").read(), f"{KEY_TOKEN}\n")

    def test_tool_write_outside_memory(self):
        box = sandbox.Box()
        victim = self.outside(box)
        box.tool({"file_path": victim})
        self.assert_outside_untouched(victim)

    def test_tool_write_outside_memory_does_not_review_memory_either(self):
        box = sandbox.Box()
        victim = self.outside(box)
        box.write("n.md", f"{KEY_TOKEN}\n")
        box.tool({"file_path": victim})
        self.assertEqual(box.read("n.md"), f"{KEY_TOKEN}\n", "only a note, or a shell command, triggers it")
        box.prompt("hello")
        self.assertEqual(box.read("n.md"), f"{MASKED}\n", "the next message picks it up")

    def test_path_traversal(self):
        box = sandbox.Box()
        victim = self.outside(box)
        rel = os.path.relpath(victim, box.memory)
        for raw in (os.path.join(box.memory, rel), rel):
            box.tool({"file_path": raw})
            self.assert_outside_untouched(victim)

    def test_sibling_folder_with_the_same_prefix(self):
        box = sandbox.Box()
        victim = box.write("victim.md", f"{KEY_TOKEN}\n", memory=box.memory + "-evil")
        box.tool({"file_path": victim})
        self.assert_outside_untouched(victim)

    def test_only_markdown_files(self):
        box = sandbox.Box()
        for name in ("token.txt", "data.json", "script.py", "n.md.bak"):
            box.write(name, f"{KEY_TOKEN}\n")
            box.tool({"file_path": box.note(name)})
            self.assertEqual(box.read(name), f"{KEY_TOKEN}\n")
        box.prompt("hello")
        for name in ("token.txt", "data.json", "script.py", "n.md.bak"):
            self.assertEqual(box.read(name), f"{KEY_TOKEN}\n")

    def test_uppercase_extension_counts(self):
        box = sandbox.Box()
        box.write("UPPER.MD", f"{KEY_TOKEN}\n")
        box.tool({"file_path": box.note("UPPER.MD")})
        self.assertEqual(box.read("UPPER.MD"), f"{MASKED}\n")

    def test_relative_path_uses_the_session_cwd(self):
        box = sandbox.Box()
        box.write("rel.md", f"{KEY_TOKEN}\n")
        box.tool({"file_path": "rel.md"})
        self.assertEqual(box.read("rel.md"), f"{MASKED}\n")

    def test_git_folder_is_never_entered(self):
        box = sandbox.Box()
        box.write(os.path.join(".git", "n.md"), f"{KEY_TOKEN}\n")
        box.run("redact", "--all")
        self.assertEqual(box.read(os.path.join(".git", "n.md")), f"{KEY_TOKEN}\n")

    def test_hidden_folders_only_by_hand(self):
        box = sandbox.Box()
        name = os.path.join(".versions", "old.md")
        box.write(name, f"{KEY_TOKEN}\n")
        box.prompt("hello")
        self.assertEqual(box.read(name), f"{KEY_TOKEN}\n")
        self.assertEqual(box.run("redact").returncode, 0)
        self.assertEqual(box.read(name), f"{KEY_TOKEN}\n")
        box.run("redact", "--all")
        self.assertEqual(box.read(name), f"{MASKED}\n")

    def test_unsafe_roots_are_refused(self):
        box = sandbox.Box()
        victim = box.write("victim.md", f"{KEY_TOKEN}\n", memory=box.home)
        for root in (box.home, os.path.dirname(box.home), box.config,
                     os.path.splitdrive(box.home)[0] + os.sep):
            result = box.run("redact", CLAUDEPASSREDACTOR_DIRS=root)
            self.assertEqual(result.returncode, 2, "a refused folder must not look like a clean run")
            self.assertIn("refused", result.out)
            self.assertEqual(open(victim, encoding="utf-8").read(), f"{KEY_TOKEN}\n", root)

    def test_explicit_root_replaces_the_default_ones(self):
        box = sandbox.Box()
        other = os.path.join(box.root, "other")
        note = box.write("n.md", f"{KEY_TOKEN}\n", memory=other)
        box.write("default.md", f"{KEY_TOKEN}\n")
        box.run("redact", CLAUDEPASSREDACTOR_DIRS=other)
        self.assertEqual(open(note, encoding="utf-8").read(), f"{MASKED}\n")
        self.assertEqual(box.read("default.md"), f"{KEY_TOKEN}\n")
