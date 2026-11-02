"""The key, the fingerprint store and the state file, including when they are damaged."""
import json
import os
import stat
import subprocess
import unittest
from unittest import mock

from tests import sandbox
from tests.sandbox import mr

TOKEN = "gh" + "p_" + "A1b2C3d4" * 5


def first_run(box):
    box.prompt("hello")
    return box.paths()


def write_raw(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class TestKey(unittest.TestCase):
    def test_created_outside_the_memory_with_the_right_size(self):
        box = sandbox.Box()
        paths = first_run(box)
        self.assertEqual(len(box.key()), mr.KEY_BYTES)
        self.assertFalse(sandbox.is_inside(paths.key, box.memory))
        self.assertEqual(os.listdir(box.memory), [])

    def test_stable_between_runs(self):
        box = sandbox.Box()
        first_run(box)
        key = box.key()
        box.prompt("again")
        self.assertEqual(box.key(), key)

    def test_different_on_every_install(self):
        a, b = sandbox.Box(), sandbox.Box()
        first_run(a), first_run(b)
        self.assertNotEqual(a.key(), b.key())

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_posix_permissions(self):
        box = sandbox.Box()
        paths = first_run(box)
        self.assertEqual(stat.S_IMODE(os.stat(paths.data).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(paths.key).st_mode), 0o600)
        box.prompt("the password is Stored-Value-1")
        for path in (paths.fingerprints, paths.state, paths.log, paths.lock):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, path)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_open_key_is_tightened(self):
        box = sandbox.Box()
        paths = first_run(box)
        os.chmod(paths.key, 0o644)
        box.prompt("again")
        self.assertEqual(stat.S_IMODE(os.stat(paths.key).st_mode), 0o600)

    @unittest.skipUnless(os.name == "nt", "Windows access rules")
    def test_windows_acl_has_only_the_current_user(self):
        box = sandbox.Box()
        paths = first_run(box)
        self.assertEqual(mr._windows_ace_count(paths.key), 1)
        out = subprocess.run(["icacls", paths.key], capture_output=True).stdout.decode("utf-8", "ignore")
        self.assertNotIn("Everyone", out)
        self.assertNotIn("Users:", out)
        self.assertNotIn("(I)", out, "nothing inherited")
        folder = subprocess.run(["icacls", paths.data], capture_output=True).stdout.decode("utf-8", "ignore")
        self.assertEqual(mr._windows_ace_count(paths.data), 1, f"{folder}\nlog: {box.log()}")

    @unittest.skipUnless(os.name == "nt", "Windows access rules")
    def test_status_warns_about_an_open_data_folder(self):
        box = sandbox.Box()
        paths = first_run(box)
        self.assertNotIn("data folder: warning", box.run("status").out)
        subprocess.run(["icacls", paths.data, "/grant", "*S-1-1-0:(OI)(CI)R"], capture_output=True, check=True)
        self.assertIn("data folder: warning", box.run("status").out)

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_status_warns_about_an_open_data_folder_on_posix(self):
        box = sandbox.Box()
        paths = first_run(box)
        self.assertNotIn("data folder: warning", box.run("status").out)
        os.chmod(paths.data, 0o755)
        self.assertIn("data folder: warning", box.run("status").out)

    def assert_key_kept_and_formats_work(self, box, paths, bad_key):
        write_raw(paths.key, bad_key)
        box.write("n.md", f"token {TOKEN}\n")
        result = box.prompt("the password is Not-Stored-22")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(box.read("n.md"), f"token {mr.TAG}\n", "format detection must keep working")
        self.assertEqual(box.key(), bad_key, "the key is never replaced silently")
        self.assertEqual(box.fingerprints(), [], "nothing hashed with a key that cannot be trusted")
        self.assertIn("status", json.loads(result.out)["systemMessage"])

    def test_empty_key(self):
        box = sandbox.Box()
        self.assert_key_kept_and_formats_work(box, box.paths(), b"")

    def test_short_key(self):
        box = sandbox.Box()
        self.assert_key_kept_and_formats_work(box, box.paths(), b"short")

    def test_long_key(self):
        box = sandbox.Box()
        self.assert_key_kept_and_formats_work(box, box.paths(), b"x" * (mr.KEY_BYTES + 1))

    def test_key_is_a_folder(self):
        box = sandbox.Box()
        paths = box.paths()
        os.makedirs(paths.key)
        box.write("n.md", f"token {TOKEN}\n")
        box.prompt("hello")
        self.assertEqual(box.read("n.md"), f"token {mr.TAG}\n")
        self.assertTrue(os.path.isdir(paths.key))

    def test_read_error_does_not_create_a_new_key(self):
        box = sandbox.Box()
        paths = first_run(box)
        key = box.key()
        real_open = open

        def refuse(path, *a, **k):
            if path == paths.key:
                raise PermissionError(13, "denied")
            return real_open(path, *a, **k)

        with mock.patch("builtins.open", refuse):
            self.assertEqual(mr.load_key(paths), (None, "key_unreadable"))
        self.assertEqual(box.key(), key)

    def test_missing_key_with_fingerprints_is_reported_not_replaced(self):
        box = sandbox.Box()
        box.prompt("the password is Stored-Value-2")
        os.unlink(os.path.join(box.data, "key.bin"))
        before = box.fingerprints()
        box.write("n.md", f"token {TOKEN}\n")
        result = box.prompt("hello")
        self.assertIn("status", json.loads(result.out)["systemMessage"])
        self.assertFalse(os.path.exists(os.path.join(box.data, "key.bin")))
        self.assertEqual(box.fingerprints(), before)
        self.assertEqual(box.read("n.md"), f"token {mr.TAG}\n")

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_key_that_is_a_symlink_is_refused(self):
        box = sandbox.Box()
        paths = box.paths()
        os.makedirs(paths.data)
        target = os.path.join(box.root, "elsewhere.bin")
        write_raw(target, b"x" * mr.KEY_BYTES)
        os.symlink(target, paths.key)
        self.assertEqual(mr.load_key(paths), (None, "key_invalid"))

    def test_warning_is_shown_once_per_problem(self):
        box = sandbox.Box()
        paths = box.paths()
        write_raw(paths.key, b"")
        self.assertIn("systemMessage", json.loads(box.prompt("hello").out))
        self.assertEqual(box.prompt("hello again").out, "")
        os.unlink(paths.key)
        self.assertEqual(box.prompt("key is back").out, "")
        write_raw(paths.key, b"")
        self.assertIn("systemMessage", json.loads(box.prompt("and bad again").out))


class TestFingerprintStore(unittest.TestCase):
    def setUp(self):
        self.box = sandbox.Box()
        self.box.prompt("the password is Stored-Value-3")
        self.paths = self.box.paths()

    def damage(self, data):
        write_raw(self.paths.fingerprints, data)

    def corrupt_copies(self):
        return [n for n in os.listdir(self.paths.data) if ".corrupt-" in n]

    def test_holds_no_plain_text(self):
        self.assertEqual(len(self.box.fingerprints()), 1)
        self.assertNotIn(b"Stored-Value-3", self.box.everything_stored())

    def test_fingerprint_needs_the_key(self):
        entry = self.box.fingerprints()[0]
        self.assertEqual(entry["h"], mr.fingerprint(self.box.key(), "Stored-Value-3"))
        self.assertEqual(entry["f"], "strong")

    def test_invalid_json_is_set_aside_and_not_overwritten(self):
        raw = open(self.paths.fingerprints, "rb").read()
        self.damage(raw[: len(raw) // 2])
        self.box.write("n.md", f"token {TOKEN}\n")
        result = self.box.prompt("the password is Stored-Value-4")
        self.assertEqual(self.box.read("n.md"), f"token {mr.TAG}\n")
        self.assertIn("systemMessage", json.loads(result.out))
        copies = self.corrupt_copies()
        self.assertEqual(len(copies), 1, "the damaged store is kept for recovery")
        with open(os.path.join(self.paths.data, copies[0]), "rb") as f:
            self.assertEqual(f.read(), raw[: len(raw) // 2])
        self.assertEqual(len(self.box.fingerprints()), 1)

    def test_wrong_shape_does_not_disable_redaction(self):
        for data in (b"[]", b"3", b'"text"', b"{}", b'{"secrets": 5}', b'{"secrets": {"a": 1}}', b"null"):
            self.damage(data)
            self.box.write("n.md", f"token {TOKEN}\n")
            result = self.box.prompt("hello")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(self.box.read("n.md"), f"token {mr.TAG}\n", data)

    def test_malformed_entries_are_ignored_and_good_ones_kept(self):
        good = {"h": mr.fingerprint(self.box.key(), "Stored-Value-5"), "l": 14, "f": "strong"}
        bad = [{"h": "abc"}, {"l": 1}, "text", 7, None, {"h": "z" * 64, "l": 8, "f": "strong"},
               {"h": "a" * 64, "l": 0, "f": "strong"}, {"h": "a" * 64, "l": -1, "f": "strong"},
               {"h": "a" * 64, "l": "8", "f": "strong"}, {"h": "a" * 64, "l": True, "f": "strong"},
               {"h": "a" * 64, "l": 10 ** 9, "f": "strong"}, {"h": "a" * 64, "l": 8, "f": "other"}]
        self.damage(json.dumps({"v": 1, "secrets": bad + [good]}).encode())
        self.box.write("n.md", f"Stored-Value-5 and {TOKEN}\n")
        result = self.box.prompt("hello")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.box.read("n.md"), f"{mr.TAG} and {mr.TAG}\n")

    def test_unreadable_store_is_not_overwritten(self):
        real_open = open
        paths = self.paths

        def refuse(path, *a, **k):
            if path == paths.fingerprints:
                raise PermissionError(13, "denied")
            return real_open(path, *a, **k)

        with mock.patch("builtins.open", refuse):
            self.assertEqual(mr.load_fingerprints(paths), (None, "store_unreadable"))

    def test_bad_utf8_in_the_store(self):
        self.damage(b"\xff\xfe\x00garbage")
        self.box.write("n.md", f"token {TOKEN}\n")
        self.assertEqual(self.box.prompt("hello").returncode, 0)
        self.assertEqual(self.box.read("n.md"), f"token {mr.TAG}\n")

    def test_new_fingerprints_review_all_notes(self):
        self.box.write("old.md", "ref Late-Value-6 here\n")
        self.box.prompt("hello")
        self.assertIn("Late-Value-6", self.box.read("old.md"))
        self.box.prompt("the password is Late-Value-6")
        self.assertEqual(self.box.read("old.md"), f"ref {mr.TAG} here\n")

    def test_fresh_fingerprints_also_reach_a_note_that_changed_meanwhile(self):
        self.box.write("a.md", "nothing\n")
        self.box.prompt("hello")
        self.box.write("a.md", f"ref Late-Value-7 and token {TOKEN} and Stored-Value-3\n")
        self.box.prompt("the password is Late-Value-7")
        self.assertEqual(self.box.read("a.md"), f"ref {mr.TAG} and token {mr.TAG} and {mr.TAG}\n",
                         "a changed note is looked at for everything")

    def test_a_store_changed_from_outside_means_a_full_review(self):
        self.box.write("a.md", "ref Copied-Value-8 here\n")
        self.box.prompt("hello")
        entries = self.box.fingerprints() + mr._entries_for(self.box.key(), "Copied-Value-8", "strong")
        mr.save_fingerprints(self.paths, entries)
        self.box.prompt("the password is Late-Value-9")
        self.assertEqual(self.box.read("a.md"), f"ref {mr.TAG} here\n")


class TestState(unittest.TestCase):
    def test_damaged_state_means_one_full_review(self):
        for data in (b"", b"[]", b"{", b'{"files": 3}', b"\xff\xff"):
            box = sandbox.Box()
            box.prompt("hello")
            write_raw(box.paths().state, data)
            box.write("n.md", f"token {TOKEN}\n")
            self.assertEqual(box.prompt("hello").returncode, 0)
            self.assertEqual(box.read("n.md"), f"token {mr.TAG}\n", data)

    def test_unchanged_notes_are_not_reread(self):
        box = sandbox.Box()
        box.write("n.md", "nothing here\n")
        box.prompt("hello")
        paths, roots = box.paths(), box.roots()
        state = mr.load_state(paths)
        with mock.patch.object(mr, "_read_note", side_effect=AssertionError("read")):
            mr.review(paths, roots, None, {}, state)

    def test_changed_note_is_reread(self):
        box = sandbox.Box()
        box.write("n.md", "nothing here\n")
        box.prompt("hello")
        box.write("n.md", f"now token {TOKEN}\n")
        box.prompt("hello")
        self.assertEqual(box.read("n.md"), f"now token {mr.TAG}\n")

    def test_read_error_is_not_marked_as_reviewed(self):
        box = sandbox.Box()
        path = box.write("n.md", f"token {TOKEN}\n")
        paths, roots = box.paths(), box.roots()
        state = {"files": {}}
        with mock.patch.object(mr, "_read_note", side_effect=PermissionError(13, "locked")):
            report = mr.review(paths, roots, None, {}, state)
        self.assertEqual(report.failed, [path])
        self.assertEqual(state["files"], {})
        report = mr.review(paths, roots, None, {}, state)
        self.assertEqual(report.total, 1)
        self.assertEqual(box.read("n.md"), f"token {mr.TAG}\n")

    @unittest.skipUnless(os.name == "nt", "Windows sharing modes")
    def test_really_locked_note_is_retried_after_the_lock_is_gone(self):
        import ctypes
        box = sandbox.Box()
        path = box.write("n.md", f"token {TOKEN}\n")
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateFileW.restype = ctypes.c_void_p
        handle = kernel32.CreateFileW(path, 0x80000000, 0, None, 3, 0, None)
        try:
            result = box.prompt("hello")
            self.assertIn("status", json.loads(result.out)["systemMessage"])
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
        self.assertIn(TOKEN, box.read("n.md"), "could not be touched while it was locked")
        box.prompt("hello again")
        self.assertEqual(box.read("n.md"), f"token {mr.TAG}\n")
