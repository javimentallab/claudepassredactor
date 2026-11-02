"""Two computers, each a sandbox of its own, keeping fingerprints in step through a shared file."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import sandbox
from tests.sandbox import mr

SECRET = "the password is Shared-Value-77"
VALUE = "Shared-Value-77"


class Computers:
    def __init__(self, same_key=True):
        self.folder = tempfile.mkdtemp(dir=sandbox.ROOT)
        self.shared = os.path.join(self.folder, ".fingerprints.json")
        self.a, self.b = sandbox.Box(), sandbox.Box()
        self.a.prompt("hello", **self.extra())       # creates the key and the shared file
        if same_key:
            os.makedirs(self.b.data, exist_ok=True)
            shutil.copyfile(os.path.join(self.a.data, "key.bin"), os.path.join(self.b.data, "key.bin"))
        self.b_first_prompt = self.b.prompt("hello", **self.extra())

    def extra(self):
        return {"CLAUDEPASSREDACTOR_SHARED": self.shared}

    def read_shared(self):
        with open(self.shared, encoding="utf-8") as f:
            return json.load(f)

    def conflict(self, entries, forgotten=()):
        """What Syncthing leaves when the file changed on two computers at once."""
        path = os.path.join(self.folder, ".fingerprints.sync-conflict-20260101-120000-ABCDEFG.json")
        data = dict(self.read_shared(), secrets=entries, forgotten=list(forgotten))
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path


class TestShared(unittest.TestCase):
    def test_off_unless_asked_for(self):
        box = sandbox.Box()
        box.prompt(SECRET)
        self.assertEqual(os.listdir(box.memory), [])
        self.assertEqual(len(box.fingerprints()), 1)

    def test_a_secret_given_on_one_computer_is_masked_on_the_other(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        c.b.write("n.md", f"a value with no label {VALUE} here\n")
        c.b.prompt("hello", **c.extra())
        self.assertEqual(c.b.read("n.md"), f"a value with no label {mr.TAG} here\n")
        self.assertEqual(c.b.fingerprints(), c.a.fingerprints())

    def test_a_note_that_had_not_changed_is_reviewed_again_when_a_fingerprint_arrives(self):
        c = Computers()
        c.b.write("n.md", f"a value with no label {VALUE} here\n")
        c.b.prompt("hello", **c.extra())
        self.assertIn(VALUE, c.b.read("n.md"))
        c.a.prompt(SECRET, **c.extra())
        c.b.prompt("hello", **c.extra())
        self.assertNotIn(VALUE, c.b.read("n.md"))

    def test_the_memory_hook_also_takes_fingerprints_in(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        c.b.tool({"command": "ls"}, **c.extra())
        self.assertEqual(c.b.fingerprints(), c.a.fingerprints())

    def test_the_shared_file_holds_no_text_and_no_key(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        with open(c.shared, "rb") as f:
            raw = f.read()
        self.assertNotIn(VALUE.encode(), raw)
        self.assertNotIn(c.a.key().hex().encode(), raw)
        self.assertEqual(c.read_shared()["key_check"], mr._key_check(c.a.key()))
        self.assertNotIn(mr._key_check(c.a.key()), c.a.key().hex())

    def test_nothing_is_written_when_nothing_changed(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        before = os.stat(c.shared).st_mtime_ns
        c.a.prompt("hello", **c.extra())
        c.b.prompt("hello", **c.extra())     # b takes it in, and has nothing new to add
        c.b.prompt("hello", **c.extra())
        self.assertEqual(os.stat(c.shared).st_mtime_ns, before)

    def test_conflict_copies_are_merged_and_removed(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        entries = mr._entries_for(c.a.key(), "Conflict-Value-88", "strong")
        path = c.conflict(entries)
        c.b.write("n.md", "a value with no label Conflict-Value-88 here\n")
        c.b.prompt("hello", **c.extra())
        self.assertFalse(os.path.exists(path))
        self.assertNotIn("Conflict-Value-88", c.b.read("n.md"))
        self.assertEqual(len(c.read_shared()["secrets"]), 2)

    def test_a_damaged_conflict_copy_is_left_in_place(self):
        c = Computers()
        path = c.conflict([])
        with open(path, "w", encoding="utf-8") as f:
            f.write("{not json")
        c.b.prompt(SECRET, **c.extra())
        self.assertTrue(os.path.exists(path))
        self.assertEqual(len(c.read_shared()["secrets"]), 1)

    def test_a_damaged_shared_file_is_not_replaced_and_is_reported(self):
        c = Computers()
        with open(c.shared, "w", encoding="utf-8") as f:
            f.write("{not json")
        result = c.a.prompt(SECRET, **c.extra())
        with open(c.shared, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{not json")
        self.assertEqual(len(c.a.fingerprints()), 1)      # it still works locally
        self.assertIn("status", result.out)
        self.assertIn("could not be read", c.a.run("status", **c.extra()).out)

    def test_another_key_is_not_merged_or_replaced_and_is_reported(self):
        c = Computers(same_key=False)
        before = c.read_shared()
        c.a.prompt(SECRET, **c.extra())
        after = c.read_shared()
        c.b.write("n.md", f"a value with no label {VALUE} here\n")
        c.b.prompt("hello", **c.extra())
        self.assertEqual(c.read_shared(), after)
        self.assertEqual(before["key_check"], after["key_check"])
        self.assertEqual(c.b.fingerprints(), [])
        self.assertIn(VALUE, c.b.read("n.md"))
        self.assertIn("status", c.b_first_prompt.out)     # the warning appears once
        self.assertIn("another key", c.b.run("status", **c.extra()).out)

    def test_a_forgotten_value_does_not_come_back_from_the_other_computer(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        c.b.prompt("hello", **c.extra())
        self.assertEqual(len(c.b.fingerprints()), 1)
        self.assertEqual(c.a.run("forget", stdin=f"{VALUE}\n".encode(), **c.extra()).returncode, 0)
        c.b.prompt("hello", **c.extra())
        self.assertEqual(c.b.fingerprints(), [])
        c.a.prompt("hello", **c.extra())
        self.assertEqual(c.a.fingerprints(), [])
        self.assertEqual(c.read_shared()["secrets"], [])

    def test_a_forgotten_value_given_again_is_remembered_everywhere(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        c.a.run("forget", stdin=f"{VALUE}\n".encode(), **c.extra())
        c.b.prompt(SECRET, **c.extra())
        c.a.prompt("hello", **c.extra())
        self.assertEqual(len(c.a.fingerprints()), 1)
        self.assertNotIn(mr.fingerprint(c.a.key(), VALUE), c.read_shared()["forgotten"])

    def test_a_value_added_by_hand_reaches_the_shared_file(self):
        c = Computers()
        c.a.run("add", stdin=b"Typed-Value-99\n", **c.extra())
        self.assertEqual(len(c.read_shared()["secrets"]), 1)

    def test_reset_keeps_the_shared_file_and_says_so(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        before = c.read_shared()
        for args, code in ((("reset",), 2), (("reset", "--yes"), 0)):
            result = c.a.run(*args, **c.extra())
            self.assertEqual(result.returncode, code, args)
            self.assertIn(mr.MESSAGES["en"]["reset_shared"].format(path=mr.Paths(c.a.env(**c.extra())).shared), result.out)
        self.assertEqual(c.read_shared(), before)
        self.assertEqual(c.a.fingerprints(), [])
        self.assertFalse(os.path.exists(os.path.join(c.a.data, "key.bin")))

    def test_the_other_computer_keeps_working_after_a_reset(self):
        c = Computers()
        c.a.prompt(SECRET, **c.extra())
        c.a.run("reset", "--yes", **c.extra())
        c.b.write("n.md", f"a value with no label {VALUE} here\n")
        c.b.prompt("hello", **c.extra())
        self.assertEqual(c.b.read("n.md"), f"a value with no label {mr.TAG} here\n")

    def test_reset_says_nothing_of_a_shared_file_that_is_not_there(self):
        box = sandbox.Box()
        missing = os.path.join(box.root, "missing.json")
        result = box.run("reset", "--yes", CLAUDEPASSREDACTOR_SHARED=missing)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("shared file", result.out)

    def test_the_suite_starts_with_the_variable_set(self):
        box = sandbox.Box()
        env = box.env(CLAUDEPASSREDACTOR_SHARED=os.path.abspath(os.path.join(os.sep, "outside", "fingerprints.json")),
                      PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-c", "import tests"], cwd=sandbox.REPO, env=env,
                                capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_relative_path_is_refused_and_reported(self):
        box = sandbox.Box()
        box.prompt(SECRET, CLAUDEPASSREDACTOR_SHARED="relative.json")
        self.assertFalse(os.path.exists("relative.json"))
        self.assertIn("absolute path", box.run("status", CLAUDEPASSREDACTOR_SHARED="relative.json").out)

    def test_a_malformed_entry_in_the_shared_file_is_ignored(self):
        c = Computers()
        data = dict(c.read_shared(), secrets=[{"h": "x"}, 7], forgotten=["x", 7])
        with open(c.shared, "w", encoding="utf-8") as f:
            json.dump(data, f)
        c.a.prompt(SECRET, **c.extra())
        self.assertEqual(len(c.a.fingerprints()), 1)
        self.assertEqual(c.read_shared()["forgotten"], [])


if __name__ == "__main__":
    unittest.main()
