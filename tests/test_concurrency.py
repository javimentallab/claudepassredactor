"""Several hooks at once, as happens with subagents or a tool finishing as a message is sent."""
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from tests import sandbox
from tests.sandbox import mr

WORKERS = 12


class TestConcurrency(unittest.TestCase):
    def test_no_fingerprint_is_lost(self):
        box = sandbox.Box()
        box.prompt("hello")
        with ThreadPoolExecutor(WORKERS) as pool:
            results = list(pool.map(lambda i: box.prompt(f"the password is Parallel-Value-{i:03d}"),
                                    range(WORKERS)))
        self.assertTrue(all(r.returncode == 0 and r.err == "" for r in results))
        self.assertEqual(len(box.fingerprints()), WORKERS)
        self.assertNotIn("ERROR", box.log())

    def test_first_run_creates_one_key_that_every_fingerprint_uses(self):
        box = sandbox.Box()
        with ThreadPoolExecutor(WORKERS) as pool:
            list(pool.map(lambda i: box.prompt(f"the password is FirstRun-Value-{i:03d}"), range(WORKERS)))
        key = box.key()
        expected = {mr.fingerprint(key, f"FirstRun-Value-{i:03d}") for i in range(WORKERS)}
        self.assertEqual({e["h"] for e in box.fingerprints()}, expected)
        leftovers = [n for n in os.listdir(box.data) if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_parallel_reviews_of_the_same_note(self):
        box = sandbox.Box()
        original = "password: Parallel-Value-999\n" + "A line that must survive.\n" * 200
        box.write("n.md", original)
        with ThreadPoolExecutor(WORKERS) as pool:
            results = list(pool.map(lambda _: box.tool({"file_path": box.note("n.md")}), range(WORKERS)))
        self.assertTrue(all(r.returncode == 0 for r in results))
        self.assertEqual(box.read("n.md"), original.replace("Parallel-Value-999", mr.TAG))
        self.assertEqual([n for n in os.listdir(box.memory) if n != "n.md"], [])

    def test_a_reader_never_sees_a_partial_note(self):
        """The hook masks a note again and again while another thread reads it throughout. The
        test itself replaces the note atomically, so any partial read is the hook's fault."""
        box = sandbox.Box()
        filler = "A line that must survive.\n" * 2000
        path = box.write("n.md", "password: Reader-Value-1\n" + filler)
        stop = threading.Event()
        problems = []

        def reader():
            while not stop.is_set():
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                except OSError:
                    continue          # Windows may refuse briefly during a replace
                if not data.endswith(filler.encode()):
                    problems.append(len(data))
                time.sleep(0.002)     # on Windows an open file cannot be replaced: leave gaps

        thread = threading.Thread(target=reader)
        thread.start()
        try:
            for i in range(8):
                mr.atomic_write(path, f"password: Reader-Value-{i}\n{filler}".encode())
                for _attempt in range(5):      # a replace that kept failing is retried by the next pass
                    box.tool({"file_path": path})
                    if mr.TAG in box.read("n.md"):
                        break
                self.assertIn(mr.TAG, box.read("n.md"))
        finally:
            stop.set()
            thread.join()
        self.assertEqual(problems, [], "sizes of the partial reads")
        self.assertTrue(box.read("n.md").endswith(filler))

    def test_lock_times_out_rather_than_blocking_the_session(self):
        box = sandbox.Box()
        paths = box.paths()
        box.write("n.md", "password: Locked-Value-2\n")
        code = (
            "import sys, time\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import claudepassredactor as mr\n"
            "with mr._Lock(mr.Paths()):\n"
            "    print('held', flush=True)\n"
            "    sys.stdin.read()\n"
        )
        holder = subprocess.Popen([sys.executable, "-c", code, sandbox.REPO], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, env=box.env())
        try:
            self.assertEqual(holder.stdout.readline().strip(), b"held")
            with self.subTest("the lock is really held"):
                lock = mr._Lock(paths, timeout=0.2)
                lock.__enter__()
                self.assertIsNone(lock.fd)
            with mock.patch.object(mr, "LOCK_TIMEOUT", 0.05), mock.patch.object(sys, "stdout", mock.Mock()):
                mr.hook_prompt(paths, {"prompt": "hello"})
            self.assertEqual(box.read("n.md"), f"password: {mr.TAG}\n", "the review still happens")
            self.assertIn("lock not acquired", box.log())
        finally:
            holder.communicate(b"", timeout=10)

    def test_lock_is_released_when_a_process_dies(self):
        box = sandbox.Box()
        code = (
            "import os, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import claudepassredactor as mr\n"
            "lock = mr._Lock(mr.Paths())\n"
            "lock.__enter__()\n"
            "os._exit(9)\n"
        )
        subprocess.run([sys.executable, "-c", code, sandbox.REPO], env=box.env(), check=False)
        lock = mr._Lock(box.paths(), timeout=2)
        lock.__enter__()
        self.assertIsNotNone(lock.fd)
        lock.__exit__(None, None, None)

    def test_state_stays_valid_json(self):
        box = sandbox.Box()
        box.write("n.md", "nothing\n")
        with ThreadPoolExecutor(WORKERS) as pool:
            list(pool.map(lambda i: box.prompt(f"message {i}"), range(WORKERS)))
        with open(os.path.join(box.data, "state.json"), encoding="utf-8") as f:
            self.assertIn("files", json.load(f))
