"""Pins the whole test run to a throwaway folder. Imported before anything else in tests/.

HOME, USERPROFILE and CLAUDE_CONFIG_DIR are redirected before claudepassredactor is imported, so the
tool's default locations resolve inside the sandbox and a real memory folder cannot be reached by
default, however the tests are started. Every subprocess also gets a fresh environment built here.
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "claudepassredactor.py")

_REAL_HOME = os.path.realpath(os.path.expanduser("~"))
_REAL_CONFIG = os.path.realpath(os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(_REAL_HOME, ".claude"))

ROOT = os.path.realpath(tempfile.mkdtemp(prefix="claudepassredactor-tests-"))
atexit.register(shutil.rmtree, ROOT, True)


def is_inside(path, base):
    path = os.path.normcase(os.path.realpath(path))
    base = os.path.normcase(os.path.realpath(base))
    return path == base or path.startswith(base.rstrip("\\/") + os.sep)


if is_inside(ROOT, _REAL_CONFIG):
    raise SystemExit("Refusing to run: the temporary folder is inside the real Claude folder.")

_home = os.path.join(ROOT, "home")
os.makedirs(_home)
for _var in ("HOMEDRIVE", "HOMEPATH", "CLAUDEPASSREDACTOR_DIRS", "CLAUDEPASSREDACTOR_DATA",
             "CLAUDEPASSREDACTOR_SHARED", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
    os.environ.pop(_var, None)
os.environ.update(HOME=_home, USERPROFILE=_home, CLAUDE_CONFIG_DIR=os.path.join(_home, ".claude"),
                  CLAUDEPASSREDACTOR_LANG="en")

if REPO not in sys.path:
    sys.path.insert(0, REPO)

import claudepassredactor as mr  # noqa: E402


def assert_sandboxed(paths, roots=()):
    """Stops the run if any location the tool would use is outside the sandbox."""
    locations = [paths.data, paths.config, paths.key, paths.fingerprints, *roots]
    if paths.shared:
        locations.append(paths.shared)
    for location in locations:
        if not is_inside(location, ROOT) or is_inside(location, _REAL_CONFIG):
            raise SystemExit("Refusing to run: a test location escaped the sandbox.")


assert_sandboxed(mr.Paths())


class Box:
    """A fake home with one Claude memory folder, plus helpers to run the real hook against it."""

    def __init__(self):
        self.root = tempfile.mkdtemp(dir=ROOT)
        self.home = os.path.join(self.root, "home")
        self.config = os.path.join(self.home, ".claude")
        self.memory = os.path.join(self.config, "projects", "demo-project", "memory")
        self.data = os.path.join(self.config, "claudepassredactor")
        os.makedirs(self.memory)

    def env(self, **extra):
        env = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP")
               if name in os.environ}
        env.update(HOME=self.home, USERPROFILE=self.home, CLAUDE_CONFIG_DIR=self.config,
                   CLAUDEPASSREDACTOR_LANG="en", TEMP=self.root, TMP=self.root)
        env.update(extra)
        return env

    def paths(self, **extra):
        paths = mr.Paths(self.env(**extra))
        assert_sandboxed(paths)
        return paths

    def roots(self, **extra):
        paths = self.paths(**extra)
        roots = mr.memory_roots(paths)
        assert_sandboxed(paths, roots)
        return roots

    def run(self, *args, stdin=None, payload=None, **extra):
        assert_sandboxed(self.paths(**extra), self.roots(**extra))
        data = json.dumps(payload).encode() if payload is not None else (stdin or b"")
        result = subprocess.run([sys.executable, "-I", SCRIPT, *args], input=data, capture_output=True,
                                env=self.env(**extra), timeout=120)
        result.out = result.stdout.decode("utf-8", "replace")
        result.err = result.stderr.decode("utf-8", "replace")
        return result

    def prompt(self, text, **extra):
        return self.run("prompt", payload={"hook_event_name": "UserPromptSubmit", "prompt": text}, **extra)

    def tool(self, tool_input, **extra):
        return self.run("memory", payload={"hook_event_name": "PostToolUse", "tool_name": "Tool",
                                           "tool_input": tool_input, "cwd": self.memory}, **extra)

    def note(self, name):
        return os.path.join(self.memory, name)

    def write(self, name, text, encoding="utf-8", memory=None):
        path = os.path.join(memory or self.memory, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding=encoding, newline="") as f:
            f.write(text)
        return path

    def write_bytes(self, name, data):
        path = self.note(name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def read(self, name, encoding="utf-8"):
        with open(self.note(name), encoding=encoding, newline="") as f:
            return f.read()

    def read_bytes(self, name):
        with open(self.note(name), "rb") as f:
            return f.read()

    def fingerprints(self):
        try:
            with open(os.path.join(self.data, "fingerprints.json"), encoding="utf-8") as f:
                return json.load(f)["secrets"]
        except FileNotFoundError:
            return []

    def key(self):
        with open(os.path.join(self.data, "key.bin"), "rb") as f:
            return f.read()

    def log(self):
        try:
            with open(os.path.join(self.data, "redactor.log"), encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def everything_stored(self):
        """The bytes of every file the tool keeps outside the notes."""
        blob = b""
        for base, _dirs, names in os.walk(self.data):
            for name in names:
                with open(os.path.join(base, name), "rb") as f:
                    blob += f.read()
        return blob
