#!/usr/bin/env python3
"""Runs the whole test suite with one command: python run_tests.py

Everything happens in a temporary folder that is deleted at the end, with invented secrets. The
tests package redirects HOME, USERPROFILE and CLAUDE_CONFIG_DIR before the tool is imported, so a
real Claude memory folder cannot be reached. Only the standard library is needed.
"""
import collections
import os
import sys
import time
import unittest

sys.dont_write_bytecode = True
REPO = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO)

import tests  # noqa: E402,F401  (this import is what activates the sandbox)


class CountingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.groups = collections.defaultdict(lambda: collections.Counter())

    @staticmethod
    def _group(test):
        name = type(test).__name__
        if name.startswith("TestLanguage_"):
            return name[len("TestLanguage_"):].replace("_", "-")
        return type(test).__module__.split(".")[-1].replace("test_", "") if hasattr(test, "id") else "other"

    def startTest(self, test):
        super().startTest(test)
        self.groups[self._group(test)]["run"] += 1

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.groups[self._group(test)]["failed"] += 1

    def addError(self, test, err):
        super().addError(test, err)
        self.groups[self._group(test)]["failed"] += 1

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.groups[self._group(test)]["failed"] += 1

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.groups[self._group(test)]["skipped"] += 1


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")   # failures quote any script
    suite = unittest.defaultTestLoader.discover(os.path.join(REPO, "tests"), top_level_dir=REPO)
    runner = unittest.TextTestRunner(resultclass=CountingResult, verbosity=1, stream=sys.stdout)
    started = time.time()
    result = runner.run(suite)
    print(f"\n{'group':<14}{'tests':>7}{'passed':>8}{'failed':>8}{'skipped':>9}")
    totals = collections.Counter()
    for group in sorted(result.groups):
        counts = result.groups[group]
        passed = counts["run"] - counts["failed"] - counts["skipped"]
        print(f"{group:<14}{counts['run']:>7}{passed:>8}{counts['failed']:>8}{counts['skipped']:>9}")
        totals.update(run=counts["run"], passed=passed, failed=counts["failed"], skipped=counts["skipped"])
    print(f"{'TOTAL':<14}{totals['run']:>7}{totals['passed']:>8}{totals['failed']:>8}{totals['skipped']:>9}")
    print(f"{time.time() - started:.1f} s")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
