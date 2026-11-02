"""One test per sentence and language, generated from language_cases.py."""
import re
import unittest

from tests import sandbox
from tests.language_cases import CASES
from tests.sandbox import mr


def candidates(text):
    return {value for value, _strength in mr.prompt_candidates(mr.nfc(text))}


def redact(text):
    return mr.apply_spans(text, mr.find_spans(text))


def _slug(text):
    return re.sub(r"\W+", "_", text.encode("ascii", "ignore").decode())[:30].strip("_")


def _add_cases(cls, code, case):
    def add(name, function):
        setattr(cls, f"test_{name}", function)

    for i, (text, value) in enumerate(case["secrets"]):
        def secret(self, text=text, value=value):
            self.assertEqual(candidates(text), {value}, text)
        add(f"secret_{i:02d}_{_slug(value)}", secret)

    for i, text in enumerate(case["not_secrets"]):
        def not_secret(self, text=text):
            self.assertEqual(candidates(text), set(), text)
        add(f"not_secret_{i:02d}_{_slug(text)}", not_secret)

    for i, (text, value) in enumerate(case["notes"]):
        def note(self, text=text, value=value):
            self.assertEqual(redact(text), text.replace(value, mr.TAG))
        add(f"note_{i:02d}_{_slug(value)}", note)

    def intact(self, text=case["intact"]):
        self.assertEqual(redact(text), text)
    add("intact_prose", intact)

    def end_to_end(self):
        """The real hook: a secret from a message is removed from a note that mentions it with
        no label at all, and the surrounding text survives."""
        box = sandbox.Box()
        text, value = next(c for c in case["secrets"] if len(c[1]) >= 8 and "-" in c[1])
        note = f"Reference: {value} ...\n{case['intact']}"
        box.write("note.md", note)
        result = box.prompt(text)
        self.assertEqual(box.read("note.md"), note.replace(value, mr.TAG))
        self.assertNotIn(value, result.out)
        self.assertNotIn(value.encode(), box.everything_stored())
    add("end_to_end", end_to_end)

    def weak_pin(self):
        """A PIN goes only where a keyword sits next to it; the same digits elsewhere stay."""
        box = sandbox.Box()
        message, near_keyword, elsewhere = case["weak"]
        box.write("near.md", near_keyword)
        box.write("elsewhere.md", elsewhere)
        box.prompt(message)
        self.assertEqual(box.read("near.md"), near_keyword.replace("8123", mr.TAG), "next to a keyword")
        self.assertEqual(box.read("elsewhere.md"), elsewhere, "the digits mean something else")
    add("weak_pin_only_next_to_keyword", weak_pin)


for _code, _case in CASES.items():
    _name = "TestLanguage_" + _code.replace("-", "_")
    _cls = type(_name, (unittest.TestCase,), {"__doc__": f"Language: {_code}"})
    _add_cases(_cls, _code, _case)
    globals()[_name] = _cls
del _cls                                 # or unittest would load the last class twice


class TestLanguageCoverage(unittest.TestCase):
    def test_all_15_languages_have_cases(self):
        self.assertEqual(set(CASES), {"en", "es", "pt", "fr", "de", "it", "nl", "pl", "ru", "uk",
                                      "zh-CN", "ja", "ko", "th", "hi"})
        self.assertEqual(set(CASES), set(mr.LANGUAGES))

    def test_every_language_has_a_minimum_of_cases(self):
        for code, case in CASES.items():
            self.assertGreaterEqual(len(case["secrets"]), 6, code)
            self.assertGreaterEqual(len(case["not_secrets"]), 6, code)
            self.assertGreaterEqual(len(case["notes"]), 2, code)
