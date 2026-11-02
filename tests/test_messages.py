"""The message catalogue: complete in every language, same placeholders, sensible language choice."""
import json
import string
import unittest

from tests import sandbox
from tests.language_cases import CASES
from tests.sandbox import mr


COMMAND_KEYS = ("prompt_value", "stdin_value", "no_arguments", "reset_confirm", "reset_done", "reset_shared",
                "no_store", "no_read", "warn_earlier", "warn_damaged", "warn_folder", "warn_shared",
                "warn_shared_forget", "cannot_read", "cannot_review", "lines")


def placeholders(text):
    return {field for _, field, _, _ in string.Formatter().parse(text) if field}


class TestCatalogue(unittest.TestCase):
    def test_covers_the_same_languages_as_detection(self):
        self.assertEqual(set(mr.MESSAGES), set(CASES))

    def test_no_key_is_missing(self):
        keys = set(mr.MESSAGES["en"])
        for code, catalogue in mr.MESSAGES.items():
            self.assertEqual(set(catalogue), keys, code)

    def test_placeholders_do_not_change(self):
        for key, reference in mr.MESSAGES["en"].items():
            for code, catalogue in mr.MESSAGES.items():
                self.assertEqual(placeholders(catalogue[key]), placeholders(reference), (code, key))

    def test_every_message_formats(self):
        for code, catalogue in mr.MESSAGES.items():
            for key, text in catalogue.items():
                result = text.format(tag=mr.TAG, n=3, files="a.md", path="p", problem="x", lines="[1]", detail="d")
                self.assertTrue(result.strip(), (code, key))

    def test_warnings_name_the_command_to_run(self):
        for code, catalogue in mr.MESSAGES.items():
            for key in ("attention", "key_problem"):
                self.assertIn("claudepassredactor.py status", catalogue[key], (code, key))

    def test_translations_are_not_just_english(self):
        english = mr.MESSAGES["en"]
        for code, catalogue in mr.MESSAGES.items():
            if code != "en":
                self.assertNotEqual(catalogue["detected"], english["detected"], code)
                self.assertNotEqual(catalogue["nothing"], english["nothing"], code)

    def test_every_message_of_the_commands_is_translated(self):
        english = mr.MESSAGES["en"]
        for code, catalogue in mr.MESSAGES.items():
            for key in COMMAND_KEYS:
                if code != "en":
                    self.assertNotEqual(catalogue[key], english[key], (code, key))


class TestCommandsSpeakTheLanguage(unittest.TestCase):
    def test_reset_in_every_language(self):
        for code, catalogue in mr.MESSAGES.items():
            box = sandbox.Box()
            result = box.run("reset", CLAUDEPASSREDACTOR_LANG=code)
            self.assertEqual(result.returncode, 2, code)
            self.assertIn(catalogue["reset_confirm"], result.out, code)
            done = box.run("reset", "--yes", CLAUDEPASSREDACTOR_LANG=code)
            self.assertIn(catalogue["reset_done"], done.out, code)

    def test_add_and_forget_warnings_in_every_language(self):
        for code, catalogue in mr.MESSAGES.items():
            box = sandbox.Box()
            result = box.run("add", stdin=b"Lang-Value-22\n", CLAUDEPASSREDACTOR_LANG=code)
            self.assertIn(catalogue["stdin_value"], result.err, code)
            result = box.run("forget", stdin=b"Lang-Value-22\n", CLAUDEPASSREDACTOR_LANG=code)
            self.assertIn(catalogue["stdin_value"], result.err, code)
            for command in ("add", "forget"):
                result = box.run(command, "extra", CLAUDEPASSREDACTOR_LANG=code)
                self.assertIn(catalogue["no_arguments"], result.err, (code, command))

    def test_scan_and_redact_warnings_are_translated(self):
        box = sandbox.Box()
        box.write("n.md", "password: Lang-Value-33\n")
        scan = box.run("scan", CLAUDEPASSREDACTOR_LANG="de")
        self.assertIn("Zeilen [1]", scan.out)
        for command in ("scan", "redact"):
            result = box.run(command, CLAUDEPASSREDACTOR_LANG="de", CLAUDEPASSREDACTOR_DIRS=box.home)
            self.assertIn(mr.MESSAGES["de"]["warn_folder"], result.out, command)
            self.assertNotIn("warning:", result.out, command)

    def test_status_and_help_stay_in_english(self):
        box = sandbox.Box()
        status = box.run("status", CLAUDEPASSREDACTOR_LANG="de", CLAUDEPASSREDACTOR_DIRS=box.home)
        self.assertIn("warning: a folder", status.out)
        self.assertNotIn("Warnung", status.out)
        self.assertIn("review every note now", box.run("--help", CLAUDEPASSREDACTOR_LANG="de").out)


class TestLanguageChoice(unittest.TestCase):
    def test_from_the_environment(self):
        for env, expected in (({"CLAUDEPASSREDACTOR_LANG": "de"}, "de"),
                              ({"CLAUDEPASSREDACTOR_LANG": "pt_BR.UTF-8"}, "pt"),
                              ({"LANG": "fr_FR.UTF-8"}, "fr"),
                              ({"LC_ALL": "zh_CN.UTF-8", "LANG": "en_US"}, "zh-CN"),
                              ({"LC_ALL": "C", "LANG": "ja_JP.UTF-8"}, "ja"),
                              ({"LANG": "zh_TW"}, "zh-CN"),
                              ({"LANGUAGE": "ko:en"}, "ko"),
                              ({"CLAUDEPASSREDACTOR_LANG": "tlh", "LANG": "it_IT"}, "it"),
                              ({"LANG": "es-ES"}, "es")):
            self.assertEqual(mr.ui_language(env), expected, env)

    def test_unknown_falls_back_to_english_on_posix(self):
        if mr.os.name != "nt":
            self.assertEqual(mr.ui_language({"LANG": "C"}), "en")
            self.assertEqual(mr.ui_language({}), "en")

    def test_result_is_always_a_known_language(self):
        self.assertIn(mr.ui_language({}), mr.MESSAGES)

    def test_the_hook_speaks_the_language(self):
        box = sandbox.Box()
        result = box.prompt("the password is Lang-Value-1", CLAUDEPASSREDACTOR_LANG="ru")
        self.assertIn("секреты", json.loads(result.out)["systemMessage"])
