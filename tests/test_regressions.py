"""Cases found by an independent review of the code, kept so that they stay fixed."""
import json
import os
import sys
import unittest
from unittest import mock

from tests import sandbox
from tests.sandbox import mr

FILL = "A1b2C3d4"
KEY_LINE = "MIIE" + FILL * 7 + "abcd"
PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
TOKEN = "gh" + "p_" + FILL * 5


def redact(text):
    return mr.apply_spans(text, mr.find_spans(text))


def candidates(text):
    return {value for value, _ in mr.prompt_candidates(text)}


class TestPrivateKeysKeepProse(unittest.TestCase):
    def test_lines_with_colons_after_a_cut_off_key(self):
        prose = "Nota: la clave vieja\nRuta: /home/ana\nImportante: rotarla\nPendiente\n\n## Siguiente\n"
        self.assertEqual(redact(f"{PEM_BEGIN}\n{KEY_LINE}\n\n{prose}"), f"{mr.TAG}\n\n{prose}")

    def test_prose_on_the_line_right_after_a_cut_off_key(self):
        self.assertEqual(redact(f"{PEM_BEGIN}\n{KEY_LINE}\nThe rest stays.\n"), f"{mr.TAG}\nThe rest stays.\n")

    def test_markers_mentioned_with_prose_between_them(self):
        text = f"A key starts with {PEM_BEGIN}\nand then:\n\n## Section\nmore text\n\nand ends with {PEM_END}\n"
        self.assertEqual(redact(text), text)

    def test_example_without_key_material(self):
        text = f"{PEM_BEGIN}\n...\n{PEM_END}\n"
        self.assertEqual(redact(text), text)

    def test_json_with_literal_line_breaks(self):
        text = '{"private_key": "' + PEM_BEGIN + "\\n" + KEY_LINE + "\\n" + KEY_LINE + "\\n" + PEM_END + '\\n"}\n'
        self.assertEqual(redact(text), '{"private_key": "' + mr.TAG + '\\n"}\n')

    def test_json_with_literal_line_breaks_and_no_end(self):
        text = '{"private_key": "' + PEM_BEGIN + "\\n" + KEY_LINE + "\\n" + KEY_LINE + '"}\n'
        self.assertNotIn("MIIE", redact(text))

    def test_quoted_in_markdown(self):
        text = f"> {PEM_BEGIN}\n> {KEY_LINE}\n> {PEM_END}\n"
        self.assertEqual(redact(text), f"> {mr.TAG}\n")

    def test_quoted_in_markdown_and_cut_off(self):
        self.assertNotIn("MIIE", redact(f"> {PEM_BEGIN}\n> {KEY_LINE}\n> {KEY_LINE}\n\nProse.\n"))

    def test_all_on_one_line(self):
        self.assertEqual(redact(f"x {PEM_BEGIN} {KEY_LINE} {PEM_END} y\n"), f"x {mr.TAG} y\n")

    def test_short_last_line(self):
        self.assertEqual(redact(f"{PEM_BEGIN}\n{KEY_LINE}\nabc\n{PEM_END}\n"), f"{mr.TAG}\n")

    def test_encrypted_key_with_headers(self):
        text = f"{PEM_BEGIN}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,AB12\n\n{KEY_LINE}\n{PEM_END}\n"
        self.assertEqual(redact(text), f"{mr.TAG}\n")

    def test_header_words_are_not_taken_after_the_body(self):
        text = f"{PEM_BEGIN}\n{KEY_LINE}\nComment: this line is mine\n"
        self.assertEqual(redact(text), f"{mr.TAG}\nComment: this line is mine\n")


class TestNextValueOnTheLine(unittest.TestCase):
    def test_repeated_passes_stop_at_the_password(self):
        once = redact("password: Abc-12345, host: srv-2024, user: admin-01\n")
        self.assertEqual(once, f"password: {mr.TAG}, host: srv-2024, user: admin-01\n")
        self.assertEqual(redact(redact(once)), once)

    def test_a_rejected_value_ends_the_search(self):
        for text in ("password: none, host: srv-2024\n", "| password | hidden | srv-2024 |\n",
                     "password: none host: srv-2024\n",
                     "| password | | srv-2024 |\n", "password is none, host: srv-2024\n",
                     f"password is {mr.TAG} host: srv-2024\n", f"password: {mr.TAG} | srv-2024\n"):
            self.assertEqual(redact(text), text, text)
            self.assertEqual(candidates(text), set(), text)

    def test_json_with_a_null_password(self):
        text = '{"password":null,"host":"srv-2024","user":"admin-01"}\n'
        self.assertEqual(redact(text), text)

    def test_a_word_link_can_still_be_followed_by_the_real_one(self):
        self.assertEqual(candidates("the password is: Real-Value-12"), {"Real-Value-12"})
        self.assertEqual(candidates("पासवर्ड यह है: Real-Value-13"), {"Real-Value-13"})


class TestNoFalseFingerprints(unittest.TestCase):
    def test_messages_that_do_not_give_a_secret(self):
        for text in ('<input type="password" name="username">',
                     "What's the password to db-server-01?",
                     "the password in prod-2024 is wrong",
                     "Send the token to prod-server-1",
                     "a senha para db-server-01",
                     "пароль на db-server-01",
                     "das Passwort zu db-server-01",
                     "le mot de passe à db-server-01"):
            self.assertEqual(candidates(text), set(), text)

    def test_notes_with_code_and_schemas(self):
        for text in ("password = user.password\n", "'password' => $request->password\n",
                     "| password | VARCHAR(255) |\n", "the bearer authentication/authorization flow\n",
                     'password = settings.password\n'):
            self.assertEqual(redact(text), text, text)


class TestNaturalPhrasesAreFound(unittest.TestCase):
    pass


FOUND = {
    "reset_to": ("I reset the password to Winter-2024x\n", "Winter-2024x"),
    "after_a_change": ("Tras el cambio de contraseña: Nueva-Clave-2024\n", "Nueva-Clave-2024"),
    "followed_by_a_colon": ("La contraseña es Hunter-2024x: no la compartas\n", "Hunter-2024x"),
    "no_link": ("wifi password Hunter-2024x\n", "Hunter-2024x"),
    "no_link_in_japanese": ("Wi-FiのパスワードHunter-2024x\n", "Hunter-2024x"),
    "env_short": ("DB_PASS=Abc-12345x\n", "Abc-12345x"),
    "short_word": ("pass: Abc-12345x\n", "Abc-12345x"),
    "env_suffix": ("PASSWORD_DB=Abc-12345x\n", "Abc-12345x"),
    "starts_like_a_placeholder": ("password: Changeme123!\n", "Changeme123!"),
    "api_token": ("API_TOKEN=Abc-12345x\n", "Abc-12345x"),
    "api_key_digits": ("API_KEY=918273645012\n", "918273645012"),
    "api_key_no_digit": ("API_KEY=abc-def_ghi.jkl\n", "abc-def_ghi.jkl"),
    "url_user_with_at": ("postgresql://admin@myserver:Sup3r-Secret-99@host/db\n", "Sup3r-Secret-99"),
    "url_slash": ("postgres://bob:Pa/ss-Url-62@db/x\n", "Pa/ss-Url-62"),
    "url_two_words": ("https://bob:correct-horse@host/\n", "correct-horse"),
    "ampersand_with_a_weak_head": ("password: aB3&k=Qw7zZ9pL\n", "aB3&k=Qw7zZ9pL"),
    "escaped_quote": ('password: "Xy7Zk9Lm\\"2Pq55"\n', 'Xy7Zk9Lm\\"2Pq55'),
    "not_a_closing_tag": ("password: Ab1cd2ef</x9zQ77\n", "Ab1cd2ef</x9zQ77"),
    "invisible_inside": ("password: Hunter99\u200b2024abc\n", "Hunter99\u200b2024abc"),
    "invisible_after": ("password: Hunter-2024x\u200b\n", "Hunter-2024x"),
    "parenthesis_inside": ("(password: Pa(ss)w0rd-99)\n", "Pa(ss)w0rd-99"),
}


def _make_found(text, value):
    def test(self):
        self.assertEqual(redact(text), text.replace(value, mr.TAG))
    return test


for _name, (_text, _value) in FOUND.items():
    setattr(TestNaturalPhrasesAreFound, f"test_{_name}", _make_found(_text, _value))


class TestFingerprintDetails(unittest.TestCase):
    def test_keyword_far_back_in_the_sentence(self):
        key = b"k" * mr.KEY_BYTES
        index = mr.build_index(mr._entries_for(key, "8123", "weak"))
        text = "The alarm pin, which the installer configured last year for the whole building, is 8123.\n"
        self.assertEqual(mr.apply_spans(text, mr.find_spans(text, key, index)), text.replace("8123", mr.TAG))


class TestWhatTheToolAdmits(unittest.TestCase):
    def test_a_bad_key_never_promises_masking(self):
        box = sandbox.Box()
        os.makedirs(box.data)
        with open(os.path.join(box.data, "key.bin"), "wb") as f:
            f.write(b"bad")
        for _ in range(2):
            message = json.loads(box.prompt("the password is Promise-Value-1").out)["systemMessage"]
            self.assertIn("status", message)
            self.assertNotIn(mr.TAG, message)

    def test_scan_and_redact_report_a_bad_key(self):
        box = sandbox.Box()
        os.makedirs(box.data)
        with open(os.path.join(box.data, "key.bin"), "wb") as f:
            f.write(b"bad")
        box.write("n.md", "nothing\n")
        for command in ("scan", "redact"):
            result = box.run(command)
            self.assertEqual(result.returncode, 2, command)
            self.assertIn("key_invalid", result.out, command)

    def test_status_reports_a_store_that_was_set_aside(self):
        box = sandbox.Box()
        box.prompt("the password is Stored-Value-2")
        with open(os.path.join(box.data, "fingerprints.json"), "wb") as f:
            f.write(b"[broken")
        box.prompt("hello")
        result = box.run("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("damaged fingerprint store", result.out)
        self.assertIn("errors in the log: 1", result.out)

    def test_status_counts_a_note_that_ran_out_of_time(self):
        box = sandbox.Box()
        mr.log_event(box.paths(), "ran out of time reviewing slow.md; run: redact")
        self.assertIn("errors in the log: 1", box.run("status").out)


class TestRoots(unittest.TestCase):
    def test_relative_folders_are_refused_and_reported(self):
        box = sandbox.Box()
        repo = os.path.join(box.root, "some-repo")
        victim = box.write("api.md", "password: Relative-Value-3\n", memory=os.path.join(repo, "docs"))
        env = box.env(CLAUDEPASSREDACTOR_DIRS="docs")
        result = mr_run(["prompt"], env, repo, b'{"prompt": "hello"}')
        self.assertEqual(open(victim, encoding="utf-8").read(), "password: Relative-Value-3\n")
        self.assertIn("status", json.loads(result.stdout)["systemMessage"])
        self.assertEqual(mr_run(["status"], env, repo).returncode, 2)

    def test_folder_that_does_not_exist_is_reported(self):
        box = sandbox.Box()
        missing = os.path.join(box.root, "typo")
        self.assertIn("refused or does not exist", box.run("status", CLAUDEPASSREDACTOR_DIRS=missing).out)
        self.assertEqual(box.run("scan", CLAUDEPASSREDACTOR_DIRS=missing).returncode, 2)

    def test_empty_list_is_reported(self):
        box = sandbox.Box()
        self.assertEqual(box.run("status", CLAUDEPASSREDACTOR_DIRS="").returncode, 2)

    def test_relative_data_folder_is_ignored(self):
        box = sandbox.Box()
        repo = os.path.join(box.root, "some-repo")
        os.makedirs(repo)
        mr_run(["prompt"], box.env(CLAUDEPASSREDACTOR_DATA="mr-data"), repo, b'{"prompt": "hello"}')
        self.assertEqual(os.listdir(repo), [])
        self.assertTrue(os.path.exists(os.path.join(box.data, "key.bin")))

    def test_settings_with_a_bom(self):
        box = sandbox.Box()
        custom = os.path.join(box.root, "custom-memory")
        note = box.write("n.md", "password: Bom-Value-4\n", memory=custom)
        with open(os.path.join(box.config, "settings.json"), "wb") as f:
            f.write(b"\xef\xbb\xbf" + json.dumps({"autoMemoryDirectory": custom}).encode())
        box.prompt("hello")
        self.assertIn(mr.TAG, open(note, encoding="utf-8").read())

    def test_settings_with_a_home_relative_path(self):
        box = sandbox.Box()
        note = box.write("n.md", "password: Home-Value-5\n", memory=os.path.join(box.home, "custom-memory"))
        with open(os.path.join(box.config, "settings.json"), "w", encoding="utf-8") as f:
            json.dump({"autoMemoryDirectory": "~/custom-memory"}, f)
        box.prompt("hello")
        self.assertIn(mr.TAG, open(note, encoding="utf-8").read())

    def test_a_tool_cannot_reach_a_note_inside_git(self):
        box = sandbox.Box()
        name = os.path.join(".git", "n.md")
        box.write(name, "password: Git-Value-6\n")
        box.tool({"file_path": box.note(name)})
        self.assertEqual(box.read(name), "password: Git-Value-6\n")


def mr_run(args, env, cwd, stdin=b""):
    """The tool with a chosen working folder, which Box.run does not need elsewhere."""
    import subprocess
    return subprocess.run([sys.executable, "-I", sandbox.SCRIPT, *args], input=stdin, capture_output=True,
                          env=env, cwd=cwd, timeout=60)


class TestTime(unittest.TestCase):
    def test_a_note_cut_short_by_others_gets_its_turn_next_pass(self):
        box = sandbox.Box()
        box.write("n.md", "password: Turn-Value-7\n")
        state = {"files": {}}
        with mock.patch.object(mr, "_read_note", side_effect=mr.TooSlow()):
            report = mr.review(box.paths(), box.roots(), None, {}, state, deadline=mr.time.monotonic() + 100)
        self.assertEqual(report.failed, [])
        self.assertEqual(state["files"], {}, "it did not use the time up itself")
        mr.review(box.paths(), box.roots(), None, {}, state)
        self.assertEqual(box.read("n.md"), f"password: {mr.TAG}\n")


class TestPendingFingerprints(unittest.TestCase):
    def test_fingerprints_survive_when_the_lock_cannot_be_taken(self):
        box = sandbox.Box()
        box.prompt("hello")
        paths = box.paths()
        holder = mr._Lock(paths, timeout=2)
        holder.__enter__()
        self.assertTrue(holder.held)
        out = mock.Mock()
        try:
            with mock.patch.object(mr, "LOCK_TIMEOUT", 0.05), mock.patch.object(sys, "stdout", out):
                for i in range(4):
                    mr.hook_prompt(paths, {"prompt": f"the password is Pending-Value-{i}"})
        finally:
            holder.__exit__()
        self.assertEqual(box.fingerprints(), [], "the shared store was not rewritten without the lock")
        self.assertEqual(len(mr._pending_files(paths)), 4)
        box.prompt("hello again")
        self.assertEqual(len(box.fingerprints()), 4)
        self.assertEqual(mr._pending_files(paths), [])
        self.assertNotIn(b"Pending-Value", box.everything_stored())

    def test_a_pending_fingerprint_works_at_once_and_later(self):
        box = sandbox.Box()
        box.prompt("hello")
        paths = box.paths()
        box.write("n.md", "ref Pending-Value-9 here\n")
        box.prompt("hello")
        holder = mr._Lock(paths, timeout=2)
        holder.__enter__()
        try:
            with mock.patch.object(mr, "LOCK_TIMEOUT", 0.05), mock.patch.object(sys, "stdout", mock.Mock()):
                mr.hook_prompt(paths, {"prompt": "the password is Pending-Value-9"})
        finally:
            holder.__exit__()
        self.assertEqual(box.read("n.md"), f"ref {mr.TAG} here\n")


class TestCommands(unittest.TestCase):
    def test_add_refuses_a_value_too_long(self):
        box = sandbox.Box()
        result = box.run("add", stdin=b"x" * (mr.MAX_VALUE + 1) + b"\n")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("saved", result.out)

    def test_add_ignores_spaces_at_the_ends(self):
        box = sandbox.Box()
        box.write("n.md", "ref Spaced-Value-1 here\n")
        box.run("add", stdin=b"  Spaced-Value-1  \n")
        self.assertEqual(box.read("n.md"), f"ref {mr.TAG} here\n")

    def test_forget_takes_both_forms(self):
        box = sandbox.Box()
        box.prompt("the password is Bang-Value-9!")
        self.assertEqual(len(box.fingerprints()), 2)
        self.assertEqual(box.run("forget", stdin=b"Bang-Value-9\n").returncode, 0)
        self.assertEqual(box.fingerprints(), [])

    def test_reset_removes_set_aside_copies(self):
        box = sandbox.Box()
        box.prompt("the password is Stored-Value-3")
        with open(os.path.join(box.data, "fingerprints.json"), "wb") as f:
            f.write(b"[broken")
        box.prompt("hello")
        self.assertTrue(any(".corrupt-" in n for n in os.listdir(box.data)))
        box.run("reset", "--yes")
        self.assertFalse(any(".corrupt-" in n for n in os.listdir(box.data)))

    def test_a_value_on_the_command_line_is_not_repeated(self):
        for command in ("add", "forget"):
            result = sandbox.Box().run(command, "Argv-Value-3")
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Argv-Value-3", result.out + result.err)

    def test_reading_without_a_terminal_warns_that_it_is_visible(self):
        self.assertIn("visible", sandbox.Box().run("add", stdin=b"Warned-Value-4\n").err)
