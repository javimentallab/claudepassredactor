"""Formats, labels, URLs, fingerprints and spans, independent of language.

Token-shaped values are assembled at run time. Nothing here is a real credential, and no scanner
should have to tell a fixture from a leak.
"""
import time
import unicodedata
import unittest

from tests.sandbox import mr

FILL = "A1b2C3d4"
KEY_LINE = "MIIE" + FILL * 7 + "abcd"     # as long as a real line of a key
HEX = "ab12cd34" * 4                     # 32 hex digits
KEY = b"k" * mr.KEY_BYTES


def redact(text, key=None, index=None):
    return mr.apply_spans(text, mr.find_spans(text, key, index))


def index_for(*pairs):
    entries = []
    for value, strength in pairs:
        entries += mr._entries_for(KEY, value, strength)
    return mr.build_index(entries)


PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
PGP_BEGIN = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"
PGP_END = "-----END " + "PGP PRIVATE KEY BLOCK-----"

TOKENS = {
    "github_classic": "gh" + "p_" + FILL * 5,
    "github_oauth": "gh" + "o_" + FILL * 5,
    "github_fine_grained": "github" + "_pat_" + FILL * 5,
    "gitlab": "gl" + "pat-" + FILL * 3,
    "anthropic": "sk-" + "ant-" + FILL * 4,
    "openai_legacy": "sk-" + FILL * 5,
    "openai_project": "sk-" + "proj-" + FILL * 5,
    "stripe": "sk_" + "live_" + FILL * 3,
    "stripe_webhook": "whsec_" + FILL * 4,
    "slack_bot": "xox" + "b-" + "1234567890-" + FILL * 2,
    "slack_webhook": "https://hooks.slack" + ".com/services/T00000/B00000/" + FILL * 3,
    "discord_webhook": "https://discord" + ".com/api/webhooks/123456789/" + FILL * 5,
    "aws_access_key": "AK" + "IA" + "Q2W3E4R5T6Y7U8I9",
    "aws_temporary": "AS" + "IA" + "Q2W3E4R5T6Y7U8I9",
    "google": "AI" + "za" + "Sy" + FILL * 4 + "abc",
    "npm": "npm" + "_" + FILL * 5,
    "pypi": "pypi" + "-" + FILL * 6,
    "huggingface": "hf" + "_" + FILL * 5,
    "sendgrid": "SG" + "." + FILL * 3 + "." + FILL * 4,
    "telegram": "123456789" + ":AA" + FILL * 5,
    "digitalocean": "dop" + "_v1_" + "ab12cd34" * 6,
    "jwt": "eyJ" + FILL + "." + "eyJ" + FILL + "." + FILL * 2,
    "twilio": "SK" + HEX,
    "shopify": "shp" + "at_" + HEX,
    "square": "sq0" + "atp-" + FILL * 3,
    "mailgun": "key" + "-" + HEX,
    "mailchimp": HEX + "-us" + "21",
    "atlassian": "ATA" + "TT3" + FILL * 13,
    "notion": "ntn" + "_" + FILL * 6,
    "linear": "lin" + "_api_" + FILL * 5,
    "groq": "gs" + "k_" + FILL * 7,
    "xai": "xa" + "i-" + FILL * 9,
    "replicate": "r8" + "_" + FILL * 5,
    "perplexity": "pp" + "lx-" + FILL * 6,
    "supabase": "sb" + "p_" + HEX + "ab12cd34",
    "doppler": "dp" + ".st." + FILL * 6,
    "postman": "PM" + "AK-" + HEX[:24] + "-" + HEX + "ab",
    "databricks": "da" + "pi" + HEX,
    "grafana": "gl" + "sa_" + FILL * 4 + "_" + "ab12cd34",
    "newrelic": "NR" + "AK-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N",
    "sentry": "sn" + "trys_" + FILL * 6,
    "tailscale": "ts" + "key-auth-" + FILL + "CNTRL-" + FILL * 3,
    "age": "AGE-SECRET" + "-KEY-1" + "QZ9" * 19 + "Q",
    "pem": PEM_BEGIN + "\n" + KEY_LINE + "\n" + FILL + "==\n" + PEM_END,
    "pgp": PGP_BEGIN + "\n" + KEY_LINE + "\n" + PGP_END,
}


class TestFormats(unittest.TestCase):
    pass


def _make_format_test(value):
    def test(self):
        text = f"before\nwe use {value} here\nafter\n"
        self.assertEqual(redact(text), f"before\nwe use {mr.TAG} here\nafter\n")
    return test


for _name, _value in TOKENS.items():
    setattr(TestFormats, f"test_{_name}", _make_format_test(_value))


class TestFormatEdges(unittest.TestCase):
    def test_tokens_are_remembered_from_a_message(self):
        token = TOKENS["github_classic"]
        self.assertIn((token, "strong"), mr.prompt_candidates(f"please use {token} for this"))

    def test_authorization_header_keeps_the_scheme(self):
        value = FILL * 3
        self.assertEqual(redact(f"Authorization: Bearer {value}\n"), f"Authorization: Bearer {mr.TAG}\n")

    def test_bearer_keeps_the_scheme(self):
        value = FILL * 4
        self.assertEqual(redact(f"curl -H 'bearer {value}'\n"), f"curl -H 'bearer {mr.TAG}'\n")

    def test_private_key_with_no_end_line(self):
        self.assertEqual(redact(PEM_BEGIN + "\n" + KEY_LINE + "\n" + KEY_LINE + "\n"), mr.TAG + "\n")

    def test_private_key_with_no_end_line_keeps_following_prose(self):
        text = "Before.\n" + PEM_BEGIN + "\n" + KEY_LINE + "\n" + KEY_LINE + "\nThe rest of this note stays.\n"
        self.assertEqual(redact(text), f"Before.\n{mr.TAG}\nThe rest of this note stays.\n")

    def test_private_key_with_armor_headers_and_blank_lines(self):
        text = PGP_BEGIN + "\nVersion: Demo 1.0\n\n" + KEY_LINE + "\n" + FILL + "==\n"
        self.assertEqual(redact(text), mr.TAG + "\n")

    def test_a_cut_off_key_does_not_swallow_the_next_block_or_the_prose_between(self):
        full = PEM_BEGIN + "\n" + KEY_LINE + "\n" + PEM_END
        text = PEM_BEGIN + "\n" + KEY_LINE + "\nSome prose in between.\n" + full + "\nAfter.\n"
        self.assertEqual(redact(text), f"{mr.TAG}\nSome prose in between.\n{mr.TAG}\nAfter.\n")

    def test_private_keys_are_noticed_in_a_message_but_not_hashed(self):
        block = PEM_BEGIN + "\n" + KEY_LINE + "\n" + PEM_END
        self.assertEqual(len(mr.prompt_candidates(f"here it is:\n{block}\n")), 1)
        self.assertEqual(mr._entries_for(KEY, block, "strong"), [])

    def test_public_key_block_is_left_alone(self):
        text = "-----BEGIN " + "PUBLIC KEY-----\nMIIB" + FILL + "\n-----END " + "PUBLIC KEY-----\n"
        self.assertEqual(redact(text), text)

    def test_demo_tokens_are_left_alone(self):
        for text in ("gh" + "p_" + "x" * 36, "AK" + "IAIOSFODNN7EXAMPLE", "sk-" + "ant-" + "X" * 30):
            self.assertEqual(redact(f"like {text} in the docs\n"), f"like {text} in the docs\n")

    def test_slugs_that_start_with_sk_are_left_alone(self):
        for text in ("sk-learn-tutorial-chapter-one-section-2024", "sk-backup-before-tray-removal-20261023",
                     "disk-" + FILL * 5):
            self.assertEqual(redact(f"see {text} here\n"), f"see {text} here\n")

    def test_a_token_inside_a_longer_word_is_left_alone(self):
        for name in ("github_classic", "gitlab", "anthropic", "aws_access_key", "google", "npm", "huggingface"):
            for prefix in ("x", "9", "_", "-"):
                text = f"see {prefix}{TOKENS[name]} here\n"
                self.assertEqual(redact(text), text, text)

    def test_prose_after_bearer_is_left_alone(self):
        text = "The bearer of this document may enter.\n"
        self.assertEqual(redact(text), text)


class TestAssigned(unittest.TestCase):
    """NAME=value with a random value and a name that says nothing about secrets."""
    RANDOM = "Xk9fP2mQ" + "7vL4nR8s" + "T1wZ"

    def test_random_value_is_masked(self):
        for text in (f"GRAFANA_AUTH={self.RANDOM}\n", f"cookie: HSID={self.RANDOM}; SSID=x\n",
                     f'export HA_LLAVE="{self.RANDOM}"\n'):
            with self.subTest(text=text):
                self.assertEqual(redact(text), text.replace(self.RANDOM, mr.TAG))

    def test_remembered_from_a_message(self):
        self.assertIn((self.RANDOM, "strong"), mr.prompt_candidates(f"set GRAFANA_AUTH={self.RANDOM} please"))

    def test_ids_versions_hashes_and_names_are_left_alone(self):
        for text in ("GIT_COMMIT=4f2a9c81d7e6b5a4f3e2d1c0b9a8f7e6d5c4b3a2", f"SESSION_ID={self.RANDOM}",
                     "BUILD=2024-11-07T10:00:00Z", "NODE_ENV=production", "IMAGE_TAG=v1.2.3-alpine3.19",
                     "KEY_KP5: self.evdev.ecodes.KEY_KP5x9", "HEAD:src/Components/App2.css",
                     "FAIL: test_secret_Label_zh_42", "GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D",
                     "VIPRE: Trojan.Win32.Generic2.91", "KEY_PHILIPS_POWER = Philips_Remote_KEY_POWER2",
                     "REQUEST=3f2b9c4e-8a7d-4e6f-9b1a-2c3d4e5f6a7b", "MSG=msg_01XyZ9AbCdEfGhIjKlMnOpQr",
                     "lower_case=Xk9fP2mQ7vL4nR8sT1wZ"):
            with self.subTest(text=text):
                self.assertEqual(redact(text + "\n"), text + "\n")


class TestLabels(unittest.TestCase):
    pass


LABELS = {
    "env_var": ("DB_PASSWORD=Under-Score-55\n", "Under-Score-55"),
    "env_var_long": ("MYSQL_ROOT_PASSWORD=Under-Score-66\n", "Under-Score-66"),
    "env_var_glued": ("PGPASSWORD=Under-Score-77\n", "Under-Score-77"),
    "api_key_env": ("OPENAI_API_KEY=Ab12Cd34Ef56Gh78\n", "Ab12Cd34Ef56Gh78"),
    "aws_secret": ("aws_secret_access_key = Ab12Cd34Ef56Gh78Ij90\n", "Ab12Cd34Ef56Gh78Ij90"),
    "client_secret": ('client_secret: "Ab12Cd34Ef56Gh78"\n', "Ab12Cd34Ef56Gh78"),
    "json": ('{"user": "ana", "password": "Json-Value-31"}\n', "Json-Value-31"),
    "json_escaped": ('{\\"password\\": \\"Json-Value-32\\"}\n', "Json-Value-32"),
    "yaml": ("database:\n  password: Yaml-Value-33\n", "Yaml-Value-33"),
    "table": ("| password | Table-Value-34 |\n", "Table-Value-34"),
    "bold_label": ("**Password:** Bold-Value-35\n", "Bold-Value-35"),
    "bold_value": ("Password: **Bold-Value-36**\n", "Bold-Value-36"),
    "backticks": ("password: `Tick-Value-37`\n", "Tick-Value-37"),
    "cli_flag": ("mysql --password=Flag-Value-38 prod\n", "Flag-Value-38"),
    "xml": ("<password>Xml-Value-39</password>\n", "Xml-Value-39"),
    "arrow": ("password -> Arrow-Value-40\n", "Arrow-Value-40"),
    "spaced_dash": ("password - Dash-Value-41\n", "Dash-Value-41"),
    "dollar_inside": ("password: Pa$$w0rd2024\n", "Pa$$w0rd2024"),
    "dollar_first": ("password: $ecret-Value-42\n", "$ecret-Value-42"),
    "percent": ("password: P%ssw0rd-43\n", "P%ssw0rd-43"),
    "parenthesis": ("password: Pa(ss)w0rd-44\n", "Pa(ss)w0rd-44"),
    "braces": ("password: Br{ace}s-45\n", "Br{ace}s-45"),
    "at_sign": ("password: @Home-Value-46\n", "@Home-Value-46"),
    "non_ascii": ("password: Señor-Ñandú-47\n", "Señor-Ñandú-47"),
    "exclamation": ("password: Bang-Value-48!\n", "Bang-Value-48!"),
    "long_digits": ("password: 918273645\n", "918273645"),
}


def _make_label_test(text, value):
    def test(self):
        self.assertEqual(redact(text), text.replace(value, mr.TAG))
    return test


for _name, (_text, _value) in LABELS.items():
    setattr(TestLabels, f"test_{_name}", _make_label_test(_text, _value))


class TestLabelEdges(unittest.TestCase):
    def test_connection_string_keeps_the_next_field(self):
        text = "Server=db;Password=Conn-Value-50;Database=sales\n"
        self.assertEqual(redact(text), f"Server=db;Password={mr.TAG};Database=sales\n")

    def test_connection_string_fingerprints_only_the_password(self):
        self.assertIn(("Conn-Value-51", "strong"),
                      mr.prompt_candidates("Server=db;Password=Conn-Value-51;Database=sales"))

    def test_query_string_keeps_the_next_field(self):
        text = "https://x.test/?password=Query-Value-52&page=2\n"
        self.assertEqual(redact(text), f"https://x.test/?password={mr.TAG}&page=2\n")

    def test_long_secret_leaves_no_tail(self):
        secret = "Lg7-" + "abcdef1234" * 30
        self.assertEqual(redact(f"password: {secret} done\n"), f"password: {mr.TAG} done\n")

    def test_long_secret_is_remembered_whole(self):
        secret = "Lg7-" + "abcdef1234" * 30
        self.assertIn((secret, "strong"), mr.prompt_candidates(f"the password is {secret}"))

    def test_ambiguous_words_are_not_used_on_notes(self):
        text = "la clave es Gar4je-Norte-01 y el token es Qw3rTy-Uiop-98\n"
        self.assertEqual(redact(text), text)
        values = {v for v, _ in mr.prompt_candidates(text)}
        self.assertEqual(values, {"Gar4je-Norte-01", "Qw3rTy-Uiop-98"})

    def test_a_label_ending_in_a_colon_is_not_taken_by_a_soft_link(self):
        values = {v for v, _ in mr.prompt_candidates("the password to server-2024: Real-Value-53")}
        self.assertEqual(values, {"Real-Value-53"})

    def test_trailing_exclamation_gives_both_forms(self):
        values = {v for v, _ in mr.prompt_candidates("the password is Bang-Value-54!")}
        self.assertEqual(values, {"Bang-Value-54", "Bang-Value-54!"})

    def test_already_redacted_is_stable(self):
        for text in (f"password: {mr.TAG}\n", "contraseña: [REDACTADO]\n", "password: <redacted>\n"):
            self.assertEqual(redact(text), text)
            self.assertEqual(mr.prompt_candidates(text), [])

    def test_second_pass_changes_nothing(self):
        text = "password: Twice-Value-55 and " + TOKENS["aws_access_key"] + " and x://u:Twice-Value-56@h\n"
        once = redact(text)
        self.assertEqual(once.count(mr.TAG), 3)
        self.assertEqual(redact(once), once)

    def test_values_that_are_not_secrets(self):
        for value in ("${VAR}", "$VAR", "$(cmd)", "%VAR%", "{name}", "{{name}}", "<name>", "sha1(nonce",
                      "os.getenv('X')", "process.env.DB", "********", "xxxx", "XXXXXX", "/etc/secret",
                      "~/secret", "./secret", "C:\\secret", "notes.txt", "key.pem", "https://x.test",
                      "1.2.3", "v1.2.3-beta", "10.0.0.5", "2024-03-01", "12:30", "8chars", "100MB",
                      "a.person@example.com", "[REDACTED]", "your_password", "changeme", "incorrect",
                      "abc", "(see"):
            self.assertIsNone(mr.classify(value), value)

    def test_two_words_joined_by_punctuation_are_not_secrets_without_quotes(self):
        for value in ("well-known", "read-only", "auto-generated", "d'origine", "l’attaquant", "read/write"):
            self.assertIsNone(mr.classify(value), value)
            self.assertEqual(mr.classify(value, quoted=True), "weak", value)

    def test_values_that_are_secrets(self):
        for value in ("Pa$$w0rd2024", "$ecret123", "P%ssw0rd11", "Pa(ss)w0rd12", "Hunter2024", "a1!b2@c3#",
                      "correct-horse-battery", "Señor-2024"):
            self.assertEqual(mr.classify(value), "strong", value)

    def test_only_letters_need_quotes(self):
        self.assertIsNone(mr.classify("sunshine"))
        self.assertEqual(mr.classify("sunshine", quoted=True), "strong")
        self.assertIsNone(mr.classify("required", quoted=True))

    def test_marks_count_as_letters(self):
        self.assertIsNone(mr.classify("अस्वीकार"))
        self.assertIsNone(mr.classify("สำคัญมาก"))


class TestFoundInRealProse(unittest.TestCase):
    """False positives found by running the tool over encyclopedia articles about passwords."""

    def test_syntax_of_a_url_in_a_document(self):
        text = "URL: ftp://[Benutzername[:Passwort]@]Servername[:Port]/Verzeichnispfad/Dateiname\n"
        self.assertEqual(redact(text), text)

    def test_html_attribute_value(self):
        text = 'A self-assigned password can instead use autocomplete="newpassword".\n'
        self.assertEqual(redact(text), text)

    def test_punctuation_right_after_the_link(self):
        self.assertEqual(mr.prompt_candidates('la seguridad de las contraseñas es,"Tener una mezcla'), [])

    def test_a_word_followed_by_a_bracket_in_another_script(self):
        self.assertEqual(redact("약한 비밀번호: contraseña(스페인어), 등\n"), "약한 비밀번호: contraseña(스페인어), 등\n")

    def test_numeric_range(self):
        self.assertEqual(mr.prompt_candidates("รหัสผ่านได้เร็วเพิ่มขึ้นเป็น 50-100 เท่า"), [])

    def test_quoted_phrase_in_a_script_without_spaces(self):
        self.assertEqual(mr.prompt_candidates("パスワードの数を「数百万人分」に修正"), [])

    def test_a_value_right_after_a_totp_secret_label_is_still_found(self):
        text = "otpauth://totp/Demo?secret=JBSWY3DPFQQHO33SNRSCC"
        self.assertIn(("JBSWY3DPFQQHO33SNRSCC", "strong"), mr.prompt_candidates(text))


class TestUrls(unittest.TestCase):
    def assert_masks(self, text, value):
        self.assertEqual(redact(text), text.replace(value, mr.TAG), text)

    def test_user_and_password(self):
        self.assert_masks("postgres://bob:Url-Value-60@db:5432/x\n", "Url-Value-60")

    def test_empty_user(self):
        self.assert_masks("redis://:Url-Value-61@cache:6379/0\n", "Url-Value-61")

    def test_at_sign_inside_the_password(self):
        self.assert_masks("postgres://bob:p@ss-Url-62@db/x\n", "p@ss-Url-62")

    def test_only_letters_of_some_length(self):
        self.assert_masks("https://bob:supersecretword@host/\n", "supersecretword")

    def test_long_password(self):
        value = "Url-" + "abcdef1234" * 20
        self.assert_masks(f"https://bob:{value}@host/\n", value)

    def test_left_alone(self):
        for text in ("rtsp://admin:123456@camera/x\n", "rtsp://<user>:<pass>@<ip>:554/x\n",
                     "postgres://user:password@localhost/db\n", "https://user:$PASSWORD@host/\n",
                     "https://example.com:8080/path?mail=a@b.test\n", "ssh://git@host:22/x\n",
                     "https://host:8080/x@y\n", "mailto:a@b.test\n"):
            self.assertEqual(redact(text), text, text)


class TestFingerprints(unittest.TestCase):
    def test_found_with_no_label(self):
        index = index_for(("Given-Value-70", "strong"))
        self.assertEqual(redact("note: Given-Value-70 end\n", KEY, index), f"note: {mr.TAG} end\n")

    def test_edges(self):
        index = index_for(("Given-Value-71", "strong"))
        for left, right in (("(", ")"), ("**", "**"), ("_", "_"), ("`", "`"), ('"', '"'), ("=", "&"),
                            ("\\\"", "\\\""), ("-", "-"), ("~", "~"), (":", ":")):
            text = f"x {left}Given-Value-71{right} y\n"
            self.assertEqual(redact(text, KEY, index), f"x {left}{mr.TAG}{right} y\n", text)

    def test_starts_with_a_punctuation_character(self):
        for secret in ("@Home-Value-72", "(Paren-Value-73", ":Colon-Value-74", "=Equal-Value-75"):
            index = index_for((secret, "strong"))
            self.assertEqual(redact(f"I use {secret} here\n", KEY, index), f"I use {mr.TAG} here\n", secret)

    def test_ends_with_a_punctuation_character(self):
        index = index_for(("Bang-Value-76!", "strong"))
        self.assertEqual(redact("I use Bang-Value-76! here\n", KEY, index), f"I use {mr.TAG} here\n")

    def test_longer_form_wins(self):
        index = index_for(("Bang-Value-77", "strong"), ("Bang-Value-77!", "strong"))
        self.assertEqual(redact("I use Bang-Value-77! here\n", KEY, index), f"I use {mr.TAG} here\n")

    def test_inside_a_longer_word_is_left_alone(self):
        index = index_for(("Given78", "strong"))
        self.assertEqual(redact("xGiven78 Given78x\n", KEY, index), "xGiven78 Given78x\n")

    def test_next_to_text_without_spaces(self):
        index = index_for(("Hunter2024", "strong"))
        for text in ("我的是Hunter2024，别说。\n", "これはHunter2024です。\n", "그건 Hunter2024입니다\n",
                     "อันนี้Hunter2024นะ\n"):
            self.assertNotIn("Hunter2024", redact(text, KEY, index), text)

    def test_value_in_a_script_without_spaces(self):
        index = index_for(("天王盖地虎2024", "strong"))
        self.assertEqual(redact("备注：天王盖地虎2024，别说。\n", KEY, index), f"备注：{mr.TAG}，别说。\n")

    def test_decomposed_text_matches_a_composed_secret(self):
        secret = unicodedata.normalize("NFC", "Señor-Value-79")
        index = index_for((secret, "strong"))
        text = "note " + unicodedata.normalize("NFD", secret) + " end\n"
        self.assertEqual(redact(text, KEY, index), f"note {mr.TAG} end\n")

    def test_with_spaces_when_added_by_hand(self):
        index = index_for(("correct horse battery staple", "strong"))
        self.assertEqual(redact("it is correct horse battery staple, ok\n", KEY, index), f"it is {mr.TAG}, ok\n")

    def test_weak_needs_a_keyword_in_the_same_sentence(self):
        index = index_for(("4471", "weak"))
        self.assertEqual(redact("The pin is 4471.\n", KEY, index), f"The pin is {mr.TAG}.\n")
        self.assertEqual(redact("Year 4471 is far.\n", KEY, index), "Year 4471 is far.\n")
        self.assertEqual(redact("The pin is set. Year 4471 is far.\n", KEY, index), "The pin is set. Year 4471 is far.\n")

    def test_weak_is_not_found_by_a_substring_of_another_word(self):
        index = index_for(("4471", "weak"))
        for text in ("The port mapping for 4471 is fine.\n", "In my opinion 4471 is fine.\n",
                     "A compass and 4471 maps.\n"):
            self.assertEqual(redact(text, KEY, index), text, text)

    def test_weak_glued_to_punctuation_is_left_alone(self):
        index = index_for(("4471", "weak"))
        for text in ("pin ticket-4471\n", "pin 4471-old\n", "pin v.4471\n", "pin 4471.5\n"):
            self.assertEqual(redact(text, KEY, index), text, text)

    def test_weak_as_a_url_password(self):
        index = index_for(("4471", "weak"))
        self.assertEqual(redact("rtsp://a:4471@h/x\n", KEY, index), f"rtsp://a:{mr.TAG}@h/x\n")

    def test_hash_stores_no_plain_text(self):
        entries = mr._entries_for(KEY, "Given-Value-80", "strong")
        self.assertNotIn("Given-Value-80", repr(entries))
        self.assertEqual(entries[0]["h"], mr.fingerprint(KEY, "Given-Value-80"))
        self.assertNotEqual(entries[0]["h"], mr.fingerprint(b"z" * mr.KEY_BYTES, "Given-Value-80"))


class TestHostileInput(unittest.TestCase):
    """Each of these took minutes or never finished before the scans were made linear. A quarter
    of a mebibyte is enough to tell: a quadratic scan would take far longer than the limit."""
    SIZE = 256 * 1024
    LIMIT = 30    # seconds, generous for slow CI machines

    def check(self, text):
        start = time.perf_counter()
        mr.find_spans(text)
        self.assertLess(time.perf_counter() - start, self.LIMIT)

    def test_many_begin_lines_with_no_end(self):
        self.check(((PEM_BEGIN + "\n") * 10000)[:self.SIZE])

    def test_many_keywords_on_one_line(self):
        self.check(("password " * 30000)[:self.SIZE])

    def test_opening_quotes_that_never_close(self):
        self.check(("password «" * 30000)[:self.SIZE])

    def test_url_starts(self):
        self.check(("x://a:" * 50000)[:self.SIZE])

    def test_runs_of_token_prefixes(self):
        self.check(("sk-" * 85000)[:self.SIZE])
        self.check(("eyJ" * 85000)[:self.SIZE])

    def test_labels_with_no_spaces(self):
        self.check(("password=" * 28000)[:self.SIZE])

    def test_minified_json_on_one_line(self):
        self.check(('{"password":"x","user":"y","a":null,' * 8000)[:self.SIZE])

    def test_budget_stops_a_slow_review(self):
        with self.assertRaises(mr.TooSlow):
            mr.find_spans("password " * 5000, deadline=0)

    def test_many_redactions_on_one_note_report_lines_quickly(self):
        text = "password: Many-Value-11\n" * 8000
        start = time.perf_counter()
        spans = mr.find_spans(text)
        self.assertEqual(mr._line_numbers(text, spans), list(range(1, 8001)))
        self.assertLess(time.perf_counter() - start, self.LIMIT)


class TestSpans(unittest.TestCase):
    def test_overlapping_spans_leave_no_tail(self):
        index = index_for(("Alpha-111 Bravo", "strong"), ("Bravo-222-Charlie", "strong"))
        self.assertEqual(redact("x Alpha-111 Bravo-222-Charlie y\n", KEY, index), f"x {mr.TAG} y\n")

    def test_line_endings_and_surroundings_survive(self):
        text = "uno\r\npassword: Crlf-Value-90\r\n\r\ndos\tpassword: Tab-Value-91\r\n"
        expected = f"uno\r\npassword: {mr.TAG}\r\n\r\ndos\tpassword: {mr.TAG}\r\n"
        self.assertEqual(redact(text), expected)

    def test_quick_on_a_big_note(self):
        index = index_for(*[(f"Given-Value-{i:04d}-{'x' * (i % 30)}", "strong") for i in range(40)])
        text = "Some ordinary sentence, with commas (and brackets), about nothing at all.\n" * 2000
        start = time.perf_counter()
        self.assertEqual(redact(text, KEY, index), text)
        self.assertLess(time.perf_counter() - start, 20, f"{len(text)} characters")
