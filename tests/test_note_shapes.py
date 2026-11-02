"""Text that looks like a label and a value, and is not one. Replacing it could not be undone."""
import unittest

from tests import sandbox
from tests.sandbox import mr


def redact(text):
    return mr.apply_spans(text, mr.find_spans(text))


class TestNoteShapes(unittest.TestCase):
    def test_left_alone(self):
        for text in (
            "**Ajuste (con permisos, contraseña dada por la dueña):** `demo-backup-job.service` (enabled) carga\n",
            "usuario `admin`, contraseña en `~/apps/.env` → `ACME_ADMIN_PASSWORD`. API local\n",
            "(username=demo, salt=`0_<id>_<ts>`, password=`md5(salt + md5(pwd + key))`, key sacada de `/y`)\n",
            "- [Sin guardar contraseñas](sin_guardar.md) · ⭐[llave demo = abrir-demo.ps1](abrir-demo-cifrado.md) no pedirla\n",
            "Contraseña NFD+UTF-16; vector compartido con Rust\n",
            "- `ACME_API_KEY` **obligatoria aunque sea falsa**: `resize_images` crea el cliente\n",
            "Contraseñas · llave demo = abrir-demo-42\n",
            "[Contraseñas](sin_guardar.md) y [llave demo = abrir-demo-42]\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(redact(text), text)

    def test_the_value_inside_the_brackets_is_still_found(self):
        self.assertEqual(redact("cifrado (AES, pwd Qm4Vt8Ln3Xs6Pd2) → `demo.bat` (reinicio)\n"),
                         f"cifrado (AES, pwd {mr.TAG}) → `demo.bat` (reinicio)\n")

    def test_a_bracket_right_after_the_keyword_is_still_the_label(self):
        for text in ("[password]: Hunter-2024x\n", "the password (the new one) is Hunter-2024x\n"):
            with self.subTest(text=text):
                self.assertNotIn("Hunter-2024x", redact(text))


class TestStrayNul(unittest.TestCase):
    def test_a_stray_nul_does_not_make_a_note_binary(self):
        box = sandbox.Box()
        data = ("x" * 200 + " responde `ERROR\x00`, " + "y" * 200 + "\npassword: Note-Value-11\n").encode()
        box.write_bytes("a.md", data)
        report = mr.review(box.paths(), box.roots(), None, {}, {"files": {}})
        self.assertEqual(report.failed, [])
        self.assertIn(b"ERROR\x00", box.read_bytes("a.md"))
        self.assertNotIn(b"Note-Value-11", box.read_bytes("a.md"))


if __name__ == "__main__":
    unittest.main()
