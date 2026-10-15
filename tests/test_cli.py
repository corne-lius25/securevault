import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from securevault.cli import main


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_full_workflow_with_passphrase(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(
            os.environ, {"SECUREVAULT_PASSPHRASE": "s3cret"}
        ):
            code, out, _ = run("keygen", "--bits", "2048", "--out-dir", d, "--name", "k")
            self.assertEqual(code, 0)
            self.assertIn("fingerprint", out)
            pub, priv = f"{d}/k_public.pem", f"{d}/k_private.pem"

            plain = Path(d) / "note.txt"
            plain.write_text("meet at noon")
            self.assertEqual(run("encrypt", str(plain), "-k", pub)[0], 0)
            enc = Path(str(plain) + ".svlt")
            self.assertTrue(enc.exists())
            self.assertNotIn(b"meet at noon", enc.read_bytes())

            plain.unlink()
            code, out, _ = run("decrypt", str(enc), "-k", priv)
            self.assertEqual(code, 0)
            self.assertIn("authentication OK", out)
            self.assertEqual(plain.read_text(), "meet at noon")

    def test_wrong_passphrase_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"SECUREVAULT_PASSPHRASE": "right"}):
                run("keygen", "--bits", "2048", "--out-dir", d, "--name", "k")
                Path(d, "f").write_text("x")
                run("encrypt", f"{d}/f", "-k", f"{d}/k_public.pem")
            with mock.patch.dict(os.environ, {"SECUREVAULT_PASSPHRASE": "wrong"}):
                code, _, err = run("decrypt", f"{d}/f.svlt", "-k", f"{d}/k_private.pem",
                                   "-o", f"{d}/out")
            self.assertEqual(code, 1)
            self.assertIn("error:", err)

    def test_missing_file_and_fingerprint(self):
        code, _, err = run("encrypt", "/nonexistent/file", "-k", "/nonexistent/key.pem")
        self.assertEqual(code, 1)
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(
            os.environ, {"SECUREVAULT_PASSPHRASE": ""}
        ):
            run("keygen", "--bits", "2048", "--out-dir", d, "--name", "k")
            code, out, _ = run("fingerprint", f"{d}/k_public.pem")
            self.assertEqual(code, 0)
            self.assertEqual(len(out.strip().split(":")), 32)


if __name__ == "__main__":
    unittest.main()
