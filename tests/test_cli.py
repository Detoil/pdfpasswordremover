import json
import subprocess
import sys
from pathlib import Path

import pikepdf
import pytest

from pdf_unlock.cli import main

PASSWORD = "s3cret pass"


def make_pdf(path: Path, user: str = "", owner: str = "", R: int = 6, pages: int = 2) -> Path:
    pdf = pikepdf.new()
    for _ in range(pages):
        pdf.add_blank_page()
    if user or owner:
        allow = pikepdf.Permissions(extract=False, print_highres=False, modify_other=False)
        enc = pikepdf.Encryption(user=user, owner=owner or user, R=R, allow=allow, metadata=R >= 4, aes=R >= 4)
        pdf.save(path, encryption=enc)
    else:
        pdf.save(path)
    return path


def is_encrypted(path: Path) -> bool:
    try:
        with pikepdf.open(path) as pdf:
            return pdf.is_encrypted
    except pikepdf.PasswordError:
        return True


def run_json(capsys, argv):
    code = main([*argv, "--json"])
    out = capsys.readouterr().out
    return code, json.loads(out)


@pytest.mark.parametrize("R", [2, 3, 4, 6])
def test_unlocks_with_user_password(tmp_path, capsys, R):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD, owner="owner", R=R)
    code, result = run_json(capsys, [str(src), "-p", PASSWORD])
    assert code == 0
    out = tmp_path / "locked-unlocked.pdf"
    assert result["ok"] and result["output"] == str(out)
    assert result["was_encrypted"] is True
    assert result["pages"] == 2
    assert not is_encrypted(out)


def test_owner_password_also_works(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD, owner="the-owner")
    code, result = run_json(capsys, [str(src), "-p", "the-owner"])
    assert code == 0
    assert result["encryption"]["opened_with"] == "owner_password"


def test_wrong_password(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    code, result = run_json(capsys, [str(src), "-p", "nope"])
    assert code == 3
    assert result == {"ok": False, "error": "bad_password", "message": "incorrect password", "exit_code": 3}
    assert not (tmp_path / "locked-unlocked.pdf").exists()


def test_missing_password(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    code, result = run_json(capsys, [str(src)])
    assert code == 3
    assert result["message"] == "this PDF requires a password"


def test_restrictions_only_pdf_needs_no_password(tmp_path, capsys):
    src = make_pdf(tmp_path / "restricted.pdf", owner="owner-only")
    code, result = run_json(capsys, [str(src)])
    assert code == 0
    assert result["was_encrypted"] is True
    assert not is_encrypted(Path(result["output"]))


def test_unencrypted_pdf_is_copied(tmp_path, capsys):
    src = make_pdf(tmp_path / "plain.pdf")
    code, result = run_json(capsys, [str(src)])
    assert code == 0
    assert result["was_encrypted"] is False
    assert result["encryption"] is None


def test_explicit_output_and_force(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    out = tmp_path / "sub" / "out.pdf"
    assert main([str(src), "-p", PASSWORD, "-o", str(out)]) == 0
    assert capsys.readouterr().out.strip() == str(out)
    assert not is_encrypted(out)

    code, result = run_json(capsys, [str(src), "-p", PASSWORD, "-o", str(out)])
    assert code == 5 and result["error"] == "output_exists"

    code, result = run_json(capsys, [str(src), "-p", PASSWORD, "-o", str(out), "--force"])
    assert code == 0


def test_in_place(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    code, result = run_json(capsys, [str(src), "-p", PASSWORD, "--in-place"])
    assert code == 0 and result["output"] == str(src)
    assert not is_encrypted(src)
    assert list(tmp_path.iterdir()) == [src]


def test_output_same_as_input_rejected(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    code, result = run_json(capsys, [str(src), "-p", PASSWORD, "-o", str(src), "--force"])
    assert code == 2
    assert is_encrypted(src)


def test_dry_run_writes_nothing(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    code, result = run_json(capsys, [str(src), "-p", PASSWORD, "--dry-run"])
    assert code == 0 and result["dry_run"] is True and result["output"] is None
    assert list(tmp_path.iterdir()) == [src]


def test_password_from_env(tmp_path, capsys, monkeypatch):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    monkeypatch.setenv("PDF_PW", PASSWORD)
    code, _ = run_json(capsys, [str(src), "--password-env", "PDF_PW"])
    assert code == 0


def test_password_env_unset(tmp_path, capsys, monkeypatch):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    monkeypatch.delenv("PDF_PW", raising=False)
    code, result = run_json(capsys, [str(src), "--password-env", "PDF_PW"])
    assert code == 2


def test_password_from_file(tmp_path, capsys):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    pw = tmp_path / "pw.txt"
    pw.write_text(PASSWORD + "\n")
    code, _ = run_json(capsys, [str(src), "--password-file", str(pw)])
    assert code == 0


def test_missing_input(tmp_path, capsys):
    code, result = run_json(capsys, [str(tmp_path / "nope.pdf"), "-p", "x"])
    assert code == 4 and result["error"] == "input_not_found"


def test_not_a_pdf(tmp_path, capsys):
    bad = tmp_path / "bad.pdf"
    bad.write_text("hello, not a pdf")
    code, result = run_json(capsys, [str(bad)])
    assert code == 4 and result["error"] == "invalid_pdf"


def run_module(args, stdin=b""):
    return subprocess.run(
        [sys.executable, "-m", "pdf_unlock", *args], input=stdin, capture_output=True, check=False
    )


def test_password_stdin_subprocess(tmp_path):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    proc = run_module([str(src), "--password-stdin", "--json"], stdin=(PASSWORD + "\n").encode())
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


def test_stdin_to_stdout_subprocess(tmp_path):
    src = make_pdf(tmp_path / "locked.pdf", user=PASSWORD)
    proc = run_module(["-", "-p", PASSWORD, "--json"], stdin=src.read_bytes())
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith(b"%PDF-")
    assert json.loads(proc.stderr)["output"] == "-"
    out = tmp_path / "piped.pdf"
    out.write_bytes(proc.stdout)
    assert not is_encrypted(out)


def test_password_given_for_unencrypted_pdf_is_quiet(tmp_path):
    src = make_pdf(tmp_path / "plain.pdf")
    proc = run_module([str(src), "-p", "unneeded"])
    assert proc.returncode == 0
    assert proc.stderr == b""
