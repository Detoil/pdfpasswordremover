"""Command line interface for pdf-unlock.

Opens a password protected PDF with the supplied password and writes an
unencrypted copy, with all permission restrictions removed.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any, BinaryIO, Optional

import pikepdf

from pdf_unlock import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_BAD_PASSWORD = 3
EXIT_INPUT_ERROR = 4
EXIT_OUTPUT_EXISTS = 5

EPILOG = """\
password sources (pick one; default is an empty password):
  -p/--password VALUE       password on the command line
  --password-env NAME       read it from environment variable NAME
  --password-file PATH      read it from a file (one trailing newline is stripped)
  --password-stdin          read it from stdin (one trailing newline is stripped)

  An empty password is enough for PDFs that only have an owner password
  (printing/copying restrictions but no password to open).

exit codes:
  0  success
  1  unexpected error
  2  invalid arguments
  3  wrong password (or a password is required)
  4  input file missing, unreadable, or not a valid PDF
  5  output file already exists (use --force)

examples:
  pdf-unlock statement.pdf -p hunter2
  pdf-unlock statement.pdf -p hunter2 -o unlocked.pdf --json
  PDF_PASSWORD=hunter2 pdf-unlock statement.pdf --password-env PDF_PASSWORD
  pdf-unlock statement.pdf -p hunter2 --in-place
  pdf-unlock statement.pdf -p hunter2 --dry-run --json
"""


class CliError(Exception):
    def __init__(self, code: int, error: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.error = error
        self.message = message


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf-unlock",
        description="Remove password protection from a PDF and write an unlocked copy.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", help="path to the protected PDF, or - to read from stdin")

    pw = parser.add_mutually_exclusive_group()
    pw.add_argument("-p", "--password", help="password for the PDF")
    pw.add_argument("--password-env", metavar="NAME", help="environment variable holding the password")
    pw.add_argument("--password-file", metavar="PATH", help="file containing the password")
    pw.add_argument("--password-stdin", action="store_true", help="read the password from stdin")

    out = parser.add_mutually_exclusive_group()
    out.add_argument(
        "-o",
        "--output",
        help="where to write the unlocked PDF, or - for stdout "
        "(default: <input>-unlocked.pdf next to the input, or stdout when input is stdin)",
    )
    out.add_argument("--in-place", action="store_true", help="overwrite the input file")

    parser.add_argument("-f", "--force", action="store_true", help="overwrite the output file if it exists")
    parser.add_argument(
        "--dry-run", action="store_true", help="check the password and report, without writing anything"
    )
    parser.add_argument("--json", action="store_true", help="print a single JSON result object")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _strip_newline(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value


def resolve_password(args: argparse.Namespace) -> str:
    if args.password is not None:
        return args.password
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            raise CliError(EXIT_USAGE, "usage", f"environment variable {args.password_env} is not set")
        return value
    if args.password_file:
        try:
            return _strip_newline(Path(args.password_file).read_text(encoding="utf-8"))
        except OSError as exc:
            raise CliError(EXIT_USAGE, "usage", f"cannot read password file: {exc}") from exc
    if args.password_stdin:
        return _strip_newline(sys.stdin.read())
    return ""


def default_output(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.stem}-unlocked{input_path.suffix or '.pdf'}")


def describe_encryption(pdf: pikepdf.Pdf) -> Optional[dict[str, Any]]:
    if not pdf.is_encrypted:
        return None
    enc = pdf.encryption
    return {
        "revision": enc.R,
        "version": enc.V,
        "bits": enc.bits,
        "method": str(enc.stream_method).split(".")[-1],
        "opened_with": "owner_password"
        if pdf.owner_password_matched
        else "user_password"
        if pdf.user_password_matched
        else "unknown",
    }


def open_pdf(source: Any, password: str, in_place: bool) -> pikepdf.Pdf:
    try:
        with warnings.catch_warnings():
            # pikepdf warns when a password is given but not needed; that is fine here.
            warnings.simplefilter("ignore")
            return pikepdf.open(source, password=password, allow_overwriting_input=in_place)
    except pikepdf.PasswordError as exc:
        msg = "incorrect password" if password else "this PDF requires a password"
        raise CliError(EXIT_BAD_PASSWORD, "bad_password", msg) from exc
    except FileNotFoundError as exc:
        raise CliError(EXIT_INPUT_ERROR, "input_not_found", f"input file not found: {source}") from exc
    except OSError as exc:
        raise CliError(EXIT_INPUT_ERROR, "input_unreadable", f"cannot read input: {exc}") from exc
    except pikepdf.PdfError as exc:
        raise CliError(EXIT_INPUT_ERROR, "invalid_pdf", f"not a valid PDF: {exc}") from exc


def save_unlocked(pdf: pikepdf.Pdf, output: Optional[Path], in_place: bool) -> Optional[bytes]:
    """Save without encryption. Returns the bytes when output is None (stdout)."""
    if output is None:
        buf = io.BytesIO()
        pdf.save(buf, encryption=False)
        return buf.getvalue()
    if in_place:
        pdf.save(output, encryption=False)
        return None
    # Write to a temp file then rename, so a failure never leaves a partial PDF.
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pdf-unlock-", suffix=".pdf", dir=output.parent)
    os.close(fd)
    try:
        pdf.save(tmp, encryption=False)
        os.replace(tmp, output)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return None


def verify_unlocked(source: Any) -> None:
    with pikepdf.open(source) as check:
        if check.is_encrypted:
            raise CliError(EXIT_ERROR, "still_encrypted", "output is still encrypted")


def run(args: argparse.Namespace, stdout: BinaryIO) -> dict[str, Any]:
    if args.password_stdin and args.input == "-":
        raise CliError(EXIT_USAGE, "usage", "cannot read both the PDF and the password from stdin")
    if args.in_place and args.input == "-":
        raise CliError(EXIT_USAGE, "usage", "--in-place cannot be used when reading from stdin")

    password = resolve_password(args)

    if args.input == "-":
        source: Any = io.BytesIO(sys.stdin.buffer.read())
        input_label = "-"
    else:
        input_path = Path(args.input)
        if not input_path.is_file():
            raise CliError(EXIT_INPUT_ERROR, "input_not_found", f"input file not found: {input_path}")
        source = input_path
        input_label = str(input_path)

    if args.in_place:
        output: Optional[Path] = Path(args.input)
    elif args.output == "-" or (args.output is None and args.input == "-"):
        output = None
    elif args.output is not None:
        output = Path(args.output)
    else:
        output = default_output(Path(args.input))

    if output is not None and not args.in_place and not args.dry_run:
        if args.input != "-" and output.resolve() == Path(args.input).resolve():
            raise CliError(EXIT_USAGE, "usage", "output is the same as input; use --in-place to overwrite it")
        if output.exists() and not args.force:
            raise CliError(EXIT_OUTPUT_EXISTS, "output_exists", f"output file already exists: {output} (use --force)")

    with open_pdf(source, password, args.in_place) as pdf:
        result: dict[str, Any] = {
            "ok": True,
            "input": input_label,
            "output": None,
            "was_encrypted": pdf.is_encrypted,
            "encryption": describe_encryption(pdf),
            "pages": len(pdf.pages),
            "dry_run": args.dry_run,
        }
        if args.dry_run:
            return result
        data = save_unlocked(pdf, output, args.in_place)

    if data is not None:
        verify_unlocked(io.BytesIO(data))
        stdout.write(data)
        stdout.flush()
        result["output"] = "-"
    else:
        verify_unlocked(output)
        result["output"] = str(output)
    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    stdout_bin = sys.stdout.buffer
    writes_pdf_to_stdout = not args.in_place and (
        args.output == "-" or (args.output is None and args.input == "-")
    )
    # Keep stdout clean for PDF bytes when the PDF goes to stdout.
    report = sys.stderr if writes_pdf_to_stdout else sys.stdout

    try:
        result = run(args, stdout_bin)
        code = EXIT_OK
    except CliError as exc:
        result = {"ok": False, "error": exc.error, "message": exc.message, "exit_code": exc.code}
        code = exc.code
    except Exception as exc:  # noqa: BLE001 - report anything unexpected cleanly
        result = {"ok": False, "error": "unexpected", "message": str(exc), "exit_code": EXIT_ERROR}
        code = EXIT_ERROR

    if args.json:
        print(json.dumps(result), file=report)
    elif not result["ok"]:
        print(f"pdf-unlock: error: {result['message']}", file=sys.stderr)
    elif args.dry_run:
        state = "encrypted, password OK" if result["was_encrypted"] else "not encrypted"
        print(f"{result['input']}: {state}, {result['pages']} pages", file=report)
    elif result["output"] != "-":
        print(result["output"], file=report)
    return code


if __name__ == "__main__":
    sys.exit(main())
