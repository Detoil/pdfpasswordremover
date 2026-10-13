# pdf-unlock

A command line tool that removes password protection from PDF files. Give it the
PDF and the password, and it writes an unlocked copy with no password and no
permission restrictions (printing, copying, editing).

It is designed to be called by AI agents and scripts: predictable output,
distinct exit codes, and an optional single-line JSON result.

Built on [pikepdf](https://github.com/pikepdf/pikepdf) (qpdf), so it handles
every standard PDF encryption type: RC4 40/128-bit and AES 128/256-bit.

## Install

Requires Python 3.9 or newer.

```bash
pip install git+https://github.com/detoil/pdfpasswordremover.git
```

Or with `pipx` / `uv` so it is isolated and on your PATH:

```bash
pipx install git+https://github.com/detoil/pdfpasswordremover.git
```

```bash
uv tool install git+https://github.com/detoil/pdfpasswordremover.git
```

From a local clone:

```bash
pip install .
```

This installs the `pdf-unlock` command. You can also run it as
`python -m pdf_unlock`.

## Usage

```bash
pdf-unlock statement.pdf -p 'Hunter2!'
```

Writes `statement-unlocked.pdf` next to the input and prints its path.

```
pdf-unlock INPUT [password option] [-o OUTPUT | --in-place] [-f] [--dry-run] [--json]
```

| Option | Meaning |
| --- | --- |
| `INPUT` | The protected PDF. Use `-` to read it from stdin. |
| `-p, --password VALUE` | The password (user or owner password both work). |
| `--password-env NAME` | Read the password from environment variable `NAME`. |
| `--password-file PATH` | Read the password from a file. One trailing newline is stripped. |
| `--password-stdin` | Read the password from stdin. One trailing newline is stripped. |
| `-o, --output PATH` | Where to write the result. `-` writes the PDF to stdout. Default: `<input>-unlocked.pdf`. |
| `--in-place` | Overwrite the input file with the unlocked version. |
| `-f, --force` | Overwrite the output file if it already exists. |
| `--dry-run` | Check the password and report, without writing anything. |
| `--json` | Print one JSON object describing the result. |

If no password option is given, an empty password is used. That is enough for
PDFs that open without a password but block printing or copying.

### Examples

```bash
# Choose the output path
pdf-unlock statement.pdf -p 'Hunter2!' -o unlocked/statement.pdf

# Keep the password out of shell history and process listings
PDF_PASSWORD='Hunter2!' pdf-unlock statement.pdf --password-env PDF_PASSWORD

# Replace the original file
pdf-unlock statement.pdf -p 'Hunter2!' --in-place

# Check a password without writing a file
pdf-unlock statement.pdf -p 'Hunter2!' --dry-run --json

# Pipe: PDF in on stdin, unlocked PDF out on stdout
cat statement.pdf | pdf-unlock - -p 'Hunter2!' > unlocked.pdf
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Unexpected error |
| 2 | Invalid arguments (for example `--password-env` names an unset variable) |
| 3 | Wrong password, or the PDF needs a password and none was given |
| 4 | Input file missing, unreadable, or not a valid PDF |
| 5 | Output file already exists (pass `--force` to overwrite) |

## JSON output

With `--json` the tool prints exactly one JSON object on stdout (on stderr
instead when the PDF itself is going to stdout).

Success:

```json
{"ok": true, "input": "bank.pdf", "output": "bank-unlocked.pdf", "was_encrypted": true, "encryption": {"revision": 6, "version": 5, "bits": 256, "method": "aesv3", "opened_with": "user_password"}, "pages": 2, "dry_run": false}
```

Failure:

```json
{"ok": false, "error": "bad_password", "message": "incorrect password", "exit_code": 3}
```

`error` is one of `bad_password`, `input_not_found`, `input_unreadable`,
`invalid_pdf`, `output_exists`, `usage`, `still_encrypted`, `unexpected`.

A PDF that was never encrypted is still copied to the output and reported with
`"was_encrypted": false`, so the caller always gets a usable file on success.

## Using it from an agent

Paste this into your agent's tool instructions:

> **pdf-unlock**: removes the password from a PDF.
> Run `pdf-unlock <input.pdf> -p <password> -o <output.pdf> --json`.
> It prints one JSON line. If `ok` is true, the unlocked file is at `output`.
> If `ok` is false, read `error`: `bad_password` means the password is wrong
> (ask the user for the correct one, do not guess), `input_not_found` or
> `invalid_pdf` means the input path is wrong or the file is not a PDF,
> `output_exists` means pick another output path or add `--force`.
> Use `--dry-run` to test a password without writing a file.
> Prefer `--password-env NAME` over `-p` when the password is already in an
> environment variable.

Every run verifies the written file opens without a password before reporting
success.

## Development

```bash
pip install -e '.[test]'
pytest
```

## Note

Only use this on documents you own or are authorised to access.
