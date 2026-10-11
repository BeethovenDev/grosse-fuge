"""Tests for the GROSSE FUGUE CLI (in-process, no network)."""

from __future__ import annotations

import json

import pytest

from grosse_fuge import cli


def test_redact_in_place(tmp_path: pytest.TempPathFactory) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("Call me at +1 555 123 4567 after 6.", encoding="utf-8")
    assert cli.main(["redact", str(target), "--in-place"]) == 0
    out = target.read_text(encoding="utf-8")
    assert "[R:phone]" in out
    assert "555" not in out


def test_redact_to_stdout(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    target = tmp_path / "mail.txt"
    target.write_text("write to a@b.org soon", encoding="utf-8")
    assert cli.main(["redact", str(target), "--out", "-"]) == 0
    assert capsys.readouterr().out == "write to [R:email] soon"


def test_redact_json_report(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    target = tmp_path / "data.csv"
    target.write_text("id,email\n1,a@b.org\n2,c@d.org\n", encoding="utf-8")
    out_path = tmp_path / "out.csv"
    assert cli.main(["redact", str(target), "--out", str(out_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["matched"] == 2
    assert report["by_type"] == {"email": 2}
    rows = out_path.read_text(encoding="utf-8").strip().splitlines()
    assert all(row.count(",") == 1 for row in rows)


def test_redact_pseudonym_mode(tmp_path: pytest.TempPathFactory) -> None:
    target = tmp_path / "ids.txt"
    target.write_text("key a@b.org and again a@b.org", encoding="utf-8")
    out_path = tmp_path / "out.txt"
    cli.main(["redact", str(target), "--out", str(out_path), "--mode", "pseudonym", "--salt", "s"])
    text = out_path.read_text(encoding="utf-8")
    tokens = [word for word in text.split() if "-" in word and word[0].isalpha()]
    assert len(set(tokens)) == 1  # deterministic mapping


def test_redact_names_file(tmp_path: pytest.TempPathFactory) -> None:
    target = tmp_path / "story.txt"
    names = tmp_path / "names.txt"
    target.write_text("Anna kissed the countess goodbye.", encoding="utf-8")
    names.write_text("Anna\n# comment\n", encoding="utf-8")
    out_path = tmp_path / "out.txt"
    cli.main(["redact", str(target), "--out", str(out_path), "--names", str(names)])
    assert out_path.read_text(encoding="utf-8") == "[R:named] kissed the countess goodbye."


def test_check_exit_one_when_pii_present(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    target = tmp_path / "x.txt"
    target.write_text("mail a@b.org now", encoding="utf-8")
    assert cli.main(["check", str(target)]) == 1
    assert "email" in capsys.readouterr().out


def test_check_zero_when_clean(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    target = tmp_path / "x.txt"
    target.write_text("nothing to see here.", encoding="utf-8")
    assert cli.main(["check", str(target)]) == 0
    assert "no PII fragments" in capsys.readouterr().out


def test_check_json_report_is_pure_json(
    capsys: pytest.CaptureFixture[str], tmp_path: pytest.TempPathFactory
) -> None:
    target = tmp_path / "x.csv"
    target.write_text("id,tag\n1,u1\n2,u2\n", encoding="utf-8")
    cli.main(["check", str(target), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == "csv"
    assert report["matched"] == 0


def test_unknown_type_rejected(tmp_path: pytest.TempPathFactory) -> None:
    target = tmp_path / "x.txt"
    target.write_text("hi", encoding="utf-8")
    with pytest.raises(SystemExit):
        cli.main(["check", str(target), "--types", "socks"])
