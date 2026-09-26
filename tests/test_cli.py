from datetime import datetime, timedelta

import pytest

from syslog_postmortem import cli
from syslog_postmortem.collector import CollectionResult, RawEntry

NOW = datetime(2026, 5, 10, 16, 0)


def test_resolve_window():
    assert cli.resolve_window("2026-05-10 14:00", "2026-05-10 15:30:10", None) == \
        (datetime(2026, 5, 10, 14), datetime(2026, 5, 10, 15, 30, 10))
    assert cli.resolve_window(None, None, "2h", now=NOW) == (NOW - timedelta(hours=2), NOW)
    assert cli.resolve_window("2026-05-10 15:00", None, None, now=NOW)[1] == NOW


@pytest.mark.parametrize("since, until, last, msg", [
    ("2026-05-10 16:00", "2026-05-10 15:00", None, "--to must be after --from"),
    ("2026-05-10 14:00", None, "2h", "not both"),
    (None, None, None, "is required"),
    ("10/05/2026", None, None, "invalid date"),
    (None, None, "2 weeks", "invalid duration"),
])
def test_resolve_window_errors(since, until, last, msg):
    with pytest.raises(ValueError, match=msg):
        cli.resolve_window(since, until, last, now=NOW)


def test_report_to_stdout(monkeypatch, capsys):
    raw = [RawEntry(timestamp=NOW - timedelta(minutes=5), service="nginx", priority=3,
                    message="upstream connect error", source="journald")]
    monkeypatch.setattr(cli, "collect_all", lambda *a, **k: CollectionResult(raw, ["just a warning"]))
    cli.main(["--last", "1h", "-o", "-", "--title", "Web down"])
    out, err = capsys.readouterr()
    assert out.startswith("# Postmortem: Web down")
    assert "just a warning" in err and "\033[" not in out


def test_html_file(monkeypatch, tmp_path, capsys):
    raw = [RawEntry(timestamp=NOW, service="db", priority=2, message="PANIC", source="journald")]
    monkeypatch.setattr(cli, "collect_all", lambda *a, **k: CollectionResult(raw, []))
    target = tmp_path / "pm.html"
    cli.main(["--from", "2026-05-10 15:00", "--to", "2026-05-10 17:00", "--format", "html", "-o", str(target)])
    assert target.read_text().startswith("<!DOCTYPE html>")


def test_bad_window_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--from", "yesterday"])
    assert exc.value.code == 2
