from datetime import datetime, timedelta

from syslog_postmortem.analyzer import analyze
from syslog_postmortem.collector import RawEntry
from syslog_postmortem.renderer import markdown_to_html, md_text, render_html, render_markdown

T0 = datetime(2026, 5, 10, 14, 0)
PAYLOAD = '<img src=x onerror=alert(1)>'


def result_with(message, service="sshd"):
    raw = [RawEntry(timestamp=T0, service=service, priority=3, message=message, source="auth")]
    return analyze(raw)


def test_md_text_escapes_markdown_and_html():
    assert md_text("a|b *c* <d> `e`") == "a\\|b \\*c\\* \\<d\\> \\`e\\`"
    assert md_text("line1\nline2") == "line1 line2"
    assert md_text("x" * 10, limit=5) == "xxxx…"


def test_html_escapes_log_content():
    """An attacker-chosen SSH username must not become HTML."""
    res = result_with(f"Invalid user {PAYLOAD} from 10.0.0.5")
    md = render_markdown(res, "Test", T0, T0 + timedelta(hours=1))
    page = render_html(md, 'Title <script>alert(2)</script>')
    assert "<img" not in page and "<script>alert" not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "Content-Security-Policy" in page


def test_malicious_service_name_is_escaped():
    res = result_with("error", service="evil`</code><script>x</script>")
    page = render_html(render_markdown(res, "t", T0, T0 + timedelta(hours=1)), "t")
    assert "<script>x" not in page


def test_markdown_structure_and_tables():
    res = result_with("connection refused | pipe in message")
    md = render_markdown(res, "DB outage", T0, T0 + timedelta(hours=2), ["sshd"])
    assert md.startswith("# Postmortem: DB outage")
    assert "| **Duration** | 2h |" in md
    assert "connection refused \\| pipe in message" in md
    html = markdown_to_html(md)
    assert "<table>" in html and "<th>Time</th>" in html
    assert "<td>connection refused | pipe in message</td>" in html
    assert '<li class="task">☐' in html
    assert "<!-- Fill in manually -->" in html


def test_timeline_keeps_most_severe_when_truncated():
    raw = [RawEntry(timestamp=T0 + timedelta(minutes=10 * i), service=f"s{i}", priority=4,
                    message=f"warning {i}", source="journald") for i in range(60)]
    raw.append(RawEntry(timestamp=T0 + timedelta(hours=20), service="db", priority=2,
                        message="PANIC", source="journald"))
    md = render_markdown(analyze(raw), "t", T0, T0 + timedelta(days=1))
    timeline = md.split("## Timeline")[1].split("\n---\n")[0]
    assert "PANIC" in timeline and "Showing the 50 most severe of 61" in timeline
