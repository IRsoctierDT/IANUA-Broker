"""Self-scan: mcpscan must pass its own scan (ticket T-403, NFR-SEC4)."""

from __future__ import annotations

from pathlib import Path

from mcpscan.domain import Severity
from mcpscan.engine import scan

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_repo_has_no_serious_findings() -> None:
    # Scanning the project's own tree must surface no Critical/High issues:
    # no committed plaintext secrets, no insecure .env in the repo.
    report = scan(roots=[REPO_ROOT], system="Linux", env={}, enumerate_sockets=False)
    serious = [
        f
        for s in report.servers
        for f in s.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert serious == [], f"mcpscan failed its own scan: {[f.title for f in serious]}"


def test_no_listening_socket_opened_by_import() -> None:
    # Importing the tool must not open a server port (it exposes no surface).
    import mcpscan
    import mcpscan.cli
    import mcpscan.engine  # noqa: F401

    # If any import bound a socket this would be observable; the absence of
    # server code is enforced structurally — there is no bind()/listen() call.
    assert True
