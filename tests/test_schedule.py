"""Scheduler-unit tests (Wave 2 Feature F).

The three generators are pure functions of a :class:`SchedulePlan`: no clock, no
filesystem, no network, and byte-identical for identical inputs. The CLI wrapper
prints the unit + install guidance by default (writing nothing), writes the unit
only under ``--out`` and always *prints* — never runs — the install command, and
degrades with a clear message on an unsupported OS.
"""

from __future__ import annotations

import platform
import plistlib
import shlex
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from mcpscan.cli import main
from mcpscan.schedule import (
    Cadence,
    SchedulePlan,
    launchd_plist,
    systemd_units,
    windows_task_xml,
)

MCPSCAN = "/usr/local/bin/mcpscan"
_TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _plan(
    cadence: Cadence = Cadence.DAILY, *, root: str = "/proj", pythonpath: str | None = None
) -> SchedulePlan:
    return SchedulePlan(
        invocation=(MCPSCAN,),
        roots=(root,),
        baseline=f"{root}/.mcpscan-baseline.json",
        cadence=cadence,
        pythonpath=pythonpath,
    )


def test_scan_and_diff_are_not_short_circuited() -> None:
    # scan exits non-zero on any standing finding (default --fail-on high), so the
    # scheduled command must run diff UNCONDITIONALLY (POSIX ';' / cmd '&'), never
    # '&&' — otherwise the drift check silently never runs on a non-clean machine.
    posix = launchd_plist(_plan())
    assert " ; " in posix and "&&" not in posix
    win = windows_task_xml(_plan())
    assert "&&" not in win  # cmd.exe joins with '&', not '&&'


# --- launchd (Darwin) ---
def test_launchd_plist_is_valid_and_carries_invocation() -> None:
    text = launchd_plist(_plan(Cadence.DAILY))
    doc = plistlib.loads(text.encode("utf-8"))  # parses => well-formed plist
    assert doc["Label"] == "com.mcpscan.scan"
    assert doc["RunAtLoad"] is False
    args = doc["ProgramArguments"]
    assert args[:2] == ["/bin/sh", "-c"]
    # The resolved mcpscan path is embedded, and the command runs scan then diff.
    assert MCPSCAN in args[2]
    assert "scan" in args[2] and "diff --baseline" in args[2]


def test_launchd_calendar_interval_tracks_cadence() -> None:
    daily = plistlib.loads(launchd_plist(_plan(Cadence.DAILY)).encode("utf-8"))
    assert daily["StartCalendarInterval"] == {"Hour": 3, "Minute": 0}
    hourly = plistlib.loads(launchd_plist(_plan(Cadence.HOURLY)).encode("utf-8"))
    assert hourly["StartCalendarInterval"] == {"Minute": 0}  # every hour at :00
    weekly = plistlib.loads(launchd_plist(_plan(Cadence.WEEKLY)).encode("utf-8"))
    assert weekly["StartCalendarInterval"]["Weekday"] == 0


def test_launchd_quotes_paths_with_spaces() -> None:
    text = launchd_plist(_plan(root="/proj dir"))
    doc = plistlib.loads(text.encode("utf-8"))
    assert "'/proj dir'" in doc["ProgramArguments"][2]  # shlex-quoted, shell-safe


# --- systemd (Linux) ---
def test_systemd_timer_oncalendar_matches_each_cadence() -> None:
    for cadence, keyword in (
        (Cadence.HOURLY, "hourly"),
        (Cadence.DAILY, "daily"),
        (Cadence.WEEKLY, "weekly"),
    ):
        timer, _service = systemd_units(_plan(cadence))
        assert f"OnCalendar={keyword}" in timer
        assert "Persistent=true" in timer
        assert "WantedBy=timers.target" in timer


def test_systemd_service_runs_scan_then_diff() -> None:
    _timer, service = systemd_units(_plan())
    assert "Type=oneshot" in service
    assert "ExecStart=/bin/sh -c " in service
    assert MCPSCAN in service
    assert "scan" in service and "diff --baseline" in service and "--fail-on-regression" in service


# --- Windows Task Scheduler ---
def test_windows_task_xml_is_wellformed_and_namespaced() -> None:
    xml = windows_task_xml(_plan(Cadence.DAILY))
    root = ET.fromstring(xml)  # parses => well-formed
    assert root.tag == f"{{{_TASK_NS}}}Task"
    assert root.attrib["version"] == "1.2"
    command = root.find(f".//{{{_TASK_NS}}}Command")
    arguments = root.find(f".//{{{_TASK_NS}}}Arguments")
    assert command is not None and command.text == "cmd.exe"
    assert arguments is not None and arguments.text is not None
    assert "scan" in arguments.text and "diff --baseline" in arguments.text


def test_windows_trigger_tracks_cadence() -> None:
    daily = ET.fromstring(windows_task_xml(_plan(Cadence.DAILY)))
    assert daily.find(f".//{{{_TASK_NS}}}ScheduleByDay") is not None
    weekly = ET.fromstring(windows_task_xml(_plan(Cadence.WEEKLY)))
    assert weekly.find(f".//{{{_TASK_NS}}}ScheduleByWeek") is not None
    assert weekly.find(f".//{{{_TASK_NS}}}Sunday") is not None
    hourly = ET.fromstring(windows_task_xml(_plan(Cadence.HOURLY)))
    interval = hourly.find(f".//{{{_TASK_NS}}}Repetition/{{{_TASK_NS}}}Interval")
    assert interval is not None and interval.text == "PT1H"


def test_windows_quotes_paths_with_spaces() -> None:
    xml = windows_task_xml(_plan(root="C:/proj dir"))
    arguments = ET.fromstring(xml).find(f".//{{{_TASK_NS}}}Arguments")
    assert arguments is not None and arguments.text is not None
    assert '"C:/proj dir"' in arguments.text  # cmd-style double-quoting, not POSIX


# --- source-tree runs (pythonpath baked into the command) ---
def test_posix_pythonpath_prefixes_scan_and_diff() -> None:
    # A POSIX `VAR=value cmd` assignment scopes to that one command, so both
    # halves of `scan ; diff` must carry it; the name must sit outside the
    # quotes to parse as an assignment, so only the value is shlex-quoted.
    plist = launchd_plist(_plan(pythonpath="/src tree"))
    command = plistlib.loads(plist.encode("utf-8"))["ProgramArguments"][2]
    assert command.count("PYTHONPATH='/src tree' ") == 2
    # systemd re-quotes the whole command for its own ExecStart line, so unwrap
    # it back to the /bin/sh -c payload before counting.
    _timer, service = systemd_units(_plan(pythonpath="/src tree"))
    execstart = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    payload = shlex.split(execstart.removeprefix("ExecStart="))[2]
    assert payload.count("PYTHONPATH='/src tree' ") == 2


def test_windows_pythonpath_uses_quoted_set_prefix() -> None:
    # One `set "VAR=value"` persists across the whole `&` chain; the quoted
    # form keeps the space before `&` out of the value.
    xml = windows_task_xml(_plan(pythonpath="C:/src tree"))
    arguments = ET.fromstring(xml).find(f".//{{{_TASK_NS}}}Arguments")
    assert arguments is not None and arguments.text is not None
    assert arguments.text.startswith('/c "set "PYTHONPATH=C:/src tree" & ')
    assert arguments.text.count("PYTHONPATH") == 1


def test_no_pythonpath_keeps_commands_clean() -> None:
    assert "PYTHONPATH" not in launchd_plist(_plan())
    assert "PYTHONPATH" not in "".join(systemd_units(_plan()))
    assert "PYTHONPATH" not in windows_task_xml(_plan())


def test_systemd_escapes_specifier_and_variable_expansion() -> None:
    # systemd applies %-specifier (systemd.unit(5)) and $-variable
    # (systemd.service(5)) expansion to ExecStart even within shell quotes: a
    # valid %h silently rewrites the path, an invalid %2 drops the ExecStart
    # line, and ${VAR} substitutes at execution. Every literal % and $ must
    # therefore be doubled — in roots, baseline, and PYTHONPATH.
    # A space forces shlex quoting; % and $ ride inside the quotes — the exact
    # combination systemd's quote-insensitive expansion would corrupt.
    root, src = "/srv/my %20 $repo", "/srv/my %20 $repo/src"
    _timer, service = systemd_units(_plan(root=root, pythonpath=src))
    execstart = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    assert "%" not in execstart.replace("%%", "")  # every % is escaped as %%
    assert "$" not in execstart.replace("$$", "")  # every $ is escaped as $$
    # After systemd's own %%->% and $$->$ unescapes, the /bin/sh payload is
    # byte-identical to the intended command: both halves carry PYTHONPATH,
    # roots intact.
    unescaped = execstart.removeprefix("ExecStart=").replace("%%", "%").replace("$$", "$")
    payload = shlex.split(unescaped)[2]
    assert payload.count(f"PYTHONPATH='{src}' ") == 2
    assert f"--root '{root}'" in payload
    # launchd needs no such escaping: the command rides in ProgramArguments
    # verbatim (plistlib), and launchd performs no specifier expansion.
    plist = launchd_plist(_plan(root=root, pythonpath=src))
    command = plistlib.loads(plist.encode("utf-8"))["ProgramArguments"][2]
    assert "%%" not in command and root in command


# --- determinism (pure: no clock, no I/O) ---
def test_generators_are_deterministic() -> None:
    assert launchd_plist(_plan()) == launchd_plist(_plan())
    assert systemd_units(_plan()) == systemd_units(_plan())
    assert windows_task_xml(_plan()) == windows_task_xml(_plan())


# --- CLI wiring ---
def test_schedule_requires_cadence(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schedule"]) == 2
    assert "requires --cadence" in capsys.readouterr().err


def test_schedule_default_prints_plist_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    rc = main(["schedule", "--cadence", "daily", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "<key>Label</key>" in out  # unit text on stdout
    assert "launchctl load" in out  # install guidance on stdout too
    # Default mode is read-only: nothing was written under the scanned root.
    assert list(tmp_path.iterdir()) == []


def test_schedule_out_writes_launchd_and_prints_install(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    out = tmp_path / "agent.plist"
    rc = main(["schedule", "--cadence", "weekly", "--root", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    plistlib.loads(out.read_bytes())  # a valid plist landed on disk
    err = capsys.readouterr().err
    assert f"launchctl load {out}" in err  # the matching install command, printed not run


def test_schedule_out_file_is_owner_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    if __import__("os").name == "nt":  # pragma: no cover - POSIX perms only
        pytest.skip("POSIX permissions only")
    import stat

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    out = tmp_path / "agent.plist"
    main(["schedule", "--cadence", "daily", "--out", str(out)])
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_schedule_linux_writes_timer_and_service(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    out = tmp_path / "mcpscan.timer"
    rc = main(["schedule", "--cadence", "hourly", "--root", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.exists() and (tmp_path / "mcpscan.service").exists()
    assert "OnCalendar=hourly" in out.read_text(encoding="utf-8")
    err = capsys.readouterr().err
    assert "systemctl --user enable --now mcpscan.timer" in err


def test_schedule_linux_default_prints_both_units(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    rc = main(["schedule", "--cadence", "daily", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mcpscan.timer" in out and "mcpscan.service" in out
    assert "OnCalendar=daily" in out
    assert list(tmp_path.iterdir()) == []  # still writes nothing


def test_schedule_windows_writes_task_and_prints_schtasks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    out = tmp_path / "task.xml"
    rc = main(["schedule", "--cadence", "daily", "--root", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.exists()
    ET.fromstring(out.read_text(encoding="utf-8"))  # well-formed on disk
    assert 'schtasks /create /tn "mcpscan" /xml' in capsys.readouterr().err


def test_schedule_unsupported_os_degrades_clearly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Plan9")
    rc = main(["schedule", "--cadence", "daily", "--root", str(tmp_path)])
    assert rc == 2
    assert "does not support this platform" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_schedule_discloses_baseline_creation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    main(["schedule", "--cadence", "daily", "--root", str(tmp_path)])
    err = capsys.readouterr().err
    assert "mcpscan baseline --out" in err  # tells the user to create the baseline first


def test_schedule_source_tree_run_bakes_pythonpath(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # Regression: a PYTHONPATH=src source-tree run used to emit units running a
    # bare `python -m mcpscan`, and every scheduled run died with
    # ModuleNotFoundError in the scheduler's empty environment.
    import mcpscan

    parent = str(Path(mcpscan.__file__).resolve().parent.parent)
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(shutil, "which", lambda _cmd: None)  # no installed mcpscan
    monkeypatch.setenv("PYTHONPATH", parent)
    out = tmp_path / "agent.plist"
    rc = main(["schedule", "--cadence", "daily", "--root", str(tmp_path), "--out", str(out)])
    assert rc == 0
    command = plistlib.loads(out.read_bytes())["ProgramArguments"][2]
    fallback = " ".join(shlex.quote(tok) for tok in (sys.executable, "-m", "mcpscan"))
    assert command.count(f"PYTHONPATH={shlex.quote(parent)} {fallback}") == 2  # scan AND diff
    err = capsys.readouterr().err
    assert f"PYTHONPATH={parent}" in err  # the baked path is disclosed loudly
    assert "install" in err.lower()  # with guidance toward an install-independent unit
