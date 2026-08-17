# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""OS-native scheduler-unit generation (Wave 2 Feature F): ``mcpscan schedule``.

Continuous cadence without a resident process. Instead of running a daemon, this
module renders the text of an OS-native scheduler unit — a launchd plist, a
systemd timer+service pair, or a Windows Task Scheduler XML — that the operator
installs so the host's own scheduler runs ``mcpscan scan`` + ``mcpscan diff``
against a baseline on a cadence. The tool never becomes a background service.

Determinism: every generator here is a **pure** function of its
:class:`SchedulePlan` — no clock, no filesystem, no network. The one timestamp a
Windows trigger needs (``StartBoundary``) is a fixed anchor constant, not a
"now" read, so identical plans always render identical bytes. Resolving the
mcpscan invocation (a ``shutil.which`` filesystem touch) happens in ``cli`` and
is passed in; nothing here reads the environment.

Gating: this module only *renders* text. It writes no file and executes no
installer — the CLI writes the unit only under an explicit ``--out`` and always
prints (never runs) the ``launchctl`` / ``systemctl`` / ``schtasks`` command,
because installing a scheduler is the user's action. No egress at any point.
"""

from __future__ import annotations

import plistlib
import shlex
import xml.etree.ElementTree as ET  # nosec B405 (generate-only; parses no untrusted XML)
from dataclasses import dataclass
from enum import Enum

# launchd label / systemd + Windows unit identity. Stable so re-running schedule
# targets the same unit rather than piling up duplicates.
DEFAULT_LABEL = "com.mcpscan.scan"
SERVICE_STEM = "mcpscan"

# A fixed anchor for the Windows trigger's StartBoundary. Windows Task Scheduler
# only uses this as the repetition origin; a constant in the past keeps the
# generator clock-free (determinism guardrail) while remaining valid.
_WINDOWS_START_BOUNDARY = "2026-01-01T03:00:00"


class ScheduleError(ValueError):
    """A plan that cannot be rendered into a valid unit for this OS."""


class Cadence(Enum):
    """How often the scheduled scan+diff runs."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


@dataclass(frozen=True)
class SchedulePlan:
    """The resolved inputs a scheduler unit is rendered from (pure, frozen).

    ``invocation`` is the resolved mcpscan program argv (e.g. ``("mcpscan",)`` or
    ``(sys.executable, "-m", "mcpscan")``) — resolved in ``cli`` so this module
    performs no filesystem lookup. ``roots`` are the project roots to scan (each
    is passed as a ``--root`` to both sub-commands); ``baseline`` is the snapshot
    path the ``diff`` sub-command compares against. ``pythonpath`` is the mcpscan
    package parent to bake into the command as ``PYTHONPATH`` — set by ``cli``
    only for source-tree runs, where the scheduler's bare environment (no
    ``PYTHONPATH``, different cwd) would otherwise fail the ``python -m mcpscan``
    fallback with ``ModuleNotFoundError``; ``None`` for an installed mcpscan a
    bare interpreter finds on its own.
    """

    invocation: tuple[str, ...]
    roots: tuple[str, ...]
    baseline: str
    cadence: Cadence
    pythonpath: str | None = None


# --- embedded command builders (pure) ---
def _posix_command(plan: SchedulePlan) -> str:
    """The POSIX shell one-liner: ``mcpscan scan … ; mcpscan diff …``.

    Runs a fresh posture scan (for the log), then **always** diffs against the
    baseline and fails the run on any regression (the Wave 1 baseline/diff flow)
    so a scheduler watching exit codes surfaces drift. The two are separated by
    ``;`` — not ``&&`` — because ``scan`` exits non-zero on any standing finding
    (``--fail-on high`` by default), which would otherwise short-circuit and skip
    the drift check on every machine that is not already clean. With ``;`` the
    overall exit code is the ``diff``'s, i.e. the drift signal. Every token is
    ``shlex.quote``-escaped so paths with spaces survive the shell.
    """
    prefix = " ".join(shlex.quote(tok) for tok in plan.invocation)
    if plan.pythonpath is not None:
        # A leading VAR=value assignment scopes to a single command and only
        # parses as an assignment while the name sits outside any quotes — so
        # quote just the value, and put it on the prefix both halves share.
        prefix = f"PYTHONPATH={shlex.quote(plan.pythonpath)} {prefix}"
    roots = "".join(f" --root {shlex.quote(root)}" for root in plan.roots)
    scan = f"{prefix} scan{roots}"
    diff = f"{prefix} diff --baseline {shlex.quote(plan.baseline)}{roots} --fail-on-regression"
    return f"{scan} ; {diff}"


def _windows_command(plan: SchedulePlan) -> str:
    """The ``cmd.exe`` command line running scan then diff (``&`` chained).

    Windows quoting differs from POSIX: tokens carrying a space or a quote are
    wrapped in double quotes with embedded quotes doubled, which is what
    ``cmd.exe`` expects (``shlex.quote`` would emit POSIX single-quotes cmd does
    not understand). The two commands are joined with ``&`` (run unconditionally)
    rather than ``&&`` (run second only on success) for the same reason as the
    POSIX form: ``scan`` exits non-zero on any standing finding, so ``&&`` would
    skip the drift ``diff`` on every non-clean machine.
    """

    def q(tok: str) -> str:
        if tok and not any(c in tok for c in ' \t"'):
            return tok
        return '"' + tok.replace('"', '""') + '"'

    prefix = " ".join(q(tok) for tok in plan.invocation)
    roots = "".join(f" --root {q(root)}" for root in plan.roots)
    scan = f"{prefix} scan{roots}"
    diff = f"{prefix} diff --baseline {q(plan.baseline)}{roots} --fail-on-regression"
    command = f"{scan} & {diff}"
    if plan.pythonpath is not None:
        # cmd's `set` includes everything up to the separator in the value —
        # even a trailing space — so always use the quoted `set "VAR=value"`
        # form. One assignment persists across the whole `&` chain.
        command = f'set "PYTHONPATH={plan.pythonpath}" & {command}'
    return command


# --- launchd (macOS / Darwin) ---
_LAUNCHD_CALENDAR: dict[Cadence, dict[str, int]] = {
    Cadence.HOURLY: {"Minute": 0},
    Cadence.DAILY: {"Hour": 3, "Minute": 0},
    Cadence.WEEKLY: {"Weekday": 0, "Hour": 3, "Minute": 0},
}


def launchd_plist(plan: SchedulePlan, *, label: str = DEFAULT_LABEL) -> str:
    """Render a launchd LaunchAgent plist for the plan (pure).

    Uses ``StartCalendarInterval`` for the cadence (every hour at :00, daily at
    03:00, or weekly on Sunday 03:00). ``RunAtLoad`` is False so loading the
    agent does not immediately fire a scan. Serialized with :mod:`plistlib`, so
    the output is always a valid, well-formed plist.
    """
    document: dict[str, object] = {
        "Label": label,
        "ProgramArguments": ["/bin/sh", "-c", _posix_command(plan)],
        "StartCalendarInterval": _LAUNCHD_CALENDAR[plan.cadence],
        "RunAtLoad": False,
    }
    return plistlib.dumps(document, sort_keys=False).decode("utf-8")


# --- systemd (Linux) ---
_SYSTEMD_ONCALENDAR: dict[Cadence, str] = {
    Cadence.HOURLY: "hourly",
    Cadence.DAILY: "daily",
    Cadence.WEEKLY: "weekly",
}


def systemd_units(plan: SchedulePlan) -> tuple[str, str]:
    """Render the systemd ``(timer, service)`` unit pair for the plan (pure).

    The service is a ``oneshot`` that runs the scan+diff command; the timer fires
    it on the cadence via ``OnCalendar`` (systemd's built-in ``hourly`` /
    ``daily`` / ``weekly`` shortcuts) and is ``Persistent`` so a run missed while
    the machine was off is caught up on next boot.

    Security consideration: systemd applies its own expansions to ``ExecStart``
    regardless of shell-style quoting — ``%``-specifiers (systemd.unit(5)) and
    ``$``-variable substitution (systemd.service(5)) — so every literal ``%`` and
    ``$`` in the command — a root, the baseline, or the baked ``PYTHONPATH`` — is
    written as ``%%`` / ``$$``; otherwise a valid specifier silently rewrites the
    path and an invalid one drops the ``ExecStart`` line entirely.

    A unit file is line-structured, so a path carrying a **newline** cannot be
    represented at all: ``shlex.quote`` keeps it inside single quotes for a
    shell, but systemd's parser ends the ``ExecStart`` directive at the newline
    and reads the remainder as further directives — an attacker-chosen
    ``ExecStartPost=`` would be honored. Such a plan is refused with
    :class:`ScheduleError` rather than rendered; those paths need the
    launchd/Windows channels or an installed mcpscan.

    Raises:
        ScheduleError: If the rendered command carries a newline or other control
            character that a unit-file line cannot hold.
    """
    command = _posix_command(plan)
    control = next((ch for ch in command if ch < " " or ch == "\x7f"), None)
    if control is not None:
        raise ScheduleError(
            f"cannot render a systemd unit: a path contains the control character "
            f"U+{ord(control):04X}, which would terminate the ExecStart line and let "
            "the rest be read as unit directives"
        )
    execstart = shlex.quote(command).replace("%", "%%").replace("$", "$$")
    service = (
        "[Unit]\n"
        "Description=IANUA-Broker posture scan + drift check\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart=/bin/sh -c {execstart}\n"
    )
    timer = (
        "[Unit]\n"
        f"Description=Run IANUA-Broker on a {plan.cadence.value} cadence\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={_SYSTEMD_ONCALENDAR[plan.cadence]}\n"
        "Persistent=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return timer, service


# --- Windows Task Scheduler ---
_TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def _windows_trigger(parent: ET.Element, cadence: Cadence) -> None:
    """Attach the cadence trigger to a ``<Triggers>`` element."""
    if cadence is Cadence.HOURLY:
        trigger = ET.SubElement(parent, "TimeTrigger")
        ET.SubElement(trigger, "StartBoundary").text = _WINDOWS_START_BOUNDARY
        ET.SubElement(trigger, "Enabled").text = "true"
        ET.SubElement(ET.SubElement(trigger, "Repetition"), "Interval").text = "PT1H"
        return
    trigger = ET.SubElement(parent, "CalendarTrigger")
    ET.SubElement(trigger, "StartBoundary").text = _WINDOWS_START_BOUNDARY
    ET.SubElement(trigger, "Enabled").text = "true"
    if cadence is Cadence.DAILY:
        by_day = ET.SubElement(trigger, "ScheduleByDay")
        ET.SubElement(by_day, "DaysInterval").text = "1"
    else:  # WEEKLY
        by_week = ET.SubElement(trigger, "ScheduleByWeek")
        days = ET.SubElement(by_week, "DaysOfWeek")
        ET.SubElement(days, "Sunday")
        ET.SubElement(by_week, "WeeksInterval").text = "1"


def windows_task_xml(plan: SchedulePlan) -> str:
    """Render a Windows Task Scheduler task definition for the plan (pure).

    A ``cmd.exe /c`` action runs the scan+diff command on the cadence trigger.
    Built with :mod:`xml.etree.ElementTree` so the output is always well-formed
    and correctly escaped; the default namespace is the Task Scheduler schema.
    """
    root = ET.Element("Task", {"version": "1.2", "xmlns": _TASK_NS})

    reg = ET.SubElement(root, "RegistrationInfo")
    ET.SubElement(reg, "Description").text = "IANUA-Broker scheduled posture scan + diff"

    triggers = ET.SubElement(root, "Triggers")
    _windows_trigger(triggers, plan.cadence)

    principals = ET.SubElement(root, "Principals")
    principal = ET.SubElement(principals, "Principal", {"id": "Author"})
    ET.SubElement(principal, "LogonType").text = "InteractiveToken"

    settings = ET.SubElement(root, "Settings")
    ET.SubElement(settings, "MultipleInstancesPolicy").text = "IgnoreNew"
    ET.SubElement(settings, "StartWhenAvailable").text = "true"
    ET.SubElement(settings, "Enabled").text = "true"

    actions = ET.SubElement(root, "Actions", {"Context": "Author"})
    exec_el = ET.SubElement(actions, "Exec")
    ET.SubElement(exec_el, "Command").text = "cmd.exe"
    ET.SubElement(exec_el, "Arguments").text = f'/c "{_windows_command(plan)}"'

    ET.indent(root)
    body = ET.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n'
