# Copyright 2026 Ivan Rozenblad
# SPDX-License-Identifier: Apache-2.0
"""Battery-wide fixtures: keep the tests hermetic.

The battery's stated contract is that every test is deterministic and offline
(see this package's ``__init__``). The CLI-level tests broke that without
meaning to: ``main(["scan", ...])`` runs the real pipeline, and the real
pipeline enumerates the machine's listening sockets through psutil.

Two problems, one cause:

- **Non-determinism.** The finding set then depends on whatever happens to be
  listening on the machine running the tests. A CI runner with a service bound
  to a routable address contributes ``EXPOSE-BIND`` findings the test never
  planted, which silently changes the counts and grades the end-to-end tests
  assert on. The battery is about what a hostile *repository* does — the host's
  socket table is not part of the fixture.
- **Cost.** ``psutil.net_connections()`` walks the full TCP/UDP table and then
  opens a process handle per connection. That is microseconds on Linux and
  seconds on Windows, where the battery's CLI invocations turned a ~20-second
  job into a multi-minute one.

The rest of the suite already stubs this per test (see ``tests/test_cli.py``);
doing it once for the whole package keeps the battery consistent with that
convention instead of re-deriving it in every module. Socket exposure has its
own dedicated coverage in ``tests/test_sockets.py`` and ``tests/test_engine.py``,
so nothing is lost here.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import mcpscan.engine as engine_mod
from mcpscan.discovery.sockets import EnumerationResult


@pytest.fixture(autouse=True)
def _no_socket_enumeration(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make socket discovery return nothing for every test in the battery.

    Autouse and package-scoped: a new module cannot forget it and reintroduce a
    dependency on the host's network state.
    """
    monkeypatch.setattr(engine_mod, "enumerate_listening", lambda: EnumerationResult(sockets=()))
    yield
