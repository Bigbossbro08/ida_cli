"""Hard wall-clock deadline for IDA main-thread tool bodies.

``ida_kernwin.set_cancelled()`` only frees IDA SDK calls that poll for
cancellation; a pure-Python handler that overruns still blocks the main thread.
Installing a ``sys.setprofile`` hook that raises once the deadline passes gives
a best-effort hard stop for Python code that triggers call events (i.e. most
real handlers, which call into IDA APIs or other functions).

Best-effort note: a tight arithmetic loop that never makes a call may not be
interrupted until the next call event. The watchdog's ``set_cancelled`` remains
the primary mechanism for C-level work.
"""

import sys
import time
from typing import Callable, List, Optional


class DeadlineExceeded(Exception):
    """Raised inside a timed tool when its deadline passes."""


def run_with_deadline(
    func: Callable,
    deadline: Optional[float],
    cancel_fired_at: Optional[List[Optional[float]]] = None,
    cancel_grace: float = 5.0,
):
    """Call ``func()`` with a profiling hook that raises past ``deadline``.

    ``cancel_fired_at`` is an optional one-element list set by the watchdog when
    it fires ``set_cancelled``; while within ``cancel_grace`` seconds of that,
    the hook stays quiet so the tool can finish formatting a partial result.
    """
    if deadline is None:
        return func()

    def _profilefunc(frame, event, arg):
        now = time.monotonic()
        if cancel_fired_at is not None:
            fired = cancel_fired_at[0]
            if fired is not None and now < fired + cancel_grace:
                return
        if now >= deadline:
            raise DeadlineExceeded(
                f"tool exceeded its deadline ({now - deadline:.3f}s over)"
            )

    previous = sys.getprofile()
    sys.setprofile(_profilefunc)
    try:
        return func()
    finally:
        sys.setprofile(previous)
