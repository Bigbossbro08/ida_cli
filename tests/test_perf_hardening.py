"""Phase 4 tests: hard deadline guard and inventory TTL cache."""

import time
import unittest

from ida_cli.cache import TTLCache
from ida_cli.deadline import DeadlineExceeded, run_with_deadline


def _noop():
    return 1


class TestDeadline(unittest.TestCase):
    def test_returns_value_before_deadline(self):
        self.assertEqual(run_with_deadline(lambda: 21 * 2, time.monotonic() + 10), 42)

    def test_no_deadline_is_passthrough(self):
        self.assertEqual(run_with_deadline(lambda: "ok", None), "ok")

    def test_raises_when_deadline_already_passed(self):
        with self.assertRaises(DeadlineExceeded):
            run_with_deadline(lambda: 1, time.monotonic() - 1)

    def test_cancel_grace_suppresses_deadline(self):
        # cancel_fired_at set "now" + a passed deadline, but the grace window
        # keeps the hook quiet so the tool can finish formatting a partial result.
        cancel_fired_at = [time.monotonic()]

        def busy():
            total = 0
            for i in range(20000):
                total += _noop()
            return total

        result = run_with_deadline(
            busy, time.monotonic() - 1, cancel_fired_at=cancel_fired_at, cancel_grace=5.0
        )
        self.assertEqual(result, 20000)

    def test_deadline_fires_between_call_events(self):
        def slow():
            total = 0
            for i in range(5_000_000):
                total += _noop()
            return total

        with self.assertRaises(DeadlineExceeded):
            run_with_deadline(slow, time.monotonic() + 0.02)


class TestTTLCache(unittest.TestCase):
    def test_get_or_set_caches(self):
        cache = TTLCache(ttl=10)
        calls = {"n": 0}

        def producer():
            calls["n"] += 1
            return calls["n"]

        self.assertEqual(cache.get_or_set("k", producer), 1)
        self.assertEqual(cache.get_or_set("k", producer), 1)
        self.assertEqual(calls["n"], 1)

    def test_invalidate(self):
        cache = TTLCache(ttl=10)
        self.assertEqual(cache.get_or_set("k", lambda: "v"), "v")
        cache.invalidate("k")
        self.assertEqual(cache.get_or_set("k", lambda: "w"), "w")
        cache.invalidate()
        self.assertEqual(cache.get_or_set("k", lambda: "z"), "z")

    def test_ttl_expiry(self):
        cache = TTLCache(ttl=0.05)
        self.assertEqual(cache.get_or_set("k", lambda: "v"), "v")
        time.sleep(0.08)
        self.assertEqual(cache.get_or_set("k", lambda: "w"), "w")

    def test_stats(self):
        cache = TTLCache(ttl=10)
        cache.get_or_set("k", lambda: "v")
        cache.get_or_set("k", lambda: "v")
        stats = cache.stats()
        self.assertIn("k", stats["keys"])
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)


if __name__ == "__main__":
    unittest.main()
