from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from softpal_roundtrip.gui.actions import GuiActionsMixin


class QueuedRoot:
    def __init__(self):
        self.callbacks = []

    def after(self, delay, callback):
        self.callbacks.append(callback)

    def drain(self):
        while self.callbacks:
            self.callbacks.pop(0)()


class GuiHarness(GuiActionsMixin):
    def __init__(self):
        self.root = QueuedRoot()
        self._busy = False
        self.messages = []
        self.errors = []
        self.status = "就绪"

    def _set_busy(self, busy, status):
        self._busy = busy
        self.status = status

    def _append_log(self, message):
        self.messages.append(message)

    def _show_error(self, title, text):
        self.errors.append((title, text))


class ImmediateThread:
    def __init__(self, *, target, daemon):
        self.target = target

    def start(self):
        self.target()


class GuiLoggingTests(unittest.TestCase):
    def test_delayed_error_callbacks_keep_exception_and_failure_status(self):
        gui = GuiHarness()

        def fail():
            raise ValueError("idx=2 译文校验失败")

        with patch("threading.Thread", ImmediateThread):
            gui._run_background("回封", fail)
        # Execute after the worker's exception scope has already been cleared.
        gui.root.drain()
        self.assertFalse(gui._busy)
        self.assertEqual(gui.status, "回封 失败")
        self.assertTrue(any("ValueError: idx=2 译文校验失败" in message for message in gui.messages))
        self.assertEqual(len(gui.errors), 1)
        self.assertIn("idx=2 译文校验失败", gui.errors[0][1])


if __name__ == "__main__":
    unittest.main()
